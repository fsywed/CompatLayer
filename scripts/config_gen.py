#!/usr/bin/env python3
"""config_gen.py - Win7Bridge configuration generator.

Scans a target EXE's import table and (embedded) application manifest, then
auto-infers the compatibility options the Win7Bridge layer must apply for it
to run on Windows 7 SP1. Output is a JSON document covering:

  * injection path + options
  * PE header fixes (subsystem version, bound import strip)
  * version spoofing policy
  * API set virtual-name mapping (api-ms-win-* / ext-ms-win-*)
  * list of APIs that need local emulation/fallback
  * manifest rewrites (supportedOS GUID injection, Win10-only element strip)
  * unresolvable items (WinRT, D3D12, ...) explicitly marked

Knowledge base is derived from docs/api-diff.md. Pure standard library;
reuses pe_scan.PEFile for PE parsing. Compatible with Python 3.8+.

Usage:
    python3 config_gen.py <exefile> [-o <config.json>]

If -o is omitted the JSON is written to stdout.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from typing import Dict, List, Optional, Tuple

# Allow `import pe_scan` when run from any working directory.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import pe_scan  # noqa: E402  (path adjusted above)


# ---- supportedOS GUIDs (see docs/api-diff.md §2.7) ----
GUID_WIN7 = "35138b9a-5d96-4fbd-8e2d-a2440225f93a"
GUID_WIN10 = "8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a"

# Spoofed version reported to the target (Win10 2004 / build 19041 is a safe,
# broadly-compatible target that satisfies "IsWindows10OrGreater").
SPOOF_MAJOR = 10
SPOOF_MINOR = 0
SPOOF_BUILD = 19041

# Win10 APIs that Win7 lacks and Win7Bridge can provide. Maps API name ->
# (strategy, detail). Strategy values match docs/dev-guide.md §7 fallbacks.
# Source: docs/api-diff.md §2.5.
EMULATABLE_APIS: Dict[str, Tuple[str, str]] = {
    "GetSystemTimePreciseAsFileTime":
        ("fallback", "fallback to GetSystemTimeAsFileTime (~15.6ms precision)"),
    "WaitOnAddress":            ("emulate", "event-object + spin simulation"),
    "WakeByAddressSingle":      ("emulate", "event-object simulation"),
    "WakeByAddressAll":         ("emulate", "event-object simulation"),
    "VirtualAlloc2":            ("degrade", "degrade to VirtualAlloc (placeholder/replace semantics lost)"),
    "VirtualAlloc2FromApp":     ("degrade", "degrade to VirtualAlloc"),
    "MapViewOfFileNuma2":       ("degrade", "degrade to MapViewOfFile"),
    "UnmapViewOfFileEx":        ("degrade", "degrade to UnmapViewOfFile"),
    "SetThreadDescription":     ("emulate", "TLS-slot storage"),
    "GetThreadDescription":     ("emulate", "TLS-slot storage"),
    "CreatePseudoConsole":      ("emulate", "pipe + console buffer simulation"),
    "ClosePseudoConsole":       ("emulate", "pipe + console buffer simulation"),
    "ResizePseudoConsole":      ("emulate", "pipe + console buffer simulation"),
    "SetProcessDpiAwarenessContext": ("fallback", "fallback to SetProcessDPIAware"),
    "EnableMouseInPointer":     ("noop", "no-op (mouse stays default)"),
}

# DLLs that cannot be satisfied on Win7 at all (docs/api-diff.md §2.11, §2.10).
UNRESOLVABLE_DLLS = {
    "d3d12.dll": "Direct3D 12 absent on Win7 (D3D12On7 only for some Steam games)",
    "combase.dll": "COM/WinRT runtime introduced in Win8",
    "winrtbase.dll": "WinRT core introduced in Win10",
    "api-ms-win-core-winrt-l1-1-0.dll": "WinRT API set not present on Win7",
    "api-ms-win-core-winrt-string-l1-1-0.dll": "HSTRING API set not present on Win7",
    "api-ms-win-core-winrt-error-l1-1-0.dll": "WinRT error API set not present on Win7",
    "api-ms-win-core-winrt-l1-1-1.dll": "WinRT API set not present on Win7",
}

# Win10-only manifest elements that should be stripped (dev-guide.md §L0).
WIN10_ONLY_MANIFEST_ELEMENTS = ["maxversiontested", "msix", "catalog"]


def classify_api_set(dll: str) -> Optional[Tuple[str, str]]:
    """Classify an api-ms-win-* / ext-ms-win-* name. Returns (kind, note)."""
    d = dll.lower()
    if d in UNRESOLVABLE_DLLS:
        return ("unresolvable", UNRESOLVABLE_DLLS[d])
    if d.startswith("api-ms-win-core-winrt") or d.startswith("ext-ms-win-core-winrt"):
        return ("unresolvable", "WinRT API set not present on Win7")
    if d.startswith("api-ms-win-crt-") or d == "ucrtbase.dll":
        return ("ucrt", "Universal CRT; requires KB2999226 + KB3118401 on Win7 SP1")
    if d.startswith("api-ms-win-core-synch-l1-2-0"):
        return ("emulate", "WaitOnAddress family; map to local emulation")
    if d.startswith("api-ms-win-core-memory-l1-1-"):
        # Versions >= 1-1-2 are newer than Win7's API set schema and need
        # loader-level interception (docs/api-diff.md §2.3).
        return ("emulate", "newer memory API set; map to local/degraded emulation")
    if d.startswith("api-ms-win-core-threadpool-l1-2-"):
        return ("emulate", "newer threadpool API set; map to local emulation")
    if d.startswith("api-ms-win-") or d.startswith("ext-ms-win-"):
        return ("apiset", "generic API set; map to Win7 host DLL or local emulation")
    return None


def parse_manifest_guids(xml: str) -> Tuple[List[str], List[str]]:
    """Return (supportedOS GUIDs, win10-only element names found)."""
    guids: List[str] = []
    for m in re.finditer(r'<supportedOS\s+[^>]*Id\s*=\s*"([^"]+)"', xml, re.IGNORECASE):
        guids.append(m.group(1).strip().lower())
    # Some manifests use a GUID without the supportedOS wrapper; keep a
    # best-effort scan too.
    if not guids:
        guid_re = re.compile(
            r"\{?([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
            r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12})\}?")
        guids = [m.group(1).lower() for m in guid_re.finditer(xml)]
    found_elements: List[str] = []
    lower = xml.lower()
    for elem in WIN10_ONLY_MANIFEST_ELEMENTS:
        if re.search(r"<%s[\s>]" % re.escape(elem), lower):
            found_elements.append(elem)
    return guids, found_elements


def build_config(exe_path: str, pe: pe_scan.PEFile) -> Dict:
    imports = pe.parse_imports()
    manifest_xml = pe.get_manifest()

    # ---- PE header fixes ----
    needs_subsystem_fix = (
        pe.major_subsystem_version > 6
        or (pe.major_subsystem_version == 6 and pe.minor_subsystem_version > 1)
    )
    pe_fixes = {
        "fix_subsystem_version": bool(needs_subsystem_fix),
        "current_major_subsystem_version": pe.major_subsystem_version,
        "current_minor_subsystem_version": pe.minor_subsystem_version,
        "target_major_subsystem_version": 6,
        "target_minor_subsystem_version": 1,
        "strip_bound_imports": True,  # force IAT resolution (dev-guide §L0)
    }

    # ---- API set mapping + emulation + unresolvable ----
    api_set_mapping: Dict[str, Dict[str, str]] = {}
    api_emulation: List[Dict[str, str]] = []
    unresolvable: List[Dict[str, str]] = []
    warnings: List[str] = []
    seen_emul: set = set()

    for entry in imports:
        dll = entry.dll
        cls = classify_api_set(dll)
        if cls is not None:
            kind, note = cls
            if kind == "unresolvable":
                unresolvable.append({"dll": dll, "reason": note})
            elif kind == "ucrt":
                warnings.append("UCRT dependency (%s): user must install "
                                "KB2999226 + KB3118401 + VCRedist" % dll)
                api_set_mapping[dll] = {"target": "ucrtbase.dll",
                                        "strategy": "host", "note": note}
            elif kind in ("emulate", "apiset"):
                api_set_mapping[dll] = {"target": "<win7bridge-forwarder>",
                                        "strategy": kind, "note": note}
        elif dll.lower() in UNRESOLVABLE_DLLS:
            unresolvable.append({"dll": dll,
                                 "reason": UNRESOLVABLE_DLLS[dll.lower()]})

        # Per-function emulation needs (works for any host DLL).
        for fn in entry.functions:
            if fn in EMULATABLE_APIS and fn not in seen_emul:
                strategy, detail = EMULATABLE_APIS[fn]
                api_emulation.append({
                    "api": fn,
                    "source_dll": dll,
                    "strategy": strategy,
                    "detail": detail,
                })
                seen_emul.add(fn)

    # ---- manifest analysis ----
    manifest_info: Dict = {
        "present": manifest_xml is not None,
        "supportedOS_guids": [],
        "has_win7_guid": False,
        "has_win10_guid": False,
        "win10_only_elements": [],
        "rewrite": {
            "inject_win7_guid": False,
            "strip_win10_only_elements": False,
        },
    }
    if manifest_xml:
        guids, win10_elems = parse_manifest_guids(manifest_xml)
        manifest_info["supportedOS_guids"] = guids
        manifest_info["has_win7_guid"] = GUID_WIN7 in guids
        manifest_info["has_win10_guid"] = GUID_WIN10 in guids
        manifest_info["win10_only_elements"] = win10_elems
        manifest_info["rewrite"]["inject_win7_guid"] = GUID_WIN7 not in guids
        manifest_info["rewrite"]["strip_win10_only_elements"] = bool(win10_elems)

    # ---- injection path (default: loader; no anti-debug footprint) ----
    injection = {
        "path": "loader",
        "method": "CreateProcessW(CREATE_SUSPENDED) + inject DLL + ResumeThread",
        "anti_debug_safe": True,
        "alternatives": ["pe_patch", "appinit_dlls_ifco"],
        "notes": "Loader path avoids Verifier/Debugger flags; alternatives are "
                 "opt-in and risk-tagged in the UI.",
    }

    # ---- version spoofing (default on; safe for self-checking apps) ----
    version_spoof = {
        "enabled": True,
        "report_major": SPOOF_MAJOR,
        "report_minor": SPOOF_MINOR,
        "report_build": SPOOF_BUILD,
        "hook_targets": [
            "GetVersion", "GetVersionExA", "GetVersionExW",
            "RtlGetVersion", "RtlGetNtVersionNumbers", "VerifyVersionInfoW",
        ],
    }

    config: Dict = {
        "schema": "win7bridge.config/v1",
        "target": os.path.abspath(exe_path),
        "target_basename": os.path.basename(exe_path),
        "pe": {
            "format": "PE32+" if pe.is_pe32_plus else "PE32",
            "machine": "0x%04X" % pe.machine,
            "subsystem": pe.subsystem,
            "image_base": "0x%X" % pe.image_base,
        },
        "injection": injection,
        "pe_fixes": pe_fixes,
        "version_spoof": version_spoof,
        "api_set_mapping": api_set_mapping,
        "api_emulation": api_emulation,
        "manifest": manifest_info,
        "unresolvable": unresolvable,
        "warnings": warnings,
    }
    return config


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="config_gen.py",
        description="Scan an EXE's imports and manifest to auto-infer "
                    "Win7Bridge compatibility options; emit JSON config.")
    parser.add_argument("exefile", help="path to the target PE image (.exe/.dll)")
    parser.add_argument("-o", "--output", default=None,
                        help="write JSON config to this file (default: stdout)")
    args = parser.parse_args(argv)

    try:
        pe = pe_scan.PEFile(args.exefile)
    except (pe_scan.PEError, OSError) as exc:
        sys.stderr.write("error: %s\n" % exc)
        return 2

    config = build_config(args.exefile, pe)
    text = json.dumps(config, indent=2, ensure_ascii=False, sort_keys=False)

    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as fh:
                fh.write(text)
                fh.write("\n")
        except OSError as exc:
            sys.stderr.write("error writing %s: %s\n" % (args.output, exc))
            return 2
    else:
        print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
