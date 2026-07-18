#!/usr/bin/env python3
"""pe_scan.py - Win7Bridge PE file scanner.

Parses a PE/COFF image (DOS header, PE signature, IMAGE_FILE_HEADER,
IMAGE_OPTIONAL_HEADER, Import Directory, Export Directory and the
Resource tree) using only the Python standard library, then reports:

  * MajorSubsystemVersion / MajorOperatingSystemVersion / Subsystem
  * imported DLLs and the functions/ordinals pulled from each
  * exported functions

Usage:
    python3 pe_scan.py <pefile> [--imports] [--exports] [--subsystem]

With no flags, everything is printed. Each flag selects only that
section (flags may be combined). Compatible with Python 3.8+; no
third-party dependencies (no `pefile`).
"""
from __future__ import annotations

import argparse
import struct
import sys
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

# --- PE signatures / constants ---
IMAGE_DOS_SIGNATURE = 0x5A4D        # "MZ"
IMAGE_NT_SIGNATURE = 0x00004550     # "PE\0\0"
IMAGE_OPTIONAL_HDR32_MAGIC = 0x10B  # PE32
IMAGE_OPTIONAL_HDR64_MAGIC = 0x20B  # PE32+

# DataDirectory indices
DIR_EXPORT = 0
DIR_IMPORT = 1
DIR_RESOURCE = 2

IMAGE_ORDINAL_FLAG32 = 0x80000000
IMAGE_ORDINAL_FLAG64 = 0x8000000000000000

RT_MANIFEST = 24

# Machine types (subset)
MACHINE_NAMES = {
    0x014C: "i386 (x86)",
    0x0200: "IA64",
    0x8664: "AMD64 (x64)",
    0xAA64: "ARM64",
    0x01C0: "ARM",
}

SUBSYSTEM_NAMES = {
    1: "NATIVE",
    2: "WINDOWS_GUI",
    3: "WINDOWS_CUI",
    5: "OS2_CUI",
    7: "POSIX_CUI",
    9: "WINDOWS_CE_GUI",
    10: "EFI_APPLICATION",
    11: "EFI_BOOT_SERVICE_DRIVER",
    12: "EFI_RUNTIME_DRIVER",
    13: "EFI_ROM",
    14: "XBOX",
}


class PEError(Exception):
    """Raised on malformed/non-PE input."""


@dataclass
class Section:
    name: str
    virtual_address: int
    virtual_size: int
    pointer_to_raw_data: int
    size_of_raw_data: int


@dataclass
class ImportEntry:
    dll: str
    functions: List[str] = field(default_factory=list)
    ordinals: List[int] = field(default_factory=list)


@dataclass
class ExportInfo:
    name: str
    number_of_functions: int = 0
    ordinal_base: int = 0
    functions: List[str] = field(default_factory=list)


class PEFile:
    """Minimal read-only PE parser (PE32 and PE32+)."""

    def __init__(self, path: str):
        self.path = path
        with open(path, "rb") as fh:
            self.data = fh.read()
        self.sections: List[Section] = []
        self.is_pe32_plus = False
        self.file_header_offset = 0
        self.optional_header_offset = 0
        self.data_directories: List[Tuple[int, int]] = []
        # optional header fields (filled by _parse)
        self.machine = 0
        self.number_of_sections = 0
        self.major_os_version = 0
        self.minor_os_version = 0
        self.major_image_version = 0
        self.minor_image_version = 0
        self.major_subsystem_version = 0
        self.minor_subsystem_version = 0
        self.subsystem = 0
        self.dll_characteristics = 0
        self.number_of_rva_and_sizes = 0
        self.image_base = 0
        self.size_of_image = 0
        self.entry_point = 0
        self._parse()

    # --- low level readers ---
    def _u16(self, off: int) -> int:
        return struct.unpack_from("<H", self.data, off)[0]

    def _u32(self, off: int) -> int:
        return struct.unpack_from("<I", self.data, off)[0]

    def _u64(self, off: int) -> int:
        return struct.unpack_from("<Q", self.data, off)[0]

    def _read_cstr(self, off: int, max_len: int = 4096) -> str:
        end = self.data.find(b"\x00", off, off + max_len)
        if end < 0:
            end = off + max_len
        return self.data[off:end].decode("latin-1", errors="replace")

    # --- parsing ---
    def _parse(self) -> None:
        if len(self.data) < 0x40:
            raise PEError("file too small for a DOS header")
        if self._u16(0) != IMAGE_DOS_SIGNATURE:
            raise PEError("not a MZ file (bad DOS signature)")
        e_lfanew = self._u32(0x3C)
        if e_lfanew <= 0 or e_lfanew + 24 > len(self.data):
            raise PEError("invalid e_lfanew")
        if self._u32(e_lfanew) != IMAGE_NT_SIGNATURE:
            raise PEError("not a PE file (bad PE signature)")

        # IMAGE_FILE_HEADER (20 bytes) right after the 4-byte signature
        self.file_header_offset = e_lfanew + 4
        fh = self.file_header_offset
        self.machine = self._u16(fh + 0)
        self.number_of_sections = self._u16(fh + 2)
        size_of_optional_header = self._u16(fh + 16)
        self.optional_header_offset = fh + 20
        oh = self.optional_header_offset
        if size_of_optional_header == 0 or oh + size_of_optional_header > len(self.data):
            raise PEError("missing/invalid optional header")

        magic = self._u16(oh + 0)
        if magic == IMAGE_OPTIONAL_HDR32_MAGIC:
            self.is_pe32_plus = False
        elif magic == IMAGE_OPTIONAL_HDR64_MAGIC:
            self.is_pe32_plus = True
        else:
            raise PEError("unknown optional header magic 0x%X" % magic)

        # Fields shared by PE32 and PE32+ at identical offsets.
        self.entry_point = self._u32(oh + 16)
        self.major_os_version = self._u16(oh + 40)
        self.minor_os_version = self._u16(oh + 42)
        self.major_image_version = self._u16(oh + 44)
        self.minor_image_version = self._u16(oh + 46)
        self.major_subsystem_version = self._u16(oh + 48)
        self.minor_subsystem_version = self._u16(oh + 50)
        self.size_of_image = self._u32(oh + 56)
        self.subsystem = self._u16(oh + 68)
        self.dll_characteristics = self._u16(oh + 70)

        if self.is_pe32_plus:
            self.image_base = self._u64(oh + 24)
            nrva_off = oh + 108
        else:
            self.image_base = self._u32(oh + 28)
            nrva_off = oh + 92
        self.number_of_rva_and_sizes = self._u32(nrva_off)

        dd_off = nrva_off + 4
        count = min(self.number_of_rva_and_sizes, 16)
        self.data_directories = []
        for i in range(count):
            va = self._u32(dd_off + i * 8)
            sz = self._u32(dd_off + i * 8 + 4)
            self.data_directories.append((va, sz))

        # Section headers (40 bytes each) follow the optional header.
        sec_off = oh + size_of_optional_header
        for i in range(self.number_of_sections):
            base = sec_off + i * 40
            if base + 40 > len(self.data):
                break
            raw_name = self.data[base:base + 8]
            name = raw_name.rstrip(b"\x00").decode("latin-1", errors="replace")
            vsize = self._u32(base + 8)
            vaddr = self._u32(base + 12)
            raw_size = self._u32(base + 16)
            raw_ptr = self._u32(base + 20)
            self.sections.append(Section(name, vaddr, vsize, raw_ptr, raw_size))

    # --- RVA resolution ---
    def rva_to_offset(self, rva: int) -> Optional[int]:
        for s in self.sections:
            start = s.virtual_address
            size = s.virtual_size if s.virtual_size else s.size_of_raw_data
            if size == 0:
                continue
            if start <= rva < start + size:
                if s.pointer_to_raw_data == 0:
                    return None
                return s.pointer_to_raw_data + (rva - start)
        return None

    # --- import directory ---
    def parse_imports(self) -> List[ImportEntry]:
        if DIR_IMPORT >= len(self.data_directories):
            return []
        va, _sz = self.data_directories[DIR_IMPORT]
        if va == 0:
            return []
        off = self.rva_to_offset(va)
        if off is None:
            return []
        result: List[ImportEntry] = []
        i = 0
        while True:
            desc = off + i * 20
            if desc + 20 > len(self.data):
                break
            oft = self._u32(desc + 0)     # OriginalFirstThunk (ILT)
            # timestamp @ +4, forwarder @ +8 (unused here)
            name_rva = self._u32(desc + 12)
            ft = self._u32(desc + 16)     # FirstThunk (IAT)
            if oft == 0 and ft == 0 and name_rva == 0:
                break
            if name_rva == 0:
                i += 1
                continue
            name_off = self.rva_to_offset(name_rva)
            dll_name = self._read_cstr(name_off) if name_off is not None else "<unknown>"
            entry = ImportEntry(dll=dll_name)
            thunk_rva = oft if oft else ft
            thunk_off = self.rva_to_offset(thunk_rva) if thunk_rva else None
            if thunk_off is not None:
                funcs, ords = self._read_thunks(thunk_off)
                entry.functions = funcs
                entry.ordinals = ords
            result.append(entry)
            i += 1
        return result

    def _read_thunks(self, thunk_off: int) -> Tuple[List[str], List[int]]:
        funcs: List[str] = []
        ords: List[int] = []
        if self.is_pe32_plus:
            fmt = "<Q"
            step = 8
            flag = IMAGE_ORDINAL_FLAG64
        else:
            fmt = "<I"
            step = 4
            flag = IMAGE_ORDINAL_FLAG32
        j = 0
        while True:
            pos = thunk_off + j * step
            if pos + step > len(self.data):
                break
            val = struct.unpack_from(fmt, self.data, pos)[0]
            if val == 0:
                break
            if val & flag:
                ordinal = val & 0xFFFF
                ords.append(ordinal)
                funcs.append("Ordinal_%d" % ordinal)
            else:
                # Low bits are the RVA to IMAGE_IMPORT_BY_NAME {Hint, Name}.
                hint_off = self.rva_to_offset(val)
                if hint_off is not None and hint_off + 2 < len(self.data):
                    funcs.append(self._read_cstr(hint_off + 2))
                else:
                    funcs.append("<unknown>")
            j += 1
        return funcs, ords

    # --- export directory ---
    def parse_exports(self) -> Optional[ExportInfo]:
        if DIR_EXPORT >= len(self.data_directories):
            return None
        va, _sz = self.data_directories[DIR_EXPORT]
        if va == 0:
            return None
        off = self.rva_to_offset(va)
        if off is None or off + 40 > len(self.data):
            return None
        # IMAGE_EXPORT_DIRECTORY
        name_rva = self._u32(off + 12)
        base = self._u32(off + 16)
        num_funcs = self._u32(off + 20)
        num_names = self._u32(off + 24)
        addr_names = self._u32(off + 32)
        dll_off = self.rva_to_offset(name_rva)
        dll_name = self._read_cstr(dll_off) if dll_off is not None else "<unknown>"
        info = ExportInfo(name=dll_name, number_of_functions=num_funcs,
                          ordinal_base=base)
        names_off = self.rva_to_offset(addr_names) if addr_names else None
        if names_off is not None:
            for k in range(num_names):
                p = names_off + k * 4
                if p + 4 > len(self.data):
                    break
                fn_rva = self._u32(p)
                fn_off = self.rva_to_offset(fn_rva)
                if fn_off is not None:
                    info.functions.append(self._read_cstr(fn_off))
        return info

    # --- resource tree (only what config_gen needs: RT_MANIFEST) ---
    def find_resource(self, target_type: int) -> List[Tuple[int, int]]:
        """Return list of (file_offset, size) for resources of the given type."""
        if DIR_RESOURCE >= len(self.data_directories):
            return []
        va, _sz = self.data_directories[DIR_RESOURCE]
        if va == 0:
            return []
        base = self.rva_to_offset(va)
        if base is None or base + 16 > len(self.data):
            return []
        results: List[Tuple[int, int]] = []
        num_named = self._u16(base + 12)
        num_id = self._u16(base + 14)
        for i in range(num_named + num_id):
            p = base + 16 + i * 8
            if p + 8 > len(self.data):
                break
            name_or_id = self._u32(p)
            offset = self._u32(p + 4)
            if name_or_id & 0x80000000:
                continue  # named type, not an ID
            tid = name_or_id & 0xFFFF
            if tid == target_type and (offset & 0x80000000):
                self._res_collect(base, base + (offset & 0x7FFFFFFF), results)
        return results

    def _res_collect(self, base: int, dir_off: int,
                     results: List[Tuple[int, int]]) -> None:
        if dir_off + 16 > len(self.data):
            return
        num_named = self._u16(dir_off + 12)
        num_id = self._u16(dir_off + 14)
        for i in range(num_named + num_id):
            p = dir_off + 16 + i * 8
            if p + 8 > len(self.data):
                break
            offset = self._u32(p + 4)
            if offset & 0x80000000:
                # descend into the language-level subdirectory
                self._res_collect_leaf(base, base + (offset & 0x7FFFFFFF),
                                       results)
            else:
                self._res_add_data(base + (offset & 0x7FFFFFFF), results)

    def _res_collect_leaf(self, base: int, dir_off: int,
                          results: List[Tuple[int, int]]) -> None:
        if dir_off + 16 > len(self.data):
            return
        num_named = self._u16(dir_off + 12)
        num_id = self._u16(dir_off + 14)
        for i in range(num_named + num_id):
            p = dir_off + 16 + i * 8
            if p + 8 > len(self.data):
                break
            offset = self._u32(p + 4)
            if not (offset & 0x80000000):
                self._res_add_data(base + (offset & 0x7FFFFFFF), results)

    def _res_add_data(self, data_entry_off: int,
                      results: List[Tuple[int, int]]) -> None:
        if data_entry_off + 16 > len(self.data):
            return
        data_rva = self._u32(data_entry_off + 0)
        data_size = self._u32(data_entry_off + 4)
        data_off = self.rva_to_offset(data_rva)
        if data_off is not None:
            results.append((data_off, data_size))

    def get_manifest(self) -> Optional[str]:
        for data_off, data_size in self.find_resource(RT_MANIFEST):
            return self.data[data_off:data_off + data_size].decode(
                "utf-8", errors="replace")
        return None


# ---- reporting ----
def format_report(pe: PEFile,
                  show_subsystem: bool,
                  show_imports: bool,
                  show_exports: bool) -> str:
    lines: List[str] = []
    if show_subsystem:
        machine = MACHINE_NAMES.get(pe.machine, "unknown (0x%04X)" % pe.machine)
        subsys = SUBSYSTEM_NAMES.get(pe.subsystem, "unknown (%d)" % pe.subsystem)
        lines.append("PE file: %s" % pe.path)
        lines.append("Machine: %s" % machine)
        lines.append("Format: %s" % ("PE32+" if pe.is_pe32_plus else "PE32"))
        lines.append("ImageBase: 0x%X" % pe.image_base)
        lines.append("EntryPoint: 0x%X" % pe.entry_point)
        lines.append("Sections: %d" % pe.number_of_sections)
        lines.append("Subsystem: %d (%s)" % (pe.subsystem, subsys))
        lines.append("MajorSubsystemVersion: %d.%d"
                     % (pe.major_subsystem_version, pe.minor_subsystem_version))
        lines.append("MajorOperatingSystemVersion: %d.%d"
                     % (pe.major_os_version, pe.minor_os_version))
        lines.append("MajorImageVersion: %d.%d"
                     % (pe.major_image_version, pe.minor_image_version))
        lines.append("SizeOfImage: 0x%X" % pe.size_of_image)
    if show_imports:
        if lines:
            lines.append("")
        lines.append("=== Imports ===")
        imports = pe.parse_imports()
        if not imports:
            lines.append("(no imports)")
        for entry in imports:
            lines.append("[%s]" % entry.dll)
            if entry.functions:
                for fn in entry.functions:
                    lines.append("  %s" % fn)
            if entry.ordinals:
                lines.append("  (ordinals: %s)"
                             % ", ".join(str(o) for o in entry.ordinals))
            if not entry.functions and not entry.ordinals:
                lines.append("  (no thunks resolved)")
    if show_exports:
        if lines:
            lines.append("")
        lines.append("=== Exports ===")
        exp = pe.parse_exports()
        if exp is None:
            lines.append("(no export directory)")
        else:
            lines.append("DLL name: %s" % exp.name)
            lines.append("NumberOfFunctions: %d (base ordinal %d)"
                         % (exp.number_of_functions, exp.ordinal_base))
            if exp.functions:
                for fn in exp.functions:
                    lines.append("  %s" % fn)
            else:
                lines.append("(no named exports)")
    return "\n".join(lines)


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="pe_scan.py",
        description="Win7Bridge PE scanner: parse imports/exports/subsystem "
                    "of a PE image using only the Python standard library.")
    parser.add_argument("pefile", help="path to the PE file (.exe/.dll)")
    parser.add_argument("--imports", action="store_true",
                        help="show the import directory (DLLs + functions)")
    parser.add_argument("--exports", action="store_true",
                        help="show the export directory (named exports)")
    parser.add_argument("--subsystem", action="store_true",
                        help="show subsystem / OS version summary")
    args = parser.parse_args(argv)

    # No selection flags => print everything.
    if not (args.imports or args.exports or args.subsystem):
        show_subsystem = show_imports = show_exports = True
    else:
        show_subsystem = args.subsystem
        show_imports = args.imports
        show_exports = args.exports

    try:
        pe = PEFile(args.pefile)
    except (PEError, OSError) as exc:
        sys.stderr.write("error: %s\n" % exc)
        return 2

    print(format_report(pe, show_subsystem, show_imports, show_exports))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
