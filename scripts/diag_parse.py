#!/usr/bin/env python3
"""diag_parse.py - Win7Bridge diagnostic log parser.

Parses a Win7Bridge runtime log (plain text) and produces a human-readable
diagnostic report containing:

  * Dependency missing tree   (which DLL/module is missing what)
  * Intercepted API summary   (API -> hit count)
  * Anti-debug trigger points (where the target poked the debugger surface)
  * Version-spoof hit summary

Assumed log line format (emitted by the runtime logger, Task 5.1):

    <timestamp> <LEVEL> [<CATEGORY>] key1=value1 key2=value2 ...

Recognised categories and their keys:

    DEPEND     parent=<dll> child=<dll> reason=<missing|unresolved|...>
    IMPORT     dll=<dll> func=<name> status=<missing|resolved>
    API        api=<name> [intercepted=1] [result=...]
    ANTIDEBUG  check=<IsDebuggerPresent|NtQueryInformationProcess|...>
               value=<0|1|...> site=<module+offset>
    VERSION    query=<GetVersion|RtlGetVersion|...> spoofed=<0|1> reported=<...>

Lines without a [CATEGORY] token are ignored. The parser is tolerant: unknown
keys are kept but not required. Compatible with Python 3.8+; stdlib only.

Usage:
    python3 diag_parse.py <logfile> [-o <report.txt>]

If -o is omitted the report is written to stdout.
"""
from __future__ import annotations

import argparse
import re
import sys
from collections import Counter, defaultdict
from typing import Dict, List, Optional, Tuple

CATEGORY_RE = re.compile(r"\[([A-Z_]+)\]")
# key=value where value has no whitespace; split on the first '=' only.
KV_RE = re.compile(r"(\w+)=([^\s]*)")


def parse_line(line: str) -> Optional[Tuple[str, Dict[str, str]]]:
    """Return (category, kv-dict) for a log line, or None if unrecognised."""
    m = CATEGORY_RE.search(line)
    if not m:
        return None
    cat = m.group(1)
    kv = {k: v for k, v in KV_RE.findall(line)}
    return cat, kv


class LogReport:
    def __init__(self) -> None:
        # Dependency edges: parent -> set(child)
        self.dep_children: Dict[str, set] = defaultdict(set)
        self.child_parent: Dict[str, str] = {}
        # Missing imports: dll -> list of funcs
        self.missing_imports: Dict[str, List[str]] = defaultdict(list)
        # Intercepted API counts
        self.api_counts: Counter = Counter()
        self.api_samples: Dict[str, Dict[str, str]] = {}
        # Anti-debug triggers: site -> (check, value) counts
        self.antidebug: Dict[str, Counter] = defaultdict(Counter)
        self.antidebug_detail: Dict[str, Dict[str, str]] = {}
        # Version spoof hits
        self.version_counts: Counter = Counter()
        # Raw line count per category
        self.category_counts: Counter = Counter()
        self.total_lines = 0
        self.parsed_lines = 0

    def feed(self, line: str) -> None:
        self.total_lines += 1
        line = line.strip()
        if not line:
            return
        parsed = parse_line(line)
        if parsed is None:
            return
        cat, kv = parsed
        self.parsed_lines += 1
        self.category_counts[cat] += 1

        if cat == "DEPEND":
            parent = kv.get("parent", "<process>")
            child = kv.get("child", "")
            if child:
                self.dep_children[parent].add(child)
                self.child_parent[child] = parent
        elif cat == "IMPORT":
            dll = kv.get("dll", "<unknown>")
            func = kv.get("func", "")
            status = kv.get("status", "")
            if status == "missing" and func:
                self.missing_imports[dll].append(func)
                # Treat a missing import as a dependency edge too.
                self.dep_children[dll].add(func)
                self.child_parent.setdefault(func, dll)
        elif cat == "API":
            api = kv.get("api", "<unknown>")
            self.api_counts[api] += 1
            self.api_samples.setdefault(api, kv)
        elif cat == "ANTIDEBUG":
            check = kv.get("check", "<unknown>")
            site = kv.get("site", "<unknown>")
            value = kv.get("value", "?")
            key = "%s @ %s" % (check, site)
            self.antidebug[key][(check, value)] += 1
            self.antidebug_detail.setdefault(key, kv)
        elif cat == "VERSION":
            query = kv.get("query", "<unknown>")
            self.version_counts[query] += 1

    # ---- rendering ----
    def _dependency_tree(self) -> List[str]:
        lines: List[str] = []
        if not self.dep_children:
            lines.append("(no dependency-missing events recorded)")
            return lines
        # Roots: parents that never appear as a child.
        all_children = set(self.child_parent.keys())
        roots = [p for p in self.dep_children if p not in all_children]
        if not roots:
            roots = list(self.dep_children.keys())

        visited: set = set()

        def walk(node: str, depth: int) -> None:
            if node in visited:
                lines.append("%s%s (cycle)" % ("  " * depth, node))
                return
            visited.add(node)
            lines.append("%s%s" % ("  " * depth, node))
            for child in sorted(self.dep_children.get(node, ())):
                walk(child, depth + 1)

        for root in sorted(roots):
            walk(root, 0)
        return lines

    def render(self) -> str:
        out: List[str] = []
        out.append("Win7Bridge Diagnostic Report")
        out.append("=" * 40)
        out.append("Lines scanned: %d (parsed: %d)" % (self.total_lines,
                                                        self.parsed_lines))
        out.append("Category counts: %s"
                   % ", ".join("%s=%d" % (c, n) for c, n in
                               sorted(self.category_counts.items())))
        out.append("")

        # 1. Dependency missing tree
        out.append("1. Dependency Missing Tree")
        out.append("-" * 40)
        out.extend(self._dependency_tree())
        out.append("")

        # 2. Intercepted API summary
        out.append("2. Intercepted API Summary")
        out.append("-" * 40)
        if self.api_counts:
            out.append("%-40s %s" % ("API", "hits"))
            for api, count in self.api_counts.most_common():
                out.append("%-40s %d" % (api, count))
        else:
            out.append("(no intercepted API events recorded)")
        out.append("")

        # 3. Anti-debug trigger points
        out.append("3. Anti-debug Trigger Points")
        out.append("-" * 40)
        if self.antidebug:
            out.append("%-45s %-12s %s" % ("check @ site", "value", "hits"))
            for key in sorted(self.antidebug):
                for (check, value), count in sorted(
                        self.antidebug[key].items()):
                    out.append("%-45s %-12s %d" % (key, value, count))
        else:
            out.append("(no anti-debug trigger points recorded)")
        out.append("")

        # 4. Version spoof hits
        out.append("4. Version Spoof Hits")
        out.append("-" * 40)
        if self.version_counts:
            for query, count in self.version_counts.most_common():
                out.append("%-32s %d" % (query, count))
        else:
            out.append("(no version-spoof events recorded)")
        out.append("")

        # 5. Missing import functions (detail)
        out.append("5. Missing Import Functions (detail)")
        out.append("-" * 40)
        if self.missing_imports:
            for dll in sorted(self.missing_imports):
                funcs = self.missing_imports[dll]
                out.append("[%s] (%d)" % (dll, len(funcs)))
                for fn in funcs:
                    out.append("  %s" % fn)
        else:
            out.append("(no missing import functions recorded)")
        return "\n".join(out)


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="diag_parse.py",
        description="Parse a Win7Bridge runtime log into a diagnostic report: "
                    "dependency missing tree, intercepted API summary, "
                    "anti-debug trigger points, version-spoof hits.")
    parser.add_argument("logfile", help="path to the runtime log file")
    parser.add_argument("-o", "--output", default=None,
                        help="write report to this file (default: stdout)")
    args = parser.parse_args(argv)

    try:
        with open(args.logfile, "r", encoding="utf-8", errors="replace") as fh:
            report = LogReport()
            for line in fh:
                report.feed(line)
    except OSError as exc:
        sys.stderr.write("error: %s\n" % exc)
        return 2

    text = report.render()
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
