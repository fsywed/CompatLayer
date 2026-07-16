# Win7Bridge build system
#
# Cross-compiles the C body for x86 and x64 Windows targets via MinGW-w64.
# `make check` runs a host-gcc syntax check (-fsyntax-only) on the
# platform-independent sources plus a Python-tool self-check, so it works
# in environments without MinGW (e.g. a plain Linux sandbox).
#
# See docs/dev-guide.md §10 (engineering conventions).

# ---- toolchain ----
CC_X86 := i686-w64-mingw32-gcc
CC_X64 := x86_64-w64-mingw32-gcc
CC_HOST := gcc
PYTHON  := python3

# ---- flags ----
CFLAGS        := -Wall -Wextra -O2 -std=gnu11
# Syntax-check only: no codegen, defines WIN7BRIDGE_SYNTAX_CHECK so sources
# can stub out Windows-specific includes/declarations during host checks.
SYNTAX_CFLAGS := -Wall -Wextra -std=gnu11 -fsyntax-only -DWIN7BRIDGE_SYNTAX_CHECK

INCLUDES := -Iinclude

# ---- sources / outputs ----
# Recursive: every .c under src/ (any depth).
SRC_C   := $(strip $(shell find src -type f -name '*.c' 2>/dev/null))
OBJ_X86 := $(patsubst src/%.c,build/x86/%.o,$(SRC_C))
OBJ_X64 := $(patsubst src/%.c,build/x64/%.o,$(SRC_C))

PYTHON_TOOLS := scripts/pe_scan.py scripts/config_gen.py scripts/diag_parse.py
HOST_HEADERS := win7bridge/version.h

.PHONY: all x86 x64 check syntax-check python-check test clean help

all: x86 x64

x86: $(OBJ_X86)
	@echo "[build] x86 objects: $(words $(OBJ_X86))"

x64: $(OBJ_X64)
	@echo "[build] x64 objects: $(words $(OBJ_X64))"

# Per-architecture compile rules (only triggered when sources exist).
# The `%` stem matches nested paths, so src/sub/foo.c -> build/x86/sub/foo.o.
build/x86/%.o: src/%.c
	@mkdir -p $(dir $@)
	$(CC_X86) $(CFLAGS) $(INCLUDES) -c $< -o $@

build/x64/%.o: src/%.c
	@mkdir -p $(dir $@)
	$(CC_X64) $(CFLAGS) $(INCLUDES) -c $< -o $@

# ---- verification ----
check: syntax-check python-check
	@echo "[check] all checks passed."

# Native-gcc syntax check on src/ platform-independent code. Gracefully
# handles the "no sources yet" case so the build is green from day one.
syntax-check:
	@echo "[check] C syntax check (native gcc, -DWIN7BRIDGE_SYNTAX_CHECK)..."
	@if [ -z "$(SRC_C)" ]; then \
		echo "[check]   no C sources under src/; skipping source syntax check."; \
	else \
		set -e; \
		echo "[check]   checking $(words $(SRC_C)) source file(s):"; \
		for f in $(SRC_C); do \
			printf "  CC (syntax) %s\n" "$$f"; \
			$(CC_HOST) $(SYNTAX_CFLAGS) $(INCLUDES) "$$f"; \
		done; \
	fi
	@echo "[check]   checking public headers..."
	@printf '#include "win7bridge/version.h"\n' \
		| $(CC_HOST) $(SYNTAX_CFLAGS) $(INCLUDES) -x c - \
		&& echo "[check]   headers OK"

# Each tool must at least import and parse --help (exit 0).
python-check:
	@echo "[check] Python tool self-check..."
	@set -e; rc=0; \
	for s in $(PYTHON_TOOLS); do \
		printf "  PY --help  %s\n" "$$s"; \
		PYTHONDONTWRITEBYTECODE=1 $(PYTHON) "$$s" --help >/dev/null 2>&1 || { \
			echo "  FAIL: $$s (exit $$?)"; rc=1; }; \
	done; \
	test $$rc -eq 0 && echo "[check]   python tools OK"

# Host objects for tests: compile every src/*.c with the host compiler
# (host ABI, no WIN7BRIDGE_SYNTAX_CHECK) so test programs can link against
# the real implementation instead of stubs.
HOST_OBJ := $(patsubst src/%.c,build/test/obj/%.o,$(SRC_C))

# Build and run host test programs under tests/ (top-level *.c).
# Each test is compiled with -DWIN7BRIDGE_HOST_TEST (the convention tests use
# to expose their main()) and linked against the host-built src objects.
test: $(HOST_OBJ)
	@echo "[test] host tests under tests/..."
	@tests=$$(find tests -maxdepth 1 -type f -name '*.c' 2>/dev/null); \
	if [ -z "$$tests" ]; then \
		echo "[test]   no host test sources under tests/; nothing to do."; \
		exit 0; \
	fi; \
	rc=0; \
	for t in $$tests; do \
		base=$$(basename "$$t" .c); \
		printf "  CC/LD (host) %s -> build/test/%s\n" "$$t" "$$base"; \
		mkdir -p build/test; \
		{ $(CC_HOST) -std=gnu11 -Wall -Wextra $(INCLUDES) -DWIN7BRIDGE_HOST_TEST \
			"$$t" $(HOST_OBJ) -o "build/test/$$base" \
			&& "./build/test/$$base"; } || { echo "  FAIL: $$base"; rc=1; }; \
	done; \
	exit $$rc

build/test/obj/%.o: src/%.c
	@mkdir -p $(dir $@)
	$(CC_HOST) -std=gnu11 -Wall -Wextra $(INCLUDES) -c $< -o $@

clean:
	@echo "[clean] removing build/ and Python bytecode caches"
	@rm -rf build/ scripts/__pycache__

help:
	@echo "Win7Bridge build targets:"
	@echo "  make            build x86 + x64 objects (MinGW-w64 cross-compile)"
	@echo "  make x86        build x86 objects only"
	@echo "  make x64        build x64 objects only"
	@echo "  make check      native gcc syntax check + Python tool self-check"
	@echo "  make test       build and run host tests under tests/"
	@echo "  make clean      remove build/ and Python bytecode caches"
	@echo "  make help       this message"
	@echo ""
	@echo "Variables: CC_X86=$(CC_X86) CC_X64=$(CC_X64) CC_HOST=$(CC_HOST)"
