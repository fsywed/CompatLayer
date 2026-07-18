#!/bin/bash
# host_simulate.sh - Linux 开发机上的 host 预检
#
# 仅验证 C 源代码语法（不运行 Windows EXE）。等价于 make check 的子集。
set -e
cd "$(dirname "$0")/../.."
make check
echo "[ok] host_simulate done"
