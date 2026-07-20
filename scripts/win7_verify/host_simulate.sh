#!/bin/bash
# host_simulate.sh - Linux 开发机上的 host 预检
#
# 验证两部分：
#   1) make check：C 源代码语法（含 host 测试）
#   2) verify_test_cases.sh：Win7 验证用例集结构完整性（SubTask 5.2.1）
set -e
cd "$(dirname "$0")/../.."
make check
echo "[ok] make check done"
bash scripts/win7_verify/verify_test_cases.sh
echo "[ok] host_simulate done"
