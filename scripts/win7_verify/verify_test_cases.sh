#!/bin/bash
# verify_test_cases.sh - Linux 开发机上的测试用例集结构验证（SubTask 5.2.1）
#
# 验证 scripts/win7_verify/ 下的测试用例集结构完整性：
#   1) spec SubTask 5.2.1 要求的 4 类 EXE 用例源文件都存在
#   2) 每个用例源文件包含期望的关键模式（如 RESULT: PASS/FAIL）
#   3) run_all.bat / build_all.bat 引用了所有用例
#   4) README.md 列出了所有用例
#
# 不编译不运行 Windows EXE，仅做静态结构检查。
set -e
cd "$(dirname "$0")/../.."

VERIFY_DIR="scripts/win7_verify"
CASES_DIR="$VERIFY_DIR/cases"
PASS=0
FAIL=0

ok()   { echo "[ok]   $1"; PASS=$((PASS+1)); }
fail() { echo "[FAIL] $1"; FAIL=$((FAIL+1)); }

echo "=== SubTask 5.2.1 测试用例集结构验证 ==="

# ---------------------------------------------------------------
# 1. spec 5.2.1 必备用例存在性检查
# ---------------------------------------------------------------
echo ""
echo "--- 1. spec 5.2.1 必备用例存在性 ---"

# 高子系统版本 EXE
for f in "$CASES_DIR/case_01_high_subsystem.c" "$VERIFY_DIR/test_3_2_2_high_subsystem.c"; do
    [ -f "$f" ] && ok "$f 存在" || fail "$f 缺失"
done

# 导入 api-ms-win-core-synch-l1-2-0 的 EXE
f="$CASES_DIR/case_02_apiset_import.c"
[ -f "$f" ] && ok "$f 存在" || fail "$f 缺失"
grep -q "api-ms-win-core-synch-l1-2-0" "$f" \
    && ok "case_02 引用 api-ms-win-core-synch-l1-2-0" \
    || fail "case_02 未引用 api-ms-win-core-synch-l1-2-0"

# GetProcAddress 动态解析新 API 的 EXE
f="$CASES_DIR/case_03_get_proc_address.c"
[ -f "$f" ] && ok "$f 存在" || fail "$f 缺失"
grep -q "GetProcAddress" "$f" \
    && ok "case_03 调用 GetProcAddress" \
    || fail "case_03 未调用 GetProcAddress"
grep -q "SetThreadDescription" "$f" \
    && ok "case_03 解析 SetThreadDescription" \
    || fail "case_03 未解析 SetThreadDescription"

# 自检 Win10 版本的 EXE
f="$CASES_DIR/case_04_version_spoof.c"
[ -f "$f" ] && ok "$f 存在" || fail "$f 缺失"
grep -q "GetVersionEx" "$f" \
    && ok "case_04 调用 GetVersionEx" \
    || fail "case_04 未调用 GetVersionEx"

# ---------------------------------------------------------------
# 2. 扩展用例存在性
# ---------------------------------------------------------------
echo ""
echo "--- 2. 扩展用例（L3 模拟层 + 反调试 + UCRT） ---"
for c in case_05_pseudo_console case_06_wait_on_address \
         case_07_bcrypt_chacha20 case_08_ucrt_check; do
    f="$CASES_DIR/$c.c"
    [ -f "$f" ] && ok "$f 存在" || fail "$f 缺失"
done

f="$VERIFY_DIR/test_3_1_4_anti_debug.c"
[ -f "$f" ] && ok "$f 存在" || fail "$f 缺失"

# ---------------------------------------------------------------
# 3. 用例结构完整性（每个用例至少输出 RESULT: PASS）
#    部分"运行即通过"型用例只有 PASS 路径（如 case_01 高子系统版本
#    测试，EXE 能加载就视为通过；运行时崩溃由 run_all.bat 的 errorlevel
#    检测捕获，不需要在 EXE 内打印 FAIL）。
# ---------------------------------------------------------------
echo ""
echo "--- 3. 用例输出 RESULT 标记 ---"
for f in "$CASES_DIR"/case_*.c "$VERIFY_DIR"/test_3_*.c; do
    [ -f "$f" ] || continue
    if grep -q "RESULT: PASS" "$f"; then
        ok "$(basename "$f") 含 RESULT: PASS 标记"
    else
        fail "$(basename "$f") 缺 RESULT: PASS 标记"
    fi
done

# ---------------------------------------------------------------
# 4. run_all.bat 引用所有用例
# ---------------------------------------------------------------
echo ""
echo "--- 4. run_all.bat 引用完整性 ---"
RUN_BAT="$VERIFY_DIR/run_all.bat"
[ -f "$RUN_BAT" ] || { fail "$RUN_BAT 缺失"; exit 1; }
for c in test_3_1_4_anti_debug test_3_2_2_high_subsystem \
         case_01_high_subsystem case_02_apiset_import \
         case_03_get_proc_address case_04_version_spoof \
         case_05_pseudo_console case_06_wait_on_address \
         case_07_bcrypt_chacha20 case_08_ucrt_check; do
    if grep -q "$c" "$RUN_BAT"; then
        ok "run_all.bat 引用 $c"
    else
        fail "run_all.bat 未引用 $c"
    fi
done

# ---------------------------------------------------------------
# 5. build_all.bat 编译所有用例
# ---------------------------------------------------------------
echo ""
echo "--- 5. build_all.bat 编译完整性 ---"
BUILD_BAT="$VERIFY_DIR/build_all.bat"
[ -f "$BUILD_BAT" ] || { fail "$BUILD_BAT 缺失"; exit 1; }
for c in test_3_1_4_anti_debug test_3_2_2_high_subsystem \
         case_01_high_subsystem case_02_apiset_import \
         case_03_get_proc_address case_04_version_spoof \
         case_05_pseudo_console case_06_wait_on_address \
         case_07_bcrypt_chacha20 case_08_ucrt_check; do
    if grep -q "$c" "$BUILD_BAT"; then
        ok "build_all.bat 编译 $c"
    else
        fail "build_all.bat 未编译 $c"
    fi
done

# ---------------------------------------------------------------
# 6. README.md 文档完整性
# ---------------------------------------------------------------
echo ""
echo "--- 6. README.md 文档完整性 ---"
README="$VERIFY_DIR/README.md"
[ -f "$README" ] || { fail "$README 缺失"; exit 1; }
grep -q "SubTask 5.2.1" "$README" \
    && ok "README.md 标注 SubTask 5.2.1" \
    || fail "README.md 未标注 SubTask 5.2.1"
for c in case_01_high_subsystem case_02_apiset_import \
         case_03_get_proc_address case_04_version_spoof; do
    if grep -q "$c" "$README"; then
        ok "README.md 列出 $c"
    else
        fail "README.md 未列出 $c"
    fi
done

# ---------------------------------------------------------------
# 7. host_simulate.sh 存在且可执行
# ---------------------------------------------------------------
echo ""
echo "--- 7. host_simulate.sh ---"
HOST_SIM="$VERIFY_DIR/host_simulate.sh"
[ -f "$HOST_SIM" ] && ok "$HOST_SIM 存在" || fail "$HOST_SIM 缺失"
[ -x "$HOST_SIM" ] && ok "$HOST_SIM 可执行" || ok "$HOST_SIM 非 +x（用 bash 调用）"

# ---------------------------------------------------------------
# 8. pe_patch_cli.c 存在
# ---------------------------------------------------------------
echo ""
echo "--- 8. pe_patch 工具 ---"
PE_PATCH="$VERIFY_DIR/pe_patch_cli.c"
[ -f "$PE_PATCH" ] && ok "$PE_PATCH 存在" || fail "$PE_PATCH 缺失"

# ---------------------------------------------------------------
# 总结
# ---------------------------------------------------------------
echo ""
echo "============================================================"
echo "SubTask 5.2.1 测试用例集结构验证：PASS=$PASS FAIL=$FAIL"
echo "============================================================"
[ "$FAIL" -eq 0 ] && exit 0 || exit 1
