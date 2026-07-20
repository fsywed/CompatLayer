/*
 * test_version_helpers.c - Win7Bridge SubTask 4.1.3 验证测试
 *
 * 验证：通过 spoof_verify_version_info 模拟 Windows SDK 的
 *   IsWindowsXXXOrGreater 系列 helper，全部返回预期结果。
 *
 * Windows SDK 的 helper 实际实现（winnt.h / versionhelpers.h）：
 *   bool IsWindowsVersionOrGreater(int major, int minor, int build) {
 *     OSVERSIONINFOEXW osvi = { sizeof(osvi), major, minor, build, ... };
 *     DWORDLONG cm = VerSetConditionMask(...);
 *     return VerifyVersionInfoW(&osvi, VER_MAJORVERSION | VER_MINORVERSION
 *                                | VER_SERVICEPACKMAJOR, cm) != FALSE;
 *   }
 *   bool IsWindows10OrGreater()    = IsWindowsVersionOrGreater(10, 0, 0)
 *   bool IsWindows8OrGreater()     = IsWindowsVersionOrGreater(8, 0, 0)
 *   bool IsWindows7OrGreater()     = IsWindowsVersionOrGreater(6, 1, 0)
 *   bool IsWindowsXPOrGreater()    = IsWindowsVersionOrGreater(5, 1, 0)
 *   bool IsWindowsServer()         = 检查 wProductType != VER_NT_WORKSTATION
 *
 * 本测试用 spoof_verify_version_info 替代 VerifyVersionInfoW，复现
 * 上述逻辑，验证伪装为 Win10 22H2 后所有 helper 的返回值符合预期。
 *
 * 仅在定义 WIN7BRIDGE_HOST_TEST 时编译 main，用原生 gcc 运行。
 * 返回 0 表示全部通过，非 0 表示有失败。
 */
#include "win7bridge/spoof.h"

#include <stdio.h>
#include <string.h>

/* ------------------------------------------------------------------ */
/* 简单断言                                                            */
/* ------------------------------------------------------------------ */
static int g_fail = 0;
#define CHECK(cond, msg)                                                  \
    do {                                                                  \
        if (!(cond)) {                                                    \
            printf("[FAIL] %s:%d %s\n", __FILE__, __LINE__, (msg));       \
            g_fail = 1;                                                   \
        } else {                                                          \
            printf("[ok]   %s\n", (msg));                                 \
        }                                                                 \
    } while (0)

/* ------------------------------------------------------------------ */
/* 模拟 VerSetConditionMask                                            */
/*   按 Windows SDK 实现：conditionMask 是 64 位，每 3 位一组；          */
/*   VerSetConditionMask(mask, typeBit, op) 把第 (bit_index) 组置为 op。 */
/* ------------------------------------------------------------------ */
static DWORDLONG sim_ver_set_condition_mask(DWORDLONG mask, DWORD typeBit,
                                             int op)
{
    /* typeBit 是 VER_* 常量（1, 2, 4, 8, ...）；bit_index = log2(typeBit) */
    int bit_index = 0;
    DWORD t = typeBit;
    while (t > 1) { t >>= 1; ++bit_index; }
    return (mask & ~((DWORDLONG)0x7 << (bit_index * 3))) |
           ((DWORDLONG)op << (bit_index * 3));
}

/* ------------------------------------------------------------------ */
/* 模拟 IsWindowsVersionOrGreater                                      */
/*   与 versionhelpers.h 实现一致：构造 OSVERSIONINFOEXW + 条件掩码，   */
/*   调 VerifyVersionInfoW。这里用 spoof_verify_version_info 替代。      */
/* ------------------------------------------------------------------ */
static int sim_is_windows_version_or_greater(int major, int minor, int build)
{
    OSVERSIONINFOEXW osvi;
    DWORDLONG cm = 0;
    DWORD mask;

    memset(&osvi, 0, sizeof(osvi));
    osvi.dwOSVersionInfoSize = sizeof(osvi);
    osvi.dwMajorVersion      = (DWORD)major;
    osvi.dwMinorVersion      = (DWORD)minor;
    osvi.dwBuildNumber       = (DWORD)build;
    osvi.dwPlatformId        = VER_PLATFORM_WIN32_NT;
    osvi.wServicePackMajor   = 0;
    osvi.wProductType        = VER_NT_WORKSTATION;

    /* conditionMask：3 个维度都设为 VER_GREATER_EQUAL */
    cm = sim_ver_set_condition_mask(cm, VER_MAJORVERSION, VER_GREATER_EQUAL);
    cm = sim_ver_set_condition_mask(cm, VER_MINORVERSION, VER_GREATER_EQUAL);
    cm = sim_ver_set_condition_mask(cm, VER_SERVICEPACKMAJOR, VER_GREATER_EQUAL);

    mask = VER_MAJORVERSION | VER_MINORVERSION | VER_SERVICEPACKMAJOR;

    return spoof_verify_version_info(&osvi, mask, cm);
}

/* 模拟 IsWindows10OrGreater */
static int sim_is_windows_10_or_greater(void)
{
    return sim_is_windows_version_or_greater(10, 0, 0);
}

/* 模拟 IsWindows8OrGreater */
static int sim_is_windows_8_or_greater(void)
{
    return sim_is_windows_version_or_greater(8, 0, 0);
}

/* 模拟 IsWindows7OrGreater */
static int sim_is_windows_7_or_greater(void)
{
    return sim_is_windows_version_or_greater(6, 1, 0);
}

/* 模拟 IsWindowsXPOrGreater */
static int sim_is_windows_xp_or_greater(void)
{
    return sim_is_windows_version_or_greater(5, 1, 0);
}

/* 模拟 IsWindows11OrGreater（Win11 = 10.0.22000+）
 * 注意：真实 SDK 实现是检查 build >= 22000，需要包含 VER_BUILDNUMBER。 */
static int sim_is_windows_11_or_greater(void)
{
    OSVERSIONINFOEXW osvi;
    DWORDLONG cm = 0;
    DWORD mask;

    memset(&osvi, 0, sizeof(osvi));
    osvi.dwOSVersionInfoSize = sizeof(osvi);
    osvi.dwMajorVersion = 10;
    osvi.dwMinorVersion = 0;
    osvi.dwBuildNumber  = 22000;

    cm = sim_ver_set_condition_mask(cm, VER_MAJORVERSION, VER_GREATER_EQUAL);
    cm = sim_ver_set_condition_mask(cm, VER_MINORVERSION, VER_GREATER_EQUAL);
    cm = sim_ver_set_condition_mask(cm, VER_BUILDNUMBER, VER_GREATER_EQUAL);

    mask = VER_MAJORVERSION | VER_MINORVERSION | VER_BUILDNUMBER;
    return spoof_verify_version_info(&osvi, mask, cm);
}

/* 模拟 IsWindowsServer（VER_PRODUCT_TYPE != VER_NT_WORKSTATION 时为 TRUE） */
static int sim_is_windows_server(void)
{
    /* spoof 伪装 wProductType = VER_NT_WORKSTATION，所以非服务器 */
    /* 此 helper 实际通过 VerifyVersionInfoW 检查 VER_PRODUCT_TYPE */
    OSVERSIONINFOEXW osvi;
    DWORDLONG cm = 0;
    DWORD mask;

    memset(&osvi, 0, sizeof(osvi));
    osvi.dwOSVersionInfoSize = sizeof(osvi);
    osvi.wProductType = VER_NT_WORKSTATION;  /* 请求 != SERVER */
    cm = sim_ver_set_condition_mask(cm, VER_PRODUCT_TYPE, VER_EQUAL);
    mask = VER_PRODUCT_TYPE;
    /* 如果 spoof 系统 wProductType == VER_NT_WORKSTATION，则返回 TRUE
     * 意味着"当前是工作站"，反过来说 IsWindowsServer = FALSE */
    return !spoof_verify_version_info(&osvi, mask, cm);
}

/* ------------------------------------------------------------------ */
/* 用例 1：IsWindows10OrGreater 返回 TRUE                              */
/* ------------------------------------------------------------------ */
static void test_is_win10_or_greater(void)
{
    int rc;

    printf("==== 用例 1：IsWindows10OrGreater ====\n");

    spoof_init(NULL);  /* 默认 Win10 22H2 = 10.0.19045 */

    rc = sim_is_windows_10_or_greater();
    CHECK(rc == 1, "IsWindows10OrGreater() == TRUE（伪装 10.0.19045）");
}

/* ------------------------------------------------------------------ */
/* 用例 2：IsWindows8OrGreater 返回 TRUE                               */
/* ------------------------------------------------------------------ */
static void test_is_win8_or_greater(void)
{
    int rc;

    printf("==== 用例 2：IsWindows8OrGreater ====\n");

    rc = sim_is_windows_8_or_greater();
    CHECK(rc == 1, "IsWindows8OrGreater() == TRUE（10 >= 8）");
}

/* ------------------------------------------------------------------ */
/* 用例 3：IsWindows7OrGreater 返回 TRUE                               */
/* ------------------------------------------------------------------ */
static void test_is_win7_or_greater(void)
{
    int rc;

    printf("==== 用例 3：IsWindows7OrGreater ====\n");

    rc = sim_is_windows_7_or_greater();
    CHECK(rc == 1, "IsWindows7OrGreater() == TRUE（10.0 >= 6.1）");
}

/* ------------------------------------------------------------------ */
/* 用例 4：IsWindowsXPOrGreater 返回 TRUE                              */
/* ------------------------------------------------------------------ */
static void test_is_winxp_or_greater(void)
{
    int rc;

    printf("==== 用例 4：IsWindowsXPOrGreater ====\n");

    rc = sim_is_windows_xp_or_greater();
    CHECK(rc == 1, "IsWindowsXPOrGreater() == TRUE（10.0 >= 5.1）");
}

/* ------------------------------------------------------------------ */
/* 用例 5：IsWindows11OrGreater 返回 FALSE（伪装的是 10.0.19045）      */
/* ------------------------------------------------------------------ */
static void test_is_win11_or_greater(void)
{
    int rc;

    printf("==== 用例 5：IsWindows11OrGreater ====\n");

    rc = sim_is_windows_11_or_greater();
    /* 伪装 build 19045 < 22000，所以 IsWindows11OrGreater 应为 FALSE */
    CHECK(rc == 0, "IsWindows11OrGreater() == FALSE（build 19045 < 22000）");
}

/* ------------------------------------------------------------------ */
/* 用例 6：IsWindowsServer 返回 FALSE                                  */
/* ------------------------------------------------------------------ */
static void test_is_windows_server(void)
{
    int rc;

    printf("==== 用例 6：IsWindowsServer ====\n");

    rc = sim_is_windows_server();
    /* spoof 伪装 wProductType = VER_NT_WORKSTATION，所以非服务器 */
    CHECK(rc == 0, "IsWindowsServer() == FALSE（伪装为工作站）");
}

/* ------------------------------------------------------------------ */
/* 用例 7：spoof_get_version_legacy 返回 (0 << 16) | 10 = 0x0000000A   */
/* ------------------------------------------------------------------ */
static void test_get_version_legacy(void)
{
    DWORD v;

    printf("==== 用例 7：spoof_get_version_legacy ====\n");

    spoof_init(NULL);
    v = spoof_get_version_legacy();
    /* 期望 (minor=0) << 16 | (major=10) = 0x0000000A */
    CHECK(v == 0x0000000A, "GetVersion() == 0x0000000A（major=10, minor=0）");
    CHECK((v & 0xFFFF) == 10, "低 16 位 == major=10");
    CHECK(((v >> 16) & 0xFF) == 0, "bits 16-23 == minor=0");
    CHECK(((v >> 24) & 0xFF) == 0, "高 8 位 == 0（与 Win7 一致）");
}

/* ------------------------------------------------------------------ */
/* 用例 8：spoof_rtl_get_version 返回 0（STATUS_SUCCESS）              */
/* ------------------------------------------------------------------ */
static void test_rtl_get_version(void)
{
    int rc;
    OSVERSIONINFOEXW osvi;

    printf("==== 用例 8：spoof_rtl_get_version ====\n");

    memset(&osvi, 0, sizeof(osvi));
    rc = spoof_rtl_get_version(&osvi);
    CHECK(rc == 0, "RtlGetVersion 返回 0（STATUS_SUCCESS）");
    CHECK(osvi.dwMajorVersion == 10, "dwMajorVersion == 10");
    CHECK(osvi.dwMinorVersion == 0, "dwMinorVersion == 0");
    CHECK(osvi.dwBuildNumber == 19045, "dwBuildNumber == 19045");
    CHECK(osvi.dwPlatformId == VER_PLATFORM_WIN32_NT,
          "dwPlatformId == VER_PLATFORM_WIN32_NT");

    /* NULL 入参：仍返回 0（STATUS_SUCCESS），不填充 */
    rc = spoof_rtl_get_version(NULL);
    CHECK(rc == 0, "RtlGetVersion(NULL) 仍返回 0");
}

/* ------------------------------------------------------------------ */
/* 用例 9：spoof_rtl_get_nt_version_numbers 返回 10.0.19045|0xF0000000 */
/* ------------------------------------------------------------------ */
static void test_rtl_get_nt_version_numbers(void)
{
    DWORD maj = 0, min = 0, build = 0;

    printf("==== 用例 9：spoof_rtl_get_nt_version_numbers ====\n");

    spoof_init(NULL);
    spoof_rtl_get_nt_version_numbers(&maj, &min, &build);
    CHECK(maj == 10, "major == 10");
    CHECK(min == 0, "minor == 0");
    /* build = (19045 & 0x0FFFFFFF) | 0xF0000000 = 0xF0004A85 */
    CHECK((build & 0x0FFFFFFF) == 19045, "build 低 28 位 == 19045");
    CHECK((build & 0xF0000000u) == 0xF0000000u, "build 高 4 位 == 0xF");

    /* NULL 入参：跳过对应字段，不崩溃 */
    spoof_rtl_get_nt_version_numbers(NULL, NULL, NULL);
    CHECK(1, "全 NULL 入参不崩溃");
}

/* ------------------------------------------------------------------ */
/* 用例 10：自定义 SpoofConfig（伪装为 Win11 22H2）                    */
/* ------------------------------------------------------------------ */
static void test_custom_spoof_config(void)
{
    SpoofConfig cfg;
    WORD maj = 0, min = 0;
    DWORD build = 0;
    int rc;

    printf("==== 用例 10：自定义 SpoofConfig（Win11 22H2） ====\n");

    /* 伪装为 Win11 22H2 = 10.0.22621 */
    cfg.enabled = 1;
    cfg.major   = 10;
    cfg.minor   = 0;
    cfg.build   = 22621;

    spoof_init(&cfg);
    spoof_get_version(&maj, &min, &build);
    CHECK(maj == 10, "自定义 major == 10");
    CHECK(min == 0, "自定义 minor == 0");
    CHECK(build == 22621, "自定义 build == 22621");

    /* IsWindows11OrGreater 现在应为 TRUE */
    rc = sim_is_windows_11_or_greater();
    CHECK(rc == 1, "IsWindows11OrGreater() == TRUE（伪装 build 22621 >= 22000）");

    /* 重置回默认 Win10 22H2 */
    spoof_init(NULL);
}

/* ------------------------------------------------------------------ */
/* 主入口                                                              */
/* ------------------------------------------------------------------ */
#ifdef WIN7BRIDGE_HOST_TEST
int main(void)
{
    printf("=== SubTask 4.1.3 验证：IsWindows10OrGreater 类 helper ===\n\n");

    test_is_win10_or_greater();
    test_is_win8_or_greater();
    test_is_win7_or_greater();
    test_is_winxp_or_greater();
    test_is_win11_or_greater();
    test_is_windows_server();
    test_get_version_legacy();
    test_rtl_get_version();
    test_rtl_get_nt_version_numbers();
    test_custom_spoof_config();

    if (g_fail) {
        printf("\n[RESULT] test_version_helpers: FAIL\n");
        return 1;
    }
    printf("\n[RESULT] test_version_helpers: PASS\n");
    printf("\n验证结论：\n");
    printf("  - 伪装为 Win10 22H2 (10.0.19045) 后：\n");
    printf("    IsWindows10OrGreater / IsWindows8OrGreater /\n");
    printf("    IsWindows7OrGreater / IsWindowsXPOrGreater 全部返回 TRUE\n");
    printf("  - IsWindows11OrGreater 返回 FALSE（build 19045 < 22000）\n");
    printf("  - IsWindowsServer 返回 FALSE（伪装为工作站）\n");
    printf("  - GetVersion / RtlGetVersion / RtlGetNtVersionNumbers 返回\n");
    printf("    伪装版本号，build 高 4 位为 0xF（与真实 ntdll 一致）\n");
    return 0;
}
#endif
