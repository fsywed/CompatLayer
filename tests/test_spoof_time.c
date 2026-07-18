/*
 * test_spoof_time.c - Win7Bridge 版本伪装(L4)与时间/同步模拟(L3) host 测试
 *
 * 覆盖：
 *   1) spoof_get_version：返回 10.0 build 19045
 *   2) spoof_get_version_ex_w：dwMajorVersion==10, dwBuildNumber==19045
 *   3) spoof_verify_version_info：请求"≥Win10"返回 1（TRUE），
 *      并附"≥Win11 build"反向 FALSE 校验
 *   4) sim_GetSystemTimePreciseAsFileTime：调用后 FILETIME 非零
 *   5) sim_WaitOnAddress：addr!=compare 立即返回 0；
 *      addr==compare + 0 超时返回 258（WAIT_TIMEOUT）；
 *      WakeByAddress* 后 0 超时返回 0（WAIT_OBJECT_0）
 *
 * 仅在定义 WIN7BRIDGE_HOST_TEST 时编译 main，用原生 gcc 运行。
 * 返回 0 表示全部通过，非 0 表示有失败。
 */
#include "win7bridge/spoof.h"
#include "win7bridge/sim_time.h"

#include <stdio.h>
#include <string.h>
#include <stdint.h>

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
/* 用例 1：spoof_get_version                                           */
/* ------------------------------------------------------------------ */
static void test_spoof_get_version(void)
{
    WORD  maj = 0, min = 0;
    DWORD build = 0;
    int   rc;

    printf("==== 用例 1：spoof_get_version ====\n");

    rc = spoof_init(NULL);
    CHECK(rc == 1, "spoof_init(NULL) 返回 1");

    rc = spoof_get_version(&maj, &min, &build);
    CHECK(rc == 1, "spoof_get_version 返回 1");
    CHECK(maj == SPOOF_MAJOR, "major == 10");
    CHECK(min == SPOOF_MINOR, "minor == 0");
    CHECK(build == SPOOF_BUILD, "build == 19045");
}

/* ------------------------------------------------------------------ */
/* 用例 2：spoof_get_version_ex_w                                      */
/* ------------------------------------------------------------------ */
static void test_spoof_get_version_ex_w(void)
{
    OSVERSIONINFOEXW osvi;
    int rc;

    printf("==== 用例 2：spoof_get_version_ex_w ====\n");

    rc = spoof_get_version_ex_w(&osvi);
    CHECK(rc == 1, "spoof_get_version_ex_w 返回 1");
    CHECK(osvi.dwOSVersionInfoSize == (DWORD)sizeof(OSVERSIONINFOEXW),
          "dwOSVersionInfoSize == sizeof(OSVERSIONINFOEXW)");
    CHECK(osvi.dwMajorVersion == 10, "dwMajorVersion == 10");
    CHECK(osvi.dwMinorVersion == 0, "dwMinorVersion == 0");
    CHECK(osvi.dwBuildNumber == 19045, "dwBuildNumber == 19045");
    CHECK(osvi.dwPlatformId == VER_PLATFORM_WIN32_NT, "dwPlatformId == 2");
    CHECK(osvi.wProductType == VER_NT_WORKSTATION, "wProductType == 1");
}

/* ------------------------------------------------------------------ */
/* 用例 3：spoof_verify_version_info                                   */
/* ------------------------------------------------------------------ */
static void test_spoof_verify_version_info(void)
{
    OSVERSIONINFOEXW req;
    DWORDLONG        cond;
    DWORD            typeMask;
    int              rc;

    printf("==== 用例 3：spoof_verify_version_info ====\n");

    /* 请求"系统 >= Win10 (10.0)"：应返回 TRUE */
    memset(&req, 0, sizeof(req));
    req.dwMajorVersion = 10;
    req.dwMinorVersion = 0;
    req.dwPlatformId   = VER_PLATFORM_WIN32_NT;

    typeMask = VER_MAJORVERSION | VER_MINORVERSION;
    /* VER_MAJORVERSION=bit1 -> 第1组(shift 3)；VER_MINORVERSION=bit0 -> 第0组(shift 0)
     * 均取 VER_GREATER_EQUAL(3) */
    cond = ((DWORDLONG)VER_GREATER_EQUAL << (1 * 3)) |
           ((DWORDLONG)VER_GREATER_EQUAL << (0 * 3));

    rc = spoof_verify_version_info(&req, typeMask, cond);
    CHECK(rc == 1, "请求'>=Win10' 返回 1 (TRUE)");

    /* 反向校验：请求"系统 build >= 22621(Win11)"，伪装 build 19045 应返回 FALSE */
    {
        OSVERSIONINFOEXW req2;
        DWORDLONG        cond2;
        memset(&req2, 0, sizeof(req2));
        req2.dwMajorVersion = 10;
        req2.dwBuildNumber  = 22621;
        /* VER_BUILDNUMBER=bit2 -> 第2组(shift 6) */
        cond2 = (DWORDLONG)VER_GREATER_EQUAL << (2 * 3);
        rc = spoof_verify_version_info(&req2, VER_BUILDNUMBER, cond2);
        CHECK(rc == 0, "请求'>=build 22621' 返回 0 (FALSE，伪装 19045)");
    }
}

/* ------------------------------------------------------------------ */
/* 用例 4：sim_GetSystemTimePreciseAsFileTime                          */
/* ------------------------------------------------------------------ */
static void test_sim_get_system_time_precise(void)
{
    FILETIME ft;
    uint64_t v;
    int      rc;

    printf("==== 用例 4：sim_GetSystemTimePreciseAsFileTime ====\n");

    memset(&ft, 0, sizeof(ft));
    rc = sim_GetSystemTimePreciseAsFileTime(&ft);
    CHECK(rc == 1, "返回 1");
    v = ((uint64_t)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
    CHECK(v != 0, "FILETIME 非零");
}

/* ------------------------------------------------------------------ */
/* 用例 5：sim_WaitOnAddress / WakeByAddress*                          */
/* ------------------------------------------------------------------ */
static void test_sim_wait_on_address(void)
{
    int val        = 5;
    int compare_eq = 5;
    int compare_ne = 6;
    int rc;

    printf("==== 用例 5：sim_WaitOnAddress ====\n");

    /* 5.1 addr != compare -> 立即返回 WAIT_OBJECT_0(0) */
    rc = sim_WaitOnAddress((volatile void*)&val, (void*)&compare_ne,
                           (SIZE_T)sizeof(int), 1000);
    CHECK(rc == WAIT_OBJECT_0, "addr!=compare 立即返回 0 (WAIT_OBJECT_0)");

    /* 5.2 addr == compare 且 timeout=0 -> 返回 WAIT_TIMEOUT(258) */
    rc = sim_WaitOnAddress((volatile void*)&val, (void*)&compare_eq,
                           (SIZE_T)sizeof(int), 0);
    CHECK(rc == WAIT_TIMEOUT, "addr==compare + 0 超时返回 258 (WAIT_TIMEOUT)");

    /* 5.3 WakeByAddress* 可调用且返回 0 */
    rc = sim_WakeByAddressSingle((void*)&val);
    CHECK(rc == 0, "sim_WakeByAddressSingle 返回 0");
    rc = sim_WakeByAddressAll((void*)&val);
    CHECK(rc == 0, "sim_WakeByAddressAll 返回 0");

    /* 5.4 被 wake 后，addr==compare 的 0 超时调用应返回 WAIT_OBJECT_0
     *     （唤醒标志已置，轮询首检即命中） */
    rc = sim_WaitOnAddress((volatile void*)&val, (void*)&compare_eq,
                           (SIZE_T)sizeof(int), 0);
    CHECK(rc == WAIT_OBJECT_0, "wake 后 0 超时返回 0 (WAIT_OBJECT_0)");
}

/* ------------------------------------------------------------------ */
/* main                                                                */
/* ------------------------------------------------------------------ */
#ifdef WIN7BRIDGE_HOST_TEST
int main(void)
{
    test_spoof_get_version();
    test_spoof_get_version_ex_w();
    test_spoof_verify_version_info();
    test_sim_get_system_time_precise();
    test_sim_wait_on_address();

    if (g_fail) {
        printf("\n==== 存在失败用例 ====\n");
        return 1;
    }
    printf("\n==== 全部通过 ====\n");
    return 0;
}
#endif /* WIN7BRIDGE_HOST_TEST */
