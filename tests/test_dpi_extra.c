/*
 * test_dpi_extra.c - Win7Bridge SubTask 4.4.2 DPI 新 API 回退 host 测试
 *
 * 验证：
 *   1) sim_GetDpiForSystem：host 返回 96
 *   2) sim_GetDpiForMonitor：host 返回 96（dpi_x/dpi_y 同时被填充）
 *      + NULL 出参返回 E_POINTER
 *   3) sim_GetSystemMetricsForDpi：host 不 crash，返回 0
 *   4) sim_EnableNonClientDpiScaling：host 返回 TRUE
 *
 * 仅在定义 WIN7BRIDGE_HOST_TEST 时编译 main。
 */
#include "win7bridge/sim_dpi.h"

#include <stdio.h>

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
/* main                                                                */
/* ------------------------------------------------------------------ */
#ifdef WIN7BRIDGE_HOST_TEST
int main(void)
{
    UINT    dpi;
    UINT    dx, dy;
    HRESULT hr;
    int     sm;
    BOOL    ok;

    printf("==== 用例 1：sim_GetDpiForSystem ====\n");
    dpi = sim_GetDpiForSystem();
    CHECK(dpi == 96, "GetDpiForSystem 返回 96");

    printf("==== 用例 2：sim_GetDpiForMonitor ====\n");
    dx = 0; dy = 0;
    hr = sim_GetDpiForMonitor(NULL, 0, &dx, &dy);
    CHECK(hr == S_OK, "GetDpiForMonitor 返回 S_OK");
    CHECK(dx == 96 && dy == 96, "dpi_x/dpi_y 均为 96");

    printf("==== 用例 2.1：sim_GetDpiForMonitor NULL 出参 ====\n");
    hr = sim_GetDpiForMonitor(NULL, 0, NULL, &dy);
    CHECK(hr == E_POINTER, "dpi_x=NULL 返回 E_POINTER");
    hr = sim_GetDpiForMonitor(NULL, 0, &dx, NULL);
    CHECK(hr == E_POINTER, "dpi_y=NULL 返回 E_POINTER");

    printf("==== 用例 3：sim_GetSystemMetricsForDpi ====\n");
    sm = sim_GetSystemMetricsForDpi(0, 96);
    CHECK(sm == 0, "GetSystemMetricsForDpi host 返回 0");

    printf("==== 用例 4：sim_EnableNonClientDpiScaling ====\n");
    ok = sim_EnableNonClientDpiScaling(NULL);
    CHECK(ok == TRUE, "EnableNonClientDpiScaling 返回 TRUE");

    if (g_fail) {
        printf("\n==== 存在失败用例 ====\n");
        return 1;
    }
    printf("\n==== 全部通过 ====\n");
    return 0;
}
#endif /* WIN7BRIDGE_HOST_TEST */
