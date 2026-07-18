/*
 * test_sim_misc.c - Win7Bridge L3 模拟层 host 测试
 *
 * 覆盖 Task 4.3（线程/控制台/内存模拟）、Task 4.4（DPI 回退）、
 * Task 4.6（UCRT 前置检测）：
 *   - sim_SetThreadDescription / sim_GetThreadDescription：设置 L"worker"
 *     后读回相等。
 *   - sim_VirtualAlloc2：分配 1024 字节非空，可写入，free。
 *   - sim_SetProcessDpiAwarenessContext：返回 TRUE。
 *   - sim_GetDpiForWindow：返回 96。
 *   - ucrt_check / ucrt_status_message：调用不崩溃，消息非空。
 *
 * 仅在定义 WIN7BRIDGE_HOST_TEST 时编译 main，返回 0 表示全部通过。
 */
#include "win7bridge/sim_thread.h"
#include "win7bridge/sim_dpi.h"
#include "win7bridge/ucrt_check.h"

#include <stdio.h>
#include <stdlib.h>
#include <wchar.h>

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

#ifdef WIN7BRIDGE_HOST_TEST
int main(void)
{
    /* ---- 线程描述：设置 L"worker" 后读回相等 ---- */
    printf("==== 线程描述 SetThreadDescription/GetThreadDescription ====\n");
    {
        HANDLE   t   = (HANDLE)1;     /* host 用 1 模拟线程句柄           */
        HRESULT  hr;
        wchar_t* got = NULL;

        hr = sim_SetThreadDescription(t, L"worker");
        CHECK(hr == S_OK, "sim_SetThreadDescription 返回 S_OK");

        hr = sim_GetThreadDescription(t, &got);
        CHECK(hr == S_OK, "sim_GetThreadDescription 返回 S_OK");
        CHECK(got != NULL && wcscmp(got, L"worker") == 0,
              "读回描述等于 L\"worker\"");
        free(got);
    }

    /* ---- VirtualAlloc2：分配 1024 字节，非空，可写入，free ---- */
    printf("==== 内存 VirtualAlloc2 退化 ====\n");
    {
        void* p = sim_VirtualAlloc2(NULL, NULL, 1024,
                                    SIM_MEM_COMMIT | SIM_MEM_RESERVE,
                                    SIM_PAGE_READWRITE, NULL);
        CHECK(p != NULL, "sim_VirtualAlloc2 分配 1024 字节非空");
        if (p != NULL) {
            ((unsigned char*)p)[0]    = 0xAB;
            ((unsigned char*)p)[1023] = 0xCD;
            CHECK(((unsigned char*)p)[0] == 0xAB &&
                      ((unsigned char*)p)[1023] == 0xCD,
                  "分配区域可写入且可读回");
            free(p);
        }
    }

    /* ---- DPI 回退：SetProcessDpiAwarenessContext 返回 TRUE ---- */
    printf("==== DPI SetProcessDpiAwarenessContext 回退 ====\n");
    {
        BOOL ok = sim_SetProcessDpiAwarenessContext(0);
        CHECK(ok == TRUE, "sim_SetProcessDpiAwarenessContext 返回 TRUE");
    }

    /* ---- DPI：GetDpiForWindow 返回 96 ---- */
    printf("==== DPI GetDpiForWindow ====\n");
    {
        UINT dpi = sim_GetDpiForWindow(NULL);
        CHECK(dpi == 96, "sim_GetDpiForWindow 返回 96");
    }

    /* ---- UCRT 检测：调用不崩溃，消息非空 ---- */
    printf("==== UCRT 前置检测 ====\n");
    {
        UcrtStatus  st  = UCRT_OK;
        int         rc  = ucrt_check(&st);
        const char* msg = ucrt_status_message(st);

        CHECK(rc == 0, "ucrt_check 返回 0");
        CHECK(msg != NULL && msg[0] != '\0',
              "ucrt_status_message 返回非空字符串");
        printf("[info] ucrt status=%d msg=\"%s\"\n", (int)st, msg);

        /* 对每个枚举值验证消息非空 */
        CHECK(ucrt_status_message(UCRT_OK) != NULL, "UCRT_OK 消息非空");
        CHECK(ucrt_status_message(UCRT_MISSING_UCRTBASE) != NULL,
              "UCRT_MISSING_UCRTBASE 消息非空");
        CHECK(ucrt_status_message(UCRT_MISSING_VCRUNTIME) != NULL,
              "UCRT_MISSING_VCRUNTIME 消息非空");
        CHECK(ucrt_status_message(UCRT_MISSING_MSVCPP) != NULL,
              "UCRT_MISSING_MSVCPP 消息非空");
    }

    if (g_fail) {
        printf("\n==== 存在失败用例 ====\n");
        return 1;
    }
    printf("\n==== 全部通过 ====\n");
    return 0;
}
#endif /* WIN7BRIDGE_HOST_TEST */
