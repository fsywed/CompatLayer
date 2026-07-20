/*
 * test_ucrt_check.c - Win7Bridge SubTask 4.6 UCRT 前置检测专项 host 测试
 *
 * 覆盖：
 *   4.6.1/4.6.2 host 路径下 /tmp 模拟 DLL 通常缺失，应返回
 *               UCRT_MISSING_UCRTBASE；状态码完整传递。
 *   4.6.3 提示消息含 "KB2999226" / "VCRedist" 关键词；NULL 入参安全。
 *
 * 仅在定义 WIN7BRIDGE_HOST_TEST 时编译 main。
 */
#include "win7bridge/ucrt_check.h"

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
/* main                                                                */
/* ------------------------------------------------------------------ */
#ifdef WIN7BRIDGE_HOST_TEST
int main(void)
{
    UcrtStatus st;
    int        rc;
    const char* msg;

    printf("==== 用例 1：ucrt_check NULL 出参 ====\n");
    rc = ucrt_check(NULL);
    CHECK(rc != 0, "NULL 出参返回非 0");

    printf("==== 用例 2：ucrt_check host 缺失场景 ====\n");
    /* host 沙箱中 /tmp/ucrtbase.dll 通常不存在 */
    st = UCRT_OK;
    rc = ucrt_check(&st);
    CHECK(rc == 0, "ucrt_check 返回 0");
    CHECK(st == UCRT_MISSING_UCRTBASE,
          "host 沙箱返回 UCRT_MISSING_UCRTBASE");

    printf("==== 用例 3：UCRT_MISSING_UCRTBASE 消息含 KB2999226 ====\n");
    msg = ucrt_status_message(UCRT_MISSING_UCRTBASE);
    CHECK(msg != NULL && strstr(msg, "KB2999226") != NULL,
          "消息含 \"KB2999226\"");

    printf("==== 用例 4：VCRedist 缺失消息 ====\n");
    msg = ucrt_status_message(UCRT_MISSING_VCRUNTIME);
    CHECK(msg != NULL && strstr(msg, "VCRedist") != NULL,
          "vcruntime 消息含 \"VCRedist\"");
    msg = ucrt_status_message(UCRT_MISSING_MSVCPP);
    CHECK(msg != NULL && strstr(msg, "VCRedist") != NULL,
          "msvcp 消息含 \"VCRedist\"");

    printf("==== 用例 5：UCRT_OK 消息非空 ====\n");
    msg = ucrt_status_message(UCRT_OK);
    CHECK(msg != NULL && msg[0] != '\0', "UCRT_OK 消息非空");

    if (g_fail) {
        printf("\n==== 存在失败用例 ====\n");
        return 1;
    }
    printf("\n==== 全部通过 ====\n");
    return 0;
}
#endif /* WIN7BRIDGE_HOST_TEST */
