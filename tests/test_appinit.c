/*
 * test_appinit.c - Win7Bridge SubTask 3.3 AppInit_DLLs 注册表注入 host 测试
 *
 * 验证：
 *   1) appinit_install：写入 dll_path 后 status 切换为 INSTALLED
 *   2) appinit_uninstall：清空后 status 切换为 UNINSTALLED（可逆）
 *   3) appinstall_install(NULL) / 空串 返回 INVALID_ARG
 *   4) appinit_risk_notice：返回字符串含"反调试"与"沙箱"关键词
 *   5) install/uninstall 幂等性：重复 uninstall 不报错
 *
 * 仅在定义 WIN7BRIDGE_HOST_TEST 时编译 main。
 */
#include "win7bridge/appinit.h"

#include <stdio.h>
#include <string.h>
#include <wchar.h>

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
    AppInitResult rc;
    AppInitState  st;
    const char*   notice;

    printf("==== 用例 1：appinit_install / status ====\n");
    /* 初始状态应为 UNINSTALLED */
    st = appinit_status();
    CHECK(st == APPINIT_STATE_UNINSTALLED, "初始状态 UNINSTALLED");

    rc = appinit_install(L"C:\\win7bridge\\win7bridge.dll");
    CHECK(rc == APPINIT_OK, "install 返回 APPINIT_OK");
    st = appinit_status();
    CHECK(st == APPINIT_STATE_INSTALLED, "install 后状态 INSTALLED");

    printf("==== 用例 2：appinit_uninstall 可逆 ====\n");
    rc = appinit_uninstall();
    CHECK(rc == APPINIT_OK, "uninstall 返回 APPINIT_OK");
    st = appinit_status();
    CHECK(st == APPINIT_STATE_UNINSTALLED, "uninstall 后状态 UNINSTALLED");

    printf("==== 用例 3：appinit_install NULL/空串 返回 INVALID_ARG ====\n");
    rc = appinit_install(NULL);
    CHECK(rc == APPINIT_ERR_INVALID_ARG, "NULL 入参返回 INVALID_ARG");
    rc = appinit_install(L"");
    CHECK(rc == APPINIT_ERR_INVALID_ARG, "空串返回 INVALID_ARG");

    printf("==== 用例 4：appinit_risk_notice 关键词 ====\n");
    notice = appinit_risk_notice();
    CHECK(notice != NULL && notice[0] != '\0', "风险提示非空");
    CHECK(strstr(notice, "反调试") != NULL, "提示含\"反调试\"");
    CHECK(strstr(notice, "沙箱") != NULL, "提示含\"沙箱\"");

    printf("==== 用例 5：uninstall 幂等性 ====\n");
    /* 重复 uninstall 不报错 */
    rc = appinit_uninstall();
    CHECK(rc == APPINIT_OK, "二次 uninstall 仍返回 OK");
    rc = appinit_uninstall();
    CHECK(rc == APPINIT_OK, "三次 uninstall 仍返回 OK");

    if (g_fail) {
        printf("\n==== 存在失败用例 ====\n");
        return 1;
    }
    printf("\n==== 全部通过 ====\n");
    return 0;
}
#endif /* WIN7BRIDGE_HOST_TEST */
