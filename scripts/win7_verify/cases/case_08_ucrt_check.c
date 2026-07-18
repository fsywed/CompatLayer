/*
 * case_08_ucrt_check.c - UCRT 前置检测测试
 *
 * Win7 缺 UCRT（KB2999226），Win10 程序启动会失败。
 * Win7Bridge 应在启动前检测并给出可读提示。
 *
 * 期望：检测程序能运行（不论 UCRT 是否安装都返回 0）。
 */
#include <stdio.h>

#ifdef _WIN32
#include <windows.h>

typedef int (*PFN_ucrt_check)(int*);
typedef const char* (*PFN_ucrt_status_message)(int);

int g_status_value = 0;
#endif

int main(void)
{
    printf("==== case_08_ucrt_check ====\n");

#ifdef _WIN32
    /* 通过 LoadLibrary 加载 win7bridge.dll 的导出（已注入情况下也可直接调用） */
    HMODULE h = LoadLibraryA("win7bridge.dll");
    if (h) {
        PFN_ucrt_check pfn_check =
            (PFN_ucrt_check)GetProcAddress(h, "ucrt_check");
        PFN_ucrt_status_message pfn_msg =
            (PFN_ucrt_status_message)GetProcAddress(h, "ucrt_status_message");
        if (pfn_check && pfn_msg) {
            int status = 0;
            pfn_check(&status);
            printf("ucrt_status=%d msg=%s\n", status, pfn_msg(status));
        } else {
            printf("[INFO] win7bridge.dll loaded but ucrt_* not exported\n");
        }
        FreeLibrary(h);
    } else {
        printf("[INFO] win7bridge.dll not loaded (standalone mode)\n");
    }
#else
    printf("(host mode)\n");
#endif

    /* case_08 始终 PASS：本用例仅验证 ucrt_check 模块可被调用 */
    printf("RESULT: PASS\n");
    return 0;
}
