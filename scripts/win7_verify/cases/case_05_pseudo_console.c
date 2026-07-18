/*
 * case_05_pseudo_console.c - CreatePseudoConsole 测试
 *
 * Win10 1809 新增 CreatePseudoConsole，Win7 缺失。
 * Win7Bridge 应通过 hook GetProcAddress 返回兼容层 sim_CreatePseudoConsole。
 *
 * 期望：GetProcAddress 返回非 NULL。
 */
#include <stdio.h>

#ifdef _WIN32
#include <windows.h>
#endif

int main(void)
{
    int ok = 0;

    printf("==== case_05_pseudo_console ====\n");

#ifdef _WIN32
    HMODULE h = GetModuleHandleW(L"kernel32.dll");
    if (h) {
        void* p = (void*)GetProcAddress(h, "CreatePseudoConsole");
        if (p) {
            printf("[OK]   CreatePseudoConsole at %p\n", p);
            ok = 1;
        } else {
            printf("[FAIL] CreatePseudoConsole not found\n");
        }
    }
#else
    printf("(host mode)\n");
    ok = 1;
#endif

    if (ok) {
        printf("RESULT: PASS\n");
        return 0;
    }
    printf("RESULT: FAIL\n");
    return 1;
}
