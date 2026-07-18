/*
 * case_03_get_proc_address.c - GetProcAddress 动态解析测试
 *
 * Win10 新增 SetThreadDescription/GetThreadDescription。
 * Win7 kernel32.dll 没有这些导出，Win7Bridge 应通过 hook
 * GetProcAddress 返回兼容层实现。
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

    printf("==== case_03_get_proc_address ====\n");

#ifdef _WIN32
    HMODULE h = GetModuleHandleW(L"kernel32.dll");
    if (!h) h = LoadLibraryW(L"kernel32.dll");
    if (h) {
        void* set_desc = (void*)GetProcAddress(h, "SetThreadDescription");
        void* get_desc = (void*)GetProcAddress(h, "GetThreadDescription");
        if (set_desc) {
            printf("[OK]   SetThreadDescription at %p\n", set_desc);
        } else {
            printf("[FAIL] SetThreadDescription not found\n");
        }
        if (get_desc) {
            printf("[OK]   GetThreadDescription at %p\n", get_desc);
        } else {
            printf("[FAIL] GetThreadDescription not found\n");
        }
        if (set_desc && get_desc) ok = 1;
    } else {
        printf("[FAIL] Cannot load kernel32.dll\n");
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
