/*
 * case_02_apiset_import.c - API Set 虚拟解析测试
 *
 * Win10 程序常导入 api-ms-win-core-synch-l1-2-0.dll（含 WaitOnAddress）。
 * Win7 没有这个 API set DLL，Win7Bridge 应把它重定向到本地实现。
 *
 * 期望：LoadLibraryA + GetProcAddress 都成功。
 */
#include <stdio.h>

#ifdef _WIN32
#include <windows.h>
#endif

int main(void)
{
    int ok = 0;

    printf("==== case_02_apiset_import ====\n");

#ifdef _WIN32
    HMODULE h = LoadLibraryA("api-ms-win-core-synch-l1-2-0.dll");
    if (h) {
        void* p = (void*)GetProcAddress(h, "WaitOnAddress");
        if (p) {
            printf("[OK]   WaitOnAddress resolved at %p\n", p);
            ok = 1;
        } else {
            printf("[FAIL] WaitOnAddress not found (err=%lu)\n",
                   (unsigned long)GetLastError());
        }
        FreeLibrary(h);
    } else {
        printf("[FAIL] Cannot load api-ms-win-core-synch-l1-2-0.dll (err=%lu)\n",
               (unsigned long)GetLastError());
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
