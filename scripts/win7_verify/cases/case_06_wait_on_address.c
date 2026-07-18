/*
 * case_06_wait_on_address.c - WaitOnAddress 测试
 *
 * Win8+ 引入 WaitOnAddress/WakeByAddressSingle/WakeByAddressAll，
 * Win7 缺失。Win7Bridge 应提供本地回退实现。
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

    printf("==== case_06_wait_on_address ====\n");

#ifdef _WIN32
    HMODULE h = GetModuleHandleW(L"kernel32.dll");
    if (h) {
        void* p1 = (void*)GetProcAddress(h, "WaitOnAddress");
        void* p2 = (void*)GetProcAddress(h, "WakeByAddressSingle");
        void* p3 = (void*)GetProcAddress(h, "WakeByAddressAll");
        if (p1) printf("[OK]   WaitOnAddress at %p\n", p1);
        else    printf("[FAIL] WaitOnAddress not found\n");
        if (p2) printf("[OK]   WakeByAddressSingle at %p\n", p2);
        else    printf("[FAIL] WakeByAddressSingle not found\n");
        if (p3) printf("[OK]   WakeByAddressAll at %p\n", p3);
        else    printf("[FAIL] WakeByAddressAll not found\n");
        if (p1 && p2 && p3) ok = 1;
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
