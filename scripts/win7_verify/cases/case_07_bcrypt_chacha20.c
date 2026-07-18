/*
 * case_07_bcrypt_chacha20.c - BCrypt CHACHA20_POLY1305 测试
 *
 * Win10 1709+ BCrypt 支持 CHACHA20_POLY1305，Win7 不支持。
 * Win7Bridge 应 hook BCryptOpenAlgorithmProvider 返回伪句柄。
 *
 * 期望：BCryptOpenAlgorithmProvider 返回 0 (STATUS_SUCCESS) 且 *phAlg 非 NULL。
 */
#include <stdio.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>

#ifndef _BCRYPT_ALG_HANDLE_DEFINED
typedef PVOID BCRYPT_ALG_HANDLE;
#define _BCRYPT_ALG_HANDLE_DEFINED
#endif

typedef LONG NTSTATUS;

typedef NTSTATUS (WINAPI *PFN_BCryptOpenAlgorithmProvider)(
    BCRYPT_ALG_HANDLE*, const wchar_t*, const wchar_t*, DWORD);
#endif

int main(void)
{
    int ok = 0;

    printf("==== case_07_bcrypt_chacha20 ====\n");

#ifdef _WIN32
    HMODULE hBcrypt = LoadLibraryA("bcrypt.dll");
    if (hBcrypt) {
        PFN_BCryptOpenAlgorithmProvider pfn =
            (PFN_BCryptOpenAlgorithmProvider)GetProcAddress(
                hBcrypt, "BCryptOpenAlgorithmProvider");
        if (pfn) {
            BCRYPT_ALG_HANDLE hAlg = NULL;
            NTSTATUS st = pfn(&hAlg, L"CHACHA20_POLY1305", NULL, 0);
            printf("BCryptOpenAlgorithmProvider status=0x%lX hAlg=%p\n",
                   (unsigned long)st, (void*)hAlg);
            if (st == 0 && hAlg != NULL) {
                ok = 1;
            }
        } else {
            printf("[FAIL] BCryptOpenAlgorithmProvider not found\n");
        }
        FreeLibrary(hBcrypt);
    } else {
        printf("[FAIL] Cannot load bcrypt.dll\n");
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
