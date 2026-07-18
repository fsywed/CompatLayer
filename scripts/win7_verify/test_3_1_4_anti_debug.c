/*
 * test_3_1_4_anti_debug.c - 反调试检测目标进程
 *
 * 检查 4 项常见反调试 API：
 *   bit0: IsDebuggerPresent() 返回非 0
 *   bit1: NtQueryInformationProcess(ProcessDebugPort=7) *pdw != 0
 *   bit2: NtQueryInformationProcess(ProcessDebugFlags=31) *pdw == 0
 *   bit3: CheckRemoteDebuggerPresent 返回 TRUE
 *
 * 退出码位掩码：0 = 全通过（未被检测到调试器）
 *               bit8 = 致命错误（NtQueryInformationProcess 无法解析）
 */
#include <stdio.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>

typedef LONG (WINAPI *PFN_NtQueryInformationProcess)(
    HANDLE, ULONG, PVOID, ULONG, PULONG);
#endif

int main(void)
{
    int result = 0;

    printf("==== test_3_1_4_anti_debug ====\n");

#ifdef _WIN32
    /* bit0: IsDebuggerPresent */
    if (IsDebuggerPresent()) {
        printf("[FAIL] IsDebuggerPresent returned TRUE\n");
        result |= 0x01;
    } else {
        printf("[OK]   IsDebuggerPresent returned FALSE\n");
    }

    /* 动态解析 NtQueryInformationProcess */
    {
        HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
        PFN_NtQueryInformationProcess pfn = NULL;
        if (hNtdll) {
            pfn = (PFN_NtQueryInformationProcess)GetProcAddress(hNtdll,
                "NtQueryInformationProcess");
        }
        if (!pfn) {
            printf("[FATAL] Cannot resolve NtQueryInformationProcess\n");
            printf("RESULT: FAIL\n");
            return result | 0x100;
        }

        /* bit1: ProcessDebugPort (7) */
        {
            ULONG_PTR port = 0;
            ULONG len = 0;
            LONG st = pfn(GetCurrentProcess(), 7, &port, sizeof(port), &len);
            if (st == 0 && port != 0) {
                printf("[FAIL] ProcessDebugPort=%lu (debugger attached)\n",
                       (unsigned long)port);
                result |= 0x02;
            } else {
                printf("[OK]   ProcessDebugPort=0 (no debugger)\n");
            }
        }

        /* bit2: ProcessDebugFlags (31) - 0 means being debugged */
        {
            DWORD flags = 0;
            ULONG len = 0;
            LONG st = pfn(GetCurrentProcess(), 31, &flags, sizeof(flags), &len);
            if (st == 0 && flags == 0) {
                printf("[FAIL] ProcessDebugFlags=0 (debugger attached)\n");
                result |= 0x04;
            } else {
                printf("[OK]   ProcessDebugFlags=%lu (no debugger)\n",
                       (unsigned long)flags);
            }
        }
    }

    /* bit3: CheckRemoteDebuggerPresent */
    {
        BOOL isPresent = FALSE;
        if (CheckRemoteDebuggerPresent(GetCurrentProcess(), &isPresent) && isPresent) {
            printf("[FAIL] CheckRemoteDebuggerPresent returned TRUE\n");
            result |= 0x08;
        } else {
            printf("[OK]   CheckRemoteDebuggerPresent returned FALSE\n");
        }
    }

    printf("exit_code_mask: 0x%X\n", result);
    if (result == 0) {
        printf("RESULT: PASS\n");
    } else {
        printf("RESULT: FAIL\n");
    }
#else
    /* host 模式：无 Windows API，直接 PASS（逻辑测试用） */
    printf("(host mode: no Windows API, skipping real checks)\n");
    printf("RESULT: PASS\n");
#endif

    return result;
}
