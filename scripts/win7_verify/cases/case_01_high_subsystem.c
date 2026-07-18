/*
 * case_01_high_subsystem.c - 高子系统版本测试 EXE
 *
 * 编译时用 pe_patch --set-subsystem 10.0 设置 MajorSubsystemVersion=10.0。
 * Win7 加载器会拒绝高子系统版本的 EXE（0xC000007B），
 * 用 pe_patch.exe 修正为 6.1 后应正常启动。
 *
 * 期望：patched EXE 在 Win7 上能正常运行并返回 0。
 */
#include <stdio.h>
#include <string.h>

#ifdef _WIN32
#include <windows.h>
#endif

int main(void)
{
#ifdef _WIN32
    OSVERSIONINFOEXA vi;
#endif

    printf("==== case_01_high_subsystem ====\n");
    printf("Hello from patched EXE\n");
    printf("PID=%lu\n", (unsigned long)GetCurrentProcessId());

#ifdef _WIN32
    memset(&vi, 0, sizeof(vi));
    vi.dwOSVersionInfoSize = sizeof(vi);
    if (GetVersionExA((OSVERSIONINFOA*)&vi)) {
        printf("GetVersionExA: %u.%u build %u sp%u.%u\n",
               (unsigned)vi.dwMajorVersion,
               (unsigned)vi.dwMinorVersion,
               (unsigned)vi.dwBuildNumber,
               (unsigned)vi.wServicePackMajor,
               (unsigned)vi.wServicePackMinor);
    } else {
        printf("GetVersionExA failed err=%lu\n", (unsigned long)GetLastError());
    }
#endif

    printf("RESULT: PASS\n");
    return 0;
}
