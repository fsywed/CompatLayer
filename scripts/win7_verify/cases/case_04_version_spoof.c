/*
 * case_04_version_spoof.c - 版本伪装测试
 *
 * Win10 程序自检 IsWindows10OrGreater 在 Win7 上返回 FALSE。
 * Win7Bridge 应 hook GetVersionExW 返回 10.0.19045。
 *
 * 期望：GetVersionExW 返回 major>=10。
 */
#include <stdio.h>

#ifdef _WIN32
#include <windows.h>
#endif

int main(void)
{
    int ok = 0;

    printf("==== case_04_version_spoof ====\n");

#ifdef _WIN32
    OSVERSIONINFOEXW vi;
    memset(&vi, 0, sizeof(vi));
    vi.dwOSVersionInfoSize = sizeof(vi);
    if (GetVersionExW((OSVERSIONINFOW*)&vi)) {
        printf("GetVersionExW: %u.%u build %u\n",
               (unsigned)vi.dwMajorVersion,
               (unsigned)vi.dwMinorVersion,
               (unsigned)vi.dwBuildNumber);
        if (vi.dwMajorVersion >= 10) {
            ok = 1;
        }
    } else {
        printf("GetVersionExW failed err=%lu\n", (unsigned long)GetLastError());
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
