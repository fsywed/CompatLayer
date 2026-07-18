/*
 * fake_windows.h - Win32 API stub for -D_WIN32 syntax check on Linux
 *
 * Provides minimal type/API declarations so that win7_verify/*.c files
 * can be syntax-checked with: gcc -fsyntax-only -D_WIN32 -isystem tools/win_check
 */
#ifndef WIN7BRIDGE_FAKE_WINDOWS_H
#define WIN7BRIDGE_FAKE_WINDOWS_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <wchar.h>

/* Calling convention macros (neutralized by -D flags) */
#ifndef WINAPI
#define WINAPI
#endif
#ifndef CALLBACK
#define CALLBACK
#endif
#ifndef APIENTRY
#define APIENTRY
#endif

/* Basic types */
typedef unsigned char       BYTE;
typedef unsigned short      WORD;
typedef short               SHORT;
typedef unsigned int        UINT;
typedef unsigned long       DWORD;
typedef unsigned long       ULONG;
typedef long                LONG;
typedef unsigned long       ULONG_PTR;
typedef long                LONG_PTR;
typedef long long           LONGLONG;
typedef unsigned long long  ULONGLONG;
typedef void                VOID;
typedef BYTE                UCHAR;
typedef BYTE*               PUCHAR;
typedef char                CHAR;
typedef wchar_t             WCHAR;
typedef CHAR*               LPSTR;
typedef const CHAR*         LPCSTR;
typedef WCHAR*              LPWSTR;
typedef const WCHAR*         LPCWSTR;
typedef wchar_t*            PWSTR;
typedef const wchar_t*      PCWSTR;
typedef int                 BOOL;
typedef void*               HANDLE;
typedef void*               HMODULE;
typedef void*               HINSTANCE;
typedef void*               HWND;
typedef void*               HKEY;
typedef void*               PVOID;
typedef void*               LPVOID;
typedef DWORD*              LPDWORD;
typedef ULONG*              PULONG;
typedef const void*         LPCVOID;
typedef size_t              SIZE_T;
typedef void*               LPSECURITY_ATTRIBUTES;
typedef ULONG_PTR           DWORD_PTR;
typedef BYTE*               LPBYTE;
typedef DWORD               HCOOKIE;

/* HRESULT */
typedef LONG HRESULT;

/* Pointer-sized int */
typedef LONG_PTR            SSIZE_T;

/* FARPROC */
typedef int (WINAPI *FARPROC)(void);

/* Constants */
#define NULL                0
#define TRUE                1
#define FALSE               0
#define INFINITE            0xFFFFFFFF

#define WAIT_OBJECT_0       0
#define WAIT_TIMEOUT        258
#define WAIT_FAILED         0xFFFFFFFF

#define ERROR_INVALID_PARAMETER 87L

/* inject.c / dllmain.c 用：CreateProcess / VirtualAlloc / DllMain reason */
#define CREATE_SUSPENDED      0x00000004
#define MEM_COMMIT            0x00001000
#define MEM_RESERVE           0x00002000
#define MEM_RELEASE           0x00008000
#define PAGE_READWRITE        0x00000004
#define DLL_PROCESS_ATTACH    1
#define DLL_THREAD_ATTACH     2
#define DLL_THREAD_DETACH     3
#define DLL_PROCESS_DETACH    0

/* Ver* constants */
#define VER_MAJORVERSION      0x0000002
#define VER_MINORVERSION      0x0000001
#define VER_GREATER_EQUAL     3

/* Process info classes */
#define ProcessDebugPort      7
#define ProcessDebugFlags     31

/* OSVERSIONINFO structures */
typedef struct _OSVERSIONINFOA {
    DWORD dwOSVersionInfoSize;
    DWORD dwMajorVersion;
    DWORD dwMinorVersion;
    DWORD dwBuildNumber;
    DWORD dwPlatformId;
    char  szCSDVersion[128];
} OSVERSIONINFOA;

typedef struct _OSVERSIONINFOW {
    DWORD   dwOSVersionInfoSize;
    DWORD   dwMajorVersion;
    DWORD   dwMinorVersion;
    DWORD   dwBuildNumber;
    DWORD   dwPlatformId;
    wchar_t szCSDVersion[128];
} OSVERSIONINFOW;

typedef struct _OSVERSIONINFOEXA {
    DWORD dwOSVersionInfoSize;
    DWORD dwMajorVersion;
    DWORD dwMinorVersion;
    DWORD dwBuildNumber;
    DWORD dwPlatformId;
    char  szCSDVersion[128];
    WORD  wServicePackMajor;
    WORD  wServicePackMinor;
    WORD  wSuiteMask;
    BYTE  wProductType;
    BYTE  wReserved;
} OSVERSIONINFOEXA;

typedef struct _OSVERSIONINFOEXW {
    DWORD   dwOSVersionInfoSize;
    DWORD   dwMajorVersion;
    DWORD   dwMinorVersion;
    DWORD   dwBuildNumber;
    DWORD   dwPlatformId;
    wchar_t szCSDVersion[128];
    WORD    wServicePackMajor;
    WORD    wServicePackMinor;
    WORD    wSuiteMask;
    BYTE    wProductType;
    BYTE    wReserved;
} OSVERSIONINFOEXW;

/* LARGE_INTEGER */
typedef union _LARGE_INTEGER {
    struct {
        DWORD LowPart;
        LONG  HighPart;
    };
    LONGLONG QuadPart;
} LARGE_INTEGER;

typedef union _ULARGE_INTEGER {
    struct {
        DWORD LowPart;
        DWORD HighPart;
    };
    ULONGLONG QuadPart;
} ULARGE_INTEGER;

/* COORD */
typedef struct _COORD {
    SHORT X;
    SHORT Y;
} COORD;

/* HPCON */
typedef PVOID HPCON;

/* STARTUPINFOA / PROCESS_INFORMATION（inject.c 用） */
typedef struct _STARTUPINFOA {
    DWORD cb;
    LPSTR lpReserved;
    LPSTR lpDesktop;
    LPSTR lpTitle;
    DWORD dwX, dwY, dwXSize, dwYSize;
    DWORD dwXCountChars, dwYCountChars;
    DWORD dwFillAttribute;
    DWORD dwFlags;
    WORD  wShowWindow;
    WORD  cbReserved2;
    LPBYTE lpReserved2;
    HANDLE hStdInput;
    HANDLE hStdOutput;
    HANDLE hStdError;
} STARTUPINFOA, *LPSTARTUPINFOA;

typedef struct _PROCESS_INFORMATION {
    HANDLE hProcess;
    HANDLE hThread;
    DWORD  dwProcessId;
    DWORD  dwThreadId;
} PROCESS_INFORMATION, *LPPROCESS_INFORMATION;

typedef DWORD (WINAPI *LPTHREAD_START_ROUTINE)(LPVOID);

/* HIWORD 宏：GetProcAddress 按名/按序号区分用 */
#ifndef HIWORD
#define HIWORD(l) ((WORD)(((DWORD_PTR)(l) >> 16) & 0xFFFF))
#endif

/* Function declarations */
HMODULE WINAPI LoadLibraryA(LPCSTR);
HMODULE WINAPI LoadLibraryW(LPCWSTR);
HMODULE WINAPI GetModuleHandleA(LPCSTR);
BOOL    WINAPI FreeLibrary(HMODULE);
FARPROC WINAPI GetProcAddress(HMODULE, LPCSTR);
HMODULE WINAPI GetModuleHandleW(LPCWSTR);
DWORD   WINAPI GetLastError(void);
void    WINAPI SetLastError(DWORD);
DWORD   WINAPI GetCurrentProcessId(void);
DWORD   WINAPI GetCurrentThreadId(void);
HANDLE  WINAPI GetCurrentProcess(void);
HANDLE  WINAPI GetCurrentThread(void);
BOOL    WINAPI IsDebuggerPresent(void);
BOOL    WINAPI CheckRemoteDebuggerPresent(HANDLE, BOOL*);
BOOL    WINAPI GetVersionExA(OSVERSIONINFOA*);
BOOL    WINAPI GetVersionExW(OSVERSIONINFOW*);
BOOL    WINAPI VerifyVersionInfoW(OSVERSIONINFOEXW*, DWORD, ULONGLONG);
ULONGLONG WINAPI VerSetConditionMask(ULONGLONG, DWORD, BYTE);
HANDLE  WINAPI CreateThread(LPSECURITY_ATTRIBUTES, SIZE_T,
                            DWORD (WINAPI*)(LPVOID), LPVOID,
                            DWORD, DWORD*);
DWORD   WINAPI WaitForSingleObject(HANDLE, DWORD);
BOOL    WINAPI CloseHandle(HANDLE);
void    WINAPI Sleep(DWORD);
BOOL    WINAPI QueryPerformanceCounter(LARGE_INTEGER*);
BOOL    WINAPI QueryPerformanceFrequency(LARGE_INTEGER*);
BOOL    WINAPI CreatePipe(HANDLE*, HANDLE*, LPSECURITY_ATTRIBUTES, DWORD);
PVOID   WINAPI LocalFree(PVOID);
VOID    WINAPI ZeroMemory(PVOID, SIZE_T);
VOID    WINAPI CopyMemory(PVOID, LPCVOID, SIZE_T);
LONG    WINAPI InterlockedExchange(volatile LONG*, LONG);

/* inject.c / dllmain.c 用 */
BOOL    WINAPI CreateProcessA(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES,
                              LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID,
                              LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);
PVOID   WINAPI VirtualAllocEx(HANDLE, LPVOID, SIZE_T, DWORD, DWORD);
BOOL    WINAPI VirtualFreeEx(HANDLE, LPVOID, SIZE_T, DWORD);
BOOL    WINAPI WriteProcessMemory(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*);
HANDLE  WINAPI CreateRemoteThread(HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T,
                                  LPTHREAD_START_ROUTINE, LPVOID,
                                  DWORD, DWORD*);
BOOL    WINAPI GetExitCodeThread(HANDLE, DWORD*);
DWORD   WINAPI ResumeThread(HANDLE);
BOOL    WINAPI TerminateProcess(HANDLE, UINT);
BOOL    WINAPI DisableThreadLibraryCalls(HMODULE);
BOOL    WINAPI GetExitCodeProcess(HANDLE, DWORD*);

#endif /* WIN7BRIDGE_FAKE_WINDOWS_H */
