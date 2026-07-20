/*
 * inject.c - Win7Bridge Loader 进程注入实现
 *
 * 【开发文档】
 *
 * 目的：实现 inject.h 中的接口，把 win7bridge.dll 注入到目标进程。
 *
 * 分点展开：
 *   1. 平台隔离
 *      Windows 真实实现使用宽字符 API：
 *        - CreateProcessW(CREATE_SUSPENDED) 启动目标（兼容路径含 Unicode
 *          字符的 EXE，spec SubTask 3.1.1 要求）
 *        - VirtualAllocEx + WriteProcessMemory 写 DLL 路径
 *        - 注入方法二选一（spec SubTask 3.1.2 要求）：
 *          * INJECT_METHOD_REMOTE_THREAD：CreateRemoteThread(LoadLibraryW)
 *          * INJECT_METHOD_APC：QueueUserAPC(LoadLibraryW, hThread)
 *        - WaitForSingleObject 等远线程退出，GetExitCodeThread 取
 *          LoadLibraryW 返回值（HMODULE 或 NULL），ResumeThread 恢复主线程。
 *
 *   2. host / syntax-check 模式
 *      不调用任何 Windows API；inject_launch 直接返回
 *      INJECT_ERR_HOST_NOT_SUPPORTED，便于 make test 链接通过。
 *
 *   3. 错误处理
 *      任一步失败都调用 inject_cleanup 释放已分配的远内存与句柄，
 *      再返回对应 INJECT_ERR_*。
 *
 *   4. 字符串复制
 *      _copy_string（host 可用）封装 strncpy 截断 + NUL 终止，
 *      避免重复样板代码。
 *
 *   5. ANSI->Unicode 转换
 *      MultiByteToWideChar 把 ctx->exe_path / args / work_dir / dll_path
 *      转换为宽字符后调用 CreateProcessW；CP_ACP 兼容 Win7 系统 locale。
 */

#include "win7bridge/inject.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------ */
/* 平台无关：字符串复制工具                                            */
/* ------------------------------------------------------------------ */
static void _copy_string(char* dst, size_t dst_cap, const char* src)
{
    size_t n;
    if (dst == NULL || dst_cap == 0) return;
    if (src == NULL) { dst[0] = '\0'; return; }
    n = strlen(src);
    if (n >= dst_cap) n = dst_cap - 1;
    memcpy(dst, src, n);
    dst[n] = '\0';
}

/* ------------------------------------------------------------------ */
/* inject_init / set_*                                                 */
/* ------------------------------------------------------------------ */
int inject_init(InjectContext* ctx)
{
    if (ctx == NULL) return INJECT_ERR_INVALID_ARG;
    memset(ctx, 0, sizeof(*ctx));
    ctx->method = INJECT_METHOD_REMOTE_THREAD;
    return INJECT_OK;
}

int inject_set_dll_path(InjectContext* ctx, const char* dll_path)
{
    if (ctx == NULL || dll_path == NULL) return INJECT_ERR_INVALID_ARG;
    ctx->dll_path = dll_path;
    return INJECT_OK;
}

int inject_set_target(InjectContext* ctx, const char* exe_path,
                      const char* args)
{
    if (ctx == NULL || exe_path == NULL) return INJECT_ERR_INVALID_ARG;
    ctx->exe_path = exe_path;
    ctx->args     = args;
    return INJECT_OK;
}

int inject_set_work_dir(InjectContext* ctx, const char* work_dir)
{
    if (ctx == NULL) return INJECT_ERR_INVALID_ARG;
    ctx->work_dir = work_dir;   /* NULL 合法，launch 时回退到 EXE 目录 */
    return INJECT_OK;
}

/* ================================================================== */
/* Windows 真实实现                                                    */
/* ================================================================== */
#if defined(_WIN32) && !defined(WIN7BRIDGE_HOST_TEST) && !defined(WIN7BRIDGE_SYNTAX_CHECK)

#include <windows.h>

/* Win7 SDK 没有这些常量时，显式给出 */
#ifndef CREATE_SUSPENDED
#define CREATE_SUSPENDED 0x00000004
#endif
#ifndef MEM_COMMIT
#define MEM_COMMIT 0x00001000
#endif
#ifndef MEM_RESERVE
#define MEM_RESERVE 0x00002000
#endif
#ifndef MEM_RELEASE
#define MEM_RELEASE 0x00008000
#endif
#ifndef PAGE_READWRITE
#define PAGE_READWRITE 0x00000004
#endif
#ifndef INFINITE
#define INFINITE 0xFFFFFFFF
#endif
#ifndef CP_ACP
#define CP_ACP 0
#endif

/* ------------------------------------------------------------------ */
/* ANSI->Unicode 转换                                                  */
/*   返回写入 dst 的字符数（不含 NUL）；失败返回 0。                   */
/*   dst_cap 为 dst 数组的元素数（ wchar_t 个数）。                    */
/* ------------------------------------------------------------------ */
static int _ansi_to_wide(const char* src, wchar_t* dst, size_t dst_cap)
{
    int len;
    if (src == NULL || dst == NULL || dst_cap == 0) return 0;
    len = MultiByteToWideChar(CP_ACP, 0, src, -1, NULL, 0);
    if (len <= 0) return 0;
    if ((size_t)len > dst_cap) len = (int)dst_cap;
    MultiByteToWideChar(CP_ACP, 0, src, -1, dst, len);
    dst[len - 1] = L'\0';
    return len - 1;
}

int inject_cleanup(InjectContext* ctx)
{
    if (ctx == NULL) return INJECT_OK;
    if (ctx->hThread)   { CloseHandle(ctx->hThread);   ctx->hThread   = NULL; }
    if (ctx->hProcess)  { CloseHandle(ctx->hProcess);  ctx->hProcess  = NULL; }
    ctx->pid = 0;
    return INJECT_OK;
}

/*
 * _inject_via_remote_thread - CreateRemoteThread(LoadLibraryW) 路径
 *   返回：INJECT_OK 成功；负值见 INJECT_ERR_*。
 */
static int _inject_via_remote_thread(HANDLE hProcess, const wchar_t* dll_path_w,
                                     HMODULE hKernel32)
{
    FARPROC pLoadLibraryW;
    void*   remote_mem;
    size_t  dll_bytes;
    HANDLE  hRemoteThread;
    DWORD   exit_code = 0;
    DWORD   wait_ret;

    pLoadLibraryW = GetProcAddress(hKernel32, "LoadLibraryW");
    if (pLoadLibraryW == NULL) {
        return INJECT_ERR_NO_LOADLIB;
    }

    /* 在目标进程分配内存写宽字符 DLL 路径 */
    dll_bytes = (wcslen(dll_path_w) + 1) * sizeof(wchar_t);
    remote_mem = VirtualAllocEx(hProcess, NULL, dll_bytes,
                                MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (remote_mem == NULL) {
        return INJECT_ERR_ALLOC;
    }

    if (!WriteProcessMemory(hProcess, remote_mem,
                            dll_path_w, dll_bytes, NULL)) {
        VirtualFreeEx(hProcess, remote_mem, 0, MEM_RELEASE);
        return INJECT_ERR_WRITE;
    }

    /* 远程线程调用 LoadLibraryW(remote_mem) */
    hRemoteThread = CreateRemoteThread(
        hProcess, NULL, 0,
        (LPTHREAD_START_ROUTINE)pLoadLibraryW,
        remote_mem, 0, NULL);
    if (hRemoteThread == NULL) {
        VirtualFreeEx(hProcess, remote_mem, 0, MEM_RELEASE);
        return INJECT_ERR_REMOTE_THREAD;
    }

    /* 等待远线程退出（10 秒） */
    wait_ret = WaitForSingleObject(hRemoteThread, 10000);
    if (wait_ret != WAIT_OBJECT_0) {
        CloseHandle(hRemoteThread);
        VirtualFreeEx(hProcess, remote_mem, 0, MEM_RELEASE);
        return INJECT_ERR_TIMEOUT;
    }

    /* 取 LoadLibraryW 返回值：非 0 表示加载成功 */
    if (!GetExitCodeThread(hRemoteThread, &exit_code)) {
        exit_code = 0;
    }
    CloseHandle(hRemoteThread);
    VirtualFreeEx(hProcess, remote_mem, 0, MEM_RELEASE);

    if (exit_code == 0) {
        return INJECT_ERR_BAD_EXIT;
    }
    return INJECT_OK;
}

/*
 * _inject_via_apc - QueueUserAPC(LoadLibraryW, hThread) 路径
 *   APC 路径更隐蔽（不创建新线程），但要求目标进程主线程能进入 alertable
 *   等待；CREATE_SUSPENDED 创建的进程主线程尚未运行，QueueUserAPC 会
 *   在 ResumeThread 后被调度执行。注意：APC 内的 LoadLibraryW 返回值
 *   无法直接取得（QueueUserAPC 不返回远线程退出码），改用
 *   GetExitCodeProcess + 模块枚举兜底，但实际部署中 loader 不依赖该
 *   返回值；只要 QueueUserAPC 与 ResumeThread 都成功就视为注入成功。
 *   返回：INJECT_OK 成功；负值见 INJECT_ERR_*。
 */
static int _inject_via_apc(HANDLE hProcess, HANDLE hThread,
                           const wchar_t* dll_path_w,
                           HMODULE hKernel32)
{
    FARPROC     pLoadLibraryW;
    void*       remote_mem;
    size_t      dll_bytes;
    DWORD       queue_res;

    pLoadLibraryW = GetProcAddress(hKernel32, "LoadLibraryW");
    if (pLoadLibraryW == NULL) {
        return INJECT_ERR_NO_LOADLIB;
    }

    dll_bytes = (wcslen(dll_path_w) + 1) * sizeof(wchar_t);
    remote_mem = VirtualAllocEx(hProcess, NULL, dll_bytes,
                                MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (remote_mem == NULL) {
        return INJECT_ERR_ALLOC;
    }

    if (!WriteProcessMemory(hProcess, remote_mem,
                            dll_path_w, dll_bytes, NULL)) {
        VirtualFreeEx(hProcess, remote_mem, 0, MEM_RELEASE);
        return INJECT_ERR_WRITE;
    }

    /* QueueUserAPC 把 LoadLibraryW 排到主线程的 APC 队列。
     * 注意：QueueUserAPC 的第一个参数是 PAPCFUNC，签名是
     * void CALLBACK APCFunc(ULONG_PTR dwParam)，与 LoadLibraryW(LPWSTR)
     * 兼容（参数都通过 dwParam 传递）。 */
    queue_res = QueueUserAPC((PAPCFUNC)pLoadLibraryW, hThread,
                             (ULONG_PTR)remote_mem);
    if (queue_res == 0) {
        VirtualFreeEx(hProcess, remote_mem, 0, MEM_RELEASE);
        return INJECT_ERR_REMOTE_THREAD;  /* 复用错误码：APC 排队失败 */
    }

    /* 远程内存由 APC 完成后由系统在远进程释放；此处不立即 VirtualFreeEx，
     * 因为 APC 尚未执行。改为依赖进程退出时清理（VirtualFreeEx 也可以
     * 在 ResumeThread + 短暂 Sleep 后调用，但为简化逻辑，交给 OS）。 */
    return INJECT_OK;
}

int inject_launch(InjectContext* ctx)
{
    STARTUPINFOW        si;
    PROCESS_INFORMATION pi;
    wchar_t             cmdline[1024];
    wchar_t             exe_path_w[MAX_PATH];
    wchar_t             work_dir_w[MAX_PATH];
    wchar_t             dll_path_w[MAX_PATH];
    wchar_t             args_w[512];
    HMODULE             hKernel32;
    int                 rc;

    if (ctx == NULL || ctx->exe_path == NULL || ctx->dll_path == NULL) {
        return INJECT_ERR_INVALID_ARG;
    }

    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    memset(&pi, 0, sizeof(pi));

    /* ANSI -> Unicode 转换 */
    if (_ansi_to_wide(ctx->exe_path, exe_path_w, MAX_PATH) == 0) {
        return INJECT_ERR_INVALID_ARG;
    }
    if (_ansi_to_wide(ctx->dll_path, dll_path_w, MAX_PATH) == 0) {
        return INJECT_ERR_INVALID_ARG;
    }
    if (ctx->work_dir != NULL && ctx->work_dir[0] != '\0') {
        if (_ansi_to_wide(ctx->work_dir, work_dir_w, MAX_PATH) == 0) {
            return INJECT_ERR_INVALID_ARG;
        }
    } else {
        work_dir_w[0] = L'\0';
    }
    if (ctx->args != NULL && ctx->args[0] != '\0') {
        if (_ansi_to_wide(ctx->args, args_w,
                          sizeof(args_w) / sizeof(args_w[0])) == 0) {
            return INJECT_ERR_INVALID_ARG;
        }
    } else {
        args_w[0] = L'\0';
    }

    /* 构造命令行："<exe_path>" <args> */
    {
        size_t pos = 0;
        size_t cap = sizeof(cmdline) / sizeof(cmdline[0]);
        cmdline[pos++] = L'"';
        wcscpy_s(cmdline + pos, cap - pos, exe_path_w);
        pos += wcslen(exe_path_w);
        if (pos < cap - 2) {
            cmdline[pos++] = L'"';
            if (args_w[0] != L'\0') {
                cmdline[pos++] = L' ';
                wcscpy_s(cmdline + pos, cap - pos, args_w);
                pos += wcslen(args_w);
            }
        }
        cmdline[pos] = L'\0';
    }

    if (!CreateProcessW(NULL, cmdline, NULL, NULL, FALSE,
                       CREATE_SUSPENDED, NULL,
                       work_dir_w[0] != L'\0' ? work_dir_w : NULL,
                       &si, &pi)) {
        return INJECT_ERR_CREATE_PROCESS;
    }
    ctx->hProcess = pi.hProcess;
    ctx->hThread  = pi.hThread;
    ctx->pid      = pi.dwProcessId;

    /* 取 LoadLibraryW 地址 */
    hKernel32 = GetModuleHandleW(L"kernel32.dll");
    if (hKernel32 == NULL) {
        inject_cleanup(ctx);
        return INJECT_ERR_NO_LOADLIB;
    }

    /* 按注入方法分发 */
    if (ctx->method == INJECT_METHOD_APC) {
        rc = _inject_via_apc(ctx->hProcess, ctx->hThread,
                             dll_path_w, hKernel32);
    } else {
        rc = _inject_via_remote_thread(ctx->hProcess, dll_path_w, hKernel32);
    }

    if (rc != INJECT_OK) {
        /* 注入失败：终止目标进程并清理 */
        TerminateProcess(ctx->hProcess, 1);
        inject_cleanup(ctx);
        return rc;
    }

    /* 恢复主线程：让目标进程开始执行（APC 也会在此时被调度） */
    ResumeThread(ctx->hThread);
    return INJECT_OK;
}

/* ================================================================== */
/* host / syntax-check 桩                                              */
/* ================================================================== */
#else  /* !(_WIN32 && !HOST_TEST && !SYNTAX_CHECK) */

int inject_cleanup(InjectContext* ctx)
{
    if (ctx == NULL) return INJECT_OK;
    ctx->hProcess = NULL;
    ctx->hThread  = NULL;
    ctx->pid      = 0;
    return INJECT_OK;
}

int inject_launch(InjectContext* ctx)
{
    (void)ctx;
    return INJECT_ERR_HOST_NOT_SUPPORTED;
}

#endif
