/*
 * inject.c - Win7Bridge Loader 进程注入实现
 *
 * 【开发文档】
 *
 * 目的：实现 inject.h 中的接口，把 win7bridge.dll 注入到目标进程。
 *
 * 分点展开：
 *   1. 平台隔离
 *      Windows 真实实现：CreateProcessA(CREATE_SUSPENDED) 启动目标，
 *      VirtualAllocEx 分配远程内存写 DLL 路径，
 *      CreateRemoteThread(kernel32!LoadLibraryA, dll_path) 加载 DLL，
 *      WaitForSingleObject 等远线程退出，GetExitCodeThread 取
 *      LoadLibraryA 返回值（HMODULE 或 NULL），ResumeThread 恢复主线程。
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

int inject_cleanup(InjectContext* ctx)
{
    if (ctx == NULL) return INJECT_OK;
    if (ctx->hThread)   { CloseHandle(ctx->hThread);   ctx->hThread   = NULL; }
    if (ctx->hProcess)  { CloseHandle(ctx->hProcess);  ctx->hProcess  = NULL; }
    ctx->pid = 0;
    return INJECT_OK;
}

int inject_launch(InjectContext* ctx)
{
    STARTUPINFOA        si;
    PROCESS_INFORMATION pi;
    char                cmdline[1024];
    size_t              pos;
    HMODULE             hKernel32;
    FARPROC             pLoadLibrary;
    void*               remote_mem;
    size_t              dll_len;
    HANDLE              hRemoteThread;
    DWORD               exit_code;
    DWORD               wait_ret;

    if (ctx == NULL || ctx->exe_path == NULL || ctx->dll_path == NULL) {
        return INJECT_ERR_INVALID_ARG;
    }

    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    memset(&pi, 0, sizeof(pi));

    /* 构造命令行："<exe_path>" <args> */
    pos = 0;
    if (strlen(ctx->exe_path) >= sizeof(cmdline) - 4) {
        return INJECT_ERR_INVALID_ARG;
    }
    cmdline[pos++] = '"';
    _copy_string(cmdline + pos, sizeof(cmdline) - pos - 1, ctx->exe_path);
    pos += strlen(cmdline + pos);
    if (pos < sizeof(cmdline) - 2) {
        cmdline[pos++] = '"';
        if (ctx->args && ctx->args[0]) {
            cmdline[pos++] = ' ';
            _copy_string(cmdline + pos, sizeof(cmdline) - pos - 1, ctx->args);
            pos += strlen(cmdline + pos);
        }
    }
    cmdline[pos] = '\0';

    if (!CreateProcessA(NULL, cmdline, NULL, NULL, FALSE,
                       CREATE_SUSPENDED, NULL,
                       ctx->work_dir ? ctx->work_dir : NULL,
                       &si, &pi)) {
        return INJECT_ERR_CREATE_PROCESS;
    }
    ctx->hProcess = pi.hProcess;
    ctx->hThread  = pi.hThread;
    ctx->pid      = pi.dwProcessId;

    /* 取 LoadLibraryA 地址 */
    hKernel32 = GetModuleHandleA("kernel32.dll");
    if (hKernel32 == NULL) {
        inject_cleanup(ctx);
        return INJECT_ERR_NO_LOADLIB;
    }
    pLoadLibrary = GetProcAddress(hKernel32, "LoadLibraryA");
    if (pLoadLibrary == NULL) {
        inject_cleanup(ctx);
        return INJECT_ERR_NO_LOADLIB;
    }

    /* 在目标进程分配内存写 DLL 路径 */
    dll_len = strlen(ctx->dll_path) + 1;
    remote_mem = VirtualAllocEx(ctx->hProcess, NULL, dll_len,
                                MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (remote_mem == NULL) {
        inject_cleanup(ctx);
        return INJECT_ERR_ALLOC;
    }

    if (!WriteProcessMemory(ctx->hProcess, remote_mem,
                            ctx->dll_path, dll_len, NULL)) {
        VirtualFreeEx(ctx->hProcess, remote_mem, 0, MEM_RELEASE);
        inject_cleanup(ctx);
        return INJECT_ERR_WRITE;
    }

    /* 远程线程调用 LoadLibraryA(remote_mem) */
    hRemoteThread = CreateRemoteThread(
        ctx->hProcess, NULL, 0,
        (LPTHREAD_START_ROUTINE)pLoadLibrary,
        remote_mem, 0, NULL);
    if (hRemoteThread == NULL) {
        VirtualFreeEx(ctx->hProcess, remote_mem, 0, MEM_RELEASE);
        inject_cleanup(ctx);
        return INJECT_ERR_REMOTE_THREAD;
    }

    /* 等待远线程退出（10 秒） */
    wait_ret = WaitForSingleObject(hRemoteThread, 10000);
    if (wait_ret != WAIT_OBJECT_0) {
        TerminateProcess(ctx->hProcess, 1);
        CloseHandle(hRemoteThread);
        VirtualFreeEx(ctx->hProcess, remote_mem, 0, MEM_RELEASE);
        inject_cleanup(ctx);
        return INJECT_ERR_TIMEOUT;
    }

    /* 取 LoadLibraryA 返回值：非 0 表示加载成功 */
    if (!GetExitCodeThread(hRemoteThread, &exit_code)) {
        exit_code = 0;
    }
    CloseHandle(hRemoteThread);
    VirtualFreeEx(ctx->hProcess, remote_mem, 0, MEM_RELEASE);

    if (exit_code == 0) {
        TerminateProcess(ctx->hProcess, 1);
        inject_cleanup(ctx);
        return INJECT_ERR_BAD_EXIT;
    }

    /* 恢复主线程 */
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
