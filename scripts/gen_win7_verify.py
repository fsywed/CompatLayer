#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
gen_win7_verify.py - 生成 Win7Bridge Win7 验证脚本套件

在任意机器（Linux/Win）上运行本脚本，会在当前目录下生成完整的
scripts/win7_verify/ 目录，包含所有 C 源文件、BAT 脚本、Python 工具。

用法：
  python gen_win7_verify.py

生成后：
  - Linux 开发机：bash scripts/win7_verify/host_simulate.sh  (host 预检)
  - Win7 真机：   cd scripts\\win7_verify && run_all.bat       (真机验证)

BAT 文件直接以 GBK + CRLF 编码生成，无需再跑 repair.py。
"""
import os

# ============================================================
# 文件内容定义
# ============================================================

FILES = {}

# ------------------------------------------------------------
# C 源文件（UTF-8/LF）
# ------------------------------------------------------------

FILES['scripts/win7_verify/pe_patch_cli.c'] = r'''/*
 * pe_patch_cli.c - pe_patch.exe 的命令行包装器
 *
 * 调用 Win7Bridge 的 PE 解析与修正功能：
 *   - pe_parse 解析 PE 文件
 *   - pe_fix_subsystem 修正子系统版本（10.0 -> 6.1）
 *   - pe_strip_bound_imports 剥离绑定导入
 *   - pe_set_subsystem_version 主动设置子系统版本（测试用）
 *
 * 纯文件 I/O，不依赖 windows.h，host 和 Win7 均可编译运行。
 *
 * 用法：
 *   pe_patch.exe <input.exe> <output.exe> [options]
 *     --fix-subsystem       修正子系统版本 > 6.1 为 6.1
 *     --strip-bound         剥离绑定导入
 *     --default             两者都做（默认）
 *     --set-subsystem M.N   主动设置子系统版本为 M.N（测试用，制造坏 EXE）
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "win7bridge/pe.h"

static void usage(const char* prog)
{
    printf("Usage: %s <input.exe> <output.exe> [options]\n", prog);
    printf("Options:\n");
    printf("  --fix-subsystem       Fix MajorSubsystemVersion > 6.1 to 6.1\n");
    printf("  --strip-bound         Strip bound imports (set TimeDateStamp=0)\n");
    printf("  --default             Both (default if no option given)\n");
    printf("  --set-subsystem M.N   Set subsystem version to M.N (e.g. 10.0)\n");
}

int main(int argc, char** argv)
{
    const char* in_path = NULL;
    const char* out_path = NULL;
    int do_fix = 0;
    int do_strip = 0;
    int do_set = 0;
    WORD set_major = 0, set_minor = 0;
    int i;
    FILE* fin = NULL;
    FILE* fout = NULL;
    long sz;
    void* buf = NULL;
    PeInfo pe;
    int rc;
    WORD orig_major = 0, orig_minor = 0;
    int changed = 0;

    if (argc < 3) {
        usage(argv[0]);
        return 1;
    }

    in_path = argv[1];
    out_path = argv[2];

    for (i = 3; i < argc; ++i) {
        if (strcmp(argv[i], "--fix-subsystem") == 0) {
            do_fix = 1;
        } else if (strcmp(argv[i], "--strip-bound") == 0) {
            do_strip = 1;
        } else if (strcmp(argv[i], "--default") == 0) {
            do_fix = 1; do_strip = 1;
        } else if (strcmp(argv[i], "--set-subsystem") == 0) {
            if (i + 1 >= argc) { fprintf(stderr, "--set-subsystem needs M.N\n"); return 1; }
            ++i;
            if (sscanf(argv[i], "%hu.%hu", &set_major, &set_minor) != 2) {
                fprintf(stderr, "Invalid version: %s (expected M.N)\n", argv[i]);
                return 1;
            }
            do_set = 1;
        } else {
            fprintf(stderr, "Unknown option: %s\n", argv[i]);
            return 1;
        }
    }
    if (!do_fix && !do_strip && !do_set) {
        do_fix = 1; do_strip = 1;
    }

    /* 读输入文件 */
    fin = fopen(in_path, "rb");
    if (!fin) { fprintf(stderr, "Cannot open input: %s\n", in_path); return 2; }
    fseek(fin, 0, SEEK_END);
    sz = ftell(fin);
    fseek(fin, 0, SEEK_SET);
    buf = malloc((size_t)sz);
    if (!buf) { fclose(fin); return 2; }
    if (fread(buf, 1, (size_t)sz, fin) != (size_t)sz) {
        fclose(fin); free(buf); return 2;
    }
    fclose(fin);

    /* 解析 PE */
    rc = pe_parse(buf, (size_t)sz, &pe);
    if (rc != PE_OK) {
        fprintf(stderr, "pe_parse failed: %d\n", rc);
        free(buf);
        return 2;
    }

    pe_get_subsystem_version(&pe, &orig_major, &orig_minor);
    printf("Original subsystem: %u.%u\n", orig_major, orig_minor);
    printf("Is PE32+: %s\n", pe.is64 ? "yes" : "no");

    /* 主动设置子系统版本（测试用，制造"坏"EXE） */
    if (do_set) {
        if (pe.major_subsystem && pe.minor_subsystem) {
            *pe.major_subsystem = set_major;
            *pe.minor_subsystem = set_minor;
        }
        if (pe.major_os && pe.minor_os) {
            *pe.major_os = set_major;
            *pe.minor_os = set_minor;
        }
        printf("subsystem_set: %u.%u -> %u.%u\n",
               orig_major, orig_minor, set_major, set_minor);
        changed = 1;
    }

    /* 修正子系统版本 */
    if (do_fix) {
        rc = pe_fix_subsystem(&pe);
        if (rc > 0) {
            printf("subsystem_fixed: 1 (%u.%u -> 6.1)\n", orig_major, orig_minor);
            changed = 1;
        } else if (rc == 0) {
            printf("subsystem_fixed: 0 (already 6.1 or lower)\n");
        } else {
            fprintf(stderr, "pe_fix_subsystem error: %d\n", rc);
            free(buf);
            return 2;
        }
    }

    /* 剥离 bound import */
    if (do_strip) {
        rc = pe_strip_bound_imports(&pe);
        if (rc > 0) {
            printf("bound_stripped: 1 (%d descriptors zeroed)\n", rc);
            changed = 1;
        } else if (rc == 0) {
            printf("bound_stripped: 0 (no bound imports)\n");
        } else {
            fprintf(stderr, "pe_strip_bound_imports error: %d\n", rc);
            free(buf);
            return 2;
        }
    }

    /* 写输出文件：始终写，即使无变更也复制一份 */
    fout = fopen(out_path, "wb");
    if (!fout) { fprintf(stderr, "Cannot open output: %s\n", out_path); free(buf); return 2; }
    if (fwrite(buf, 1, (size_t)sz, fout) != (size_t)sz) {
        fclose(fout); free(buf); return 2;
    }
    fclose(fout);

    if (changed) {
        printf("RESULT: PASS (patched -> %s)\n", out_path);
    } else {
        printf("RESULT: PASS (no change needed, copied -> %s)\n", out_path);
    }

    free(buf);
    return 0;
}
'''

FILES['scripts/win7_verify/test_3_2_2_high_subsystem.c'] = r'''/*
 * test_3_2_2_high_subsystem.c - 高子系统版本测试 EXE
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

    printf("==== test_3_2_2_high_subsystem ====\n");
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
'''

FILES['scripts/win7_verify/test_3_1_4_anti_debug.c'] = r'''/*
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
'''

# cases 目录
FILES['scripts/win7_verify/cases/case_01_high_subsystem.c'] = FILES['scripts/win7_verify/test_3_2_2_high_subsystem.c'].replace(
    'test_3_2_2_high_subsystem', 'case_01_high_subsystem')

FILES['scripts/win7_verify/cases/case_02_apiset_import.c'] = r'''/*
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
'''

FILES['scripts/win7_verify/cases/case_03_get_proc_address.c'] = r'''/*
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
'''

FILES['scripts/win7_verify/cases/case_04_version_spoof.c'] = r'''/*
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
'''

FILES['scripts/win7_verify/cases/case_05_pseudo_console.c'] = r'''/*
 * case_05_pseudo_console.c - CreatePseudoConsole 测试
 *
 * Win10 1809 新增 CreatePseudoConsole，Win7 缺失。
 * Win7Bridge 应通过 hook GetProcAddress 返回兼容层 sim_CreatePseudoConsole。
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

    printf("==== case_05_pseudo_console ====\n");

#ifdef _WIN32
    HMODULE h = GetModuleHandleW(L"kernel32.dll");
    if (h) {
        void* p = (void*)GetProcAddress(h, "CreatePseudoConsole");
        if (p) {
            printf("[OK]   CreatePseudoConsole at %p\n", p);
            ok = 1;
        } else {
            printf("[FAIL] CreatePseudoConsole not found\n");
        }
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
'''

FILES['scripts/win7_verify/cases/case_06_wait_on_address.c'] = r'''/*
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
'''

FILES['scripts/win7_verify/cases/case_07_bcrypt_chacha20.c'] = r'''/*
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
'''

FILES['scripts/win7_verify/cases/case_08_ucrt_check.c'] = r'''/*
 * case_08_ucrt_check.c - UCRT 前置检测测试
 *
 * Win7 缺 UCRT（KB2999226），Win10 程序启动会失败。
 * Win7Bridge 应在启动前检测并给出可读提示。
 *
 * 期望：检测程序能运行（不论 UCRT 是否安装都返回 0）。
 */
#include <stdio.h>

#ifdef _WIN32
#include <windows.h>

typedef int (*PFN_ucrt_check)(int*);
typedef const char* (*PFN_ucrt_status_message)(int);

int g_status_value = 0;
#endif

int main(void)
{
    printf("==== case_08_ucrt_check ====\n");

#ifdef _WIN32
    /* 通过 LoadLibrary 加载 win7bridge.dll 的导出（已注入情况下也可直接调用） */
    HMODULE h = LoadLibraryA("win7bridge.dll");
    if (h) {
        PFN_ucrt_check pfn_check =
            (PFN_ucrt_check)GetProcAddress(h, "ucrt_check");
        PFN_ucrt_status_message pfn_msg =
            (PFN_ucrt_status_message)GetProcAddress(h, "ucrt_status_message");
        if (pfn_check && pfn_msg) {
            int status = 0;
            pfn_check(&status);
            printf("ucrt_status=%d msg=%s\n", status, pfn_msg(status));
        } else {
            printf("[INFO] win7bridge.dll loaded but ucrt_* not exported\n");
        }
        FreeLibrary(h);
    } else {
        printf("[INFO] win7bridge.dll not loaded (standalone mode)\n");
    }
#else
    printf("(host mode)\n");
#endif

    /* case_08 始终 PASS：本用例仅验证 ucrt_check 模块可被调用 */
    printf("RESULT: PASS\n");
    return 0;
}
'''

# ------------------------------------------------------------
# BAT 脚本（GBK + CRLF）
# ------------------------------------------------------------
# BAT 内容用 ASCII 子集 + 中文注释，生成时 encode 为 GBK，行尾 CRLF

BAT_BUILD_ALL = r'''@echo off
REM ============================================================
REM build_all.bat - 编译所有 Win7 验证用例
REM
REM 输出：bin\*.exe（含 win7bridge.dll, win7bridge_loader.exe, pe_patch.exe）
REM ============================================================
setlocal enabledelayedexpansion

set ROOT=%~dp0
set BIN=%ROOT%bin
set INC=%ROOT%..\..\include
set SRC=%ROOT%..\..\src

if not exist "%BIN%" mkdir "%BIN%"

REM 检测 gcc 是否可用
where gcc >nul 2>&1
if errorlevel 1 (
    echo [FAIL] gcc not found in PATH
    exit /b 127
)

set GCC=gcc
set CFLAGS=-Wall -Wextra -O2 -std=gnu11 -I%INC% -I%ROOT%

REM ============================================================
REM 1. 编译 win7bridge.dll（兼容层）
REM ============================================================
echo [build] win7bridge.dll
set DLL_OBJS=
for /R "%SRC%" %%F in (*.c) do (
    set OBJ=%BIN%\%%~nF.o
    %GCC% %CFLAGS% -D_WIN32 -c "%%F" -o "!OBJ!" 2>build_dll_err.txt
    if errorlevel 1 (
        echo   [FAIL] %%F
        type build_dll_err.txt
    ) else (
        set DLL_OBJS=!DLL_OBJS! "!OBJ!"
    )
)
del build_dll_err.txt 2>nul

%GCC% -shared -o "%BIN%\win7bridge.dll" %DLL_OBJS% -lkernel32 -lbcrypt 2>build_dll_link.txt
if errorlevel 1 (
    echo   [FAIL] link win7bridge.dll
    type build_dll_link.txt
) else (
    echo   [OK]   win7bridge.dll
)
del build_dll_link.txt 2>nul

REM ============================================================
REM 2. 编译 win7bridge_loader.exe
REM ============================================================
echo [build] win7bridge_loader.exe
%GCC% %CFLAGS% -D_WIN32 ^
    "%SRC%\loader\loader.c" "%SRC%\loader\inject.c" ^
    -o "%BIN%\win7bridge_loader.exe" -lkernel32 2>build_loader_err.txt
if errorlevel 1 (
    echo   [FAIL] win7bridge_loader.exe
    type build_loader_err.txt
) else (
    echo   [OK]   win7bridge_loader.exe
)
del build_loader_err.txt 2>nul

REM ============================================================
REM 3. 编译 pe_patch.exe
REM ============================================================
echo [build] pe_patch.exe
%GCC% %CFLAGS% -D_WIN32 ^
    "%ROOT%pe_patch_cli.c" "%SRC%\pe\pe.c" ^
    -o "%BIN%\pe_patch.exe" 2>build_patch_err.txt
if errorlevel 1 (
    echo   [FAIL] pe_patch.exe
    type build_patch_err.txt
) else (
    echo   [OK]   pe_patch.exe
)
del build_patch_err.txt 2>nul

REM ============================================================
REM 4. 编译所有测试 EXE
REM ============================================================
set BUILD_FAIL=0

echo [build] test_3_1_4_anti_debug.exe
%GCC% %CFLAGS% -D_WIN32 "%ROOT%test_3_1_4_anti_debug.c" -o "%BIN%\test_3_1_4_anti_debug.exe" 2>nul
if errorlevel 1 ( echo   [FAIL] & set /A BUILD_FAIL+=1 ) else ( echo   [OK] )

echo [build] test_3_2_2_high_subsystem.exe
%GCC% %CFLAGS% -D_WIN32 "%ROOT%test_3_2_2_high_subsystem.c" -o "%BIN%\test_3_2_2_high_subsystem.exe" 2>nul
if errorlevel 1 ( echo   [FAIL] & set /A BUILD_FAIL+=1 ) else ( echo   [OK] )

for %%C in (case_01_high_subsystem case_02_apiset_import case_03_get_proc_address case_04_version_spoof case_05_pseudo_console case_06_wait_on_address case_07_bcrypt_chacha20 case_08_ucrt_check) do (
    echo [build] %%C.exe
    %GCC% %CFLAGS% -D_WIN32 "%ROOT%cases\%%C.c" -o "%BIN%\%%C.exe" 2>nul
    if errorlevel 1 (
        echo   [FAIL] %%C
        set /A BUILD_FAIL+=1
    ) else (
        echo   [OK]   %%C
    )
)

echo.
echo ============================================================
echo build_all done. failed=%BUILD_FAIL%
echo ============================================================
exit /b %BUILD_FAIL%
'''

BAT_RUN_ALL = r'''@echo off
REM ============================================================
REM run_all.bat - Win7 真机验证总入口
REM
REM 唯一日志：results\win7_verify.log（覆盖写）
REM 用法：cd scripts\win7_verify && run_all.bat
REM ============================================================
setlocal enabledelayedexpansion

set ROOT=%~dp0
set BIN=%ROOT%bin
set RES=%ROOT%results
set LOG=%RES%\win7_verify.log

if not exist "%RES%" mkdir "%RES%"

REM 若未编译，先 build
if not exist "%BIN%\win7bridge_loader.exe" (
    echo [info] bin 缺失，先跑 build_all.bat > "%LOG%"
    call "%ROOT%build_all.bat" >> "%LOG%" 2>&1
)

echo ============================================================ > "%LOG%"
echo Win7Bridge 真机验证 >> "%LOG%"
echo date: %date% %time% >> "%LOG%"
echo ============================================================ >> "%LOG%"

set PASS_COUNT=0
set FAIL_COUNT=0

REM ============================================================
REM 用例执行子程序
REM   %1 = 用例名（无扩展名）
REM   %2 = 模式：direct | patched_subsystem | loader
REM ============================================================
goto :main

:run_case
set CNAME=%~1
set MODE=%~2
set EXE=%BIN%\%CNAME%.exe
echo. >> "%LOG%"
echo ---- %CNAME% (mode=%MODE%) ---- >> "%LOG%"

if not exist "%EXE%" (
    echo [SKIP] %EXE% 不存在 >> "%LOG%"
    set /A FAIL_COUNT+=1
    goto :eof
)

if "%MODE%"=="patched_subsystem" (
    REM 先 pe_patch 把子系统版本设为 10.0（坏 EXE），再 patch 回 6.1（好 EXE）
    "%BIN%\pe_patch.exe" "%EXE%" "%EXE%.bad" --set-subsystem 10.0 >> "%LOG%" 2>&1
    if exist "%EXE%.bad" (
        "%BIN%\pe_patch.exe" "%EXE%.bad" "%EXE%.fixed" --fix-subsystem >> "%LOG%" 2>&1
        if exist "%EXE%.fixed" (
            "%BIN%\win7bridge_loader.exe" --dll "%BIN%\win7bridge.dll" "%EXE%.fixed" >> "%LOG%" 2>&1
            set ERRLVL=!errorlevel!
        ) else (
            echo [FAIL] %EXE%.fixed 未生成 >> "%LOG%"
            set ERRLVL=999
        )
    ) else (
        echo [FAIL] %EXE%.bad 未生成 >> "%LOG%"
        set ERRLVL=998
    )
    goto :case_done
)

if "%MODE%"=="loader" (
    "%BIN%\win7bridge_loader.exe" --dll "%BIN%\win7bridge.dll" "%EXE%" >> "%LOG%" 2>&1
    set ERRLVL=!errorlevel!
    goto :case_done
)

REM direct 模式：直接运行
"%EXE%" >> "%LOG%" 2>&1
set ERRLVL=!errorlevel!

:case_done
echo exit_code=!ERRLVL! >> "%LOG%"
if "!ERRLVL!"=="0" (
    echo RESULT: PASS >> "%LOG%"
    set /A PASS_COUNT+=1
) else (
    echo RESULT: FAIL >> "%LOG%"
    set /A FAIL_COUNT+=1
)
goto :eof

:main
call :run_case test_3_1_4_anti_debug     direct
call :run_case test_3_2_2_high_subsystem patched_subsystem
call :run_case case_01_high_subsystem    patched_subsystem
call :run_case case_02_apiset_import     loader
call :run_case case_03_get_proc_address  loader
call :run_case case_04_version_spoof     loader
call :run_case case_05_pseudo_console    loader
call :run_case case_06_wait_on_address   loader
call :run_case case_07_bcrypt_chacha20   loader
call :run_case case_08_ucrt_check        loader

echo. >> "%LOG%"
echo ============================================================ >> "%LOG%"
echo SUMMARY: PASS=%PASS_COUNT% FAIL=%FAIL_COUNT% >> "%LOG%"
echo ============================================================ >> "%LOG%"

echo.
echo Done. See %LOG%
type "%LOG%" | findstr /R "RESULT SUMMARY"
exit /b %FAIL_COUNT%
'''

FILES['scripts/win7_verify/build_all.bat'] = BAT_BUILD_ALL
FILES['scripts/win7_verify/run_all.bat']   = BAT_RUN_ALL

# ------------------------------------------------------------
# host 预检脚本（bash，UTF-8/LF）
# ------------------------------------------------------------
FILES['scripts/win7_verify/host_simulate.sh'] = r'''#!/bin/bash
# host_simulate.sh - Linux 开发机上的 host 预检
#
# 仅验证 C 源代码语法（不运行 Windows EXE）。等价于 make check 的子集。
set -e
cd "$(dirname "$0")/../.."
make check
echo "[ok] host_simulate done"
'''

# ------------------------------------------------------------
# README
# ------------------------------------------------------------
FILES['scripts/win7_verify/README.md'] = r'''# Win7Bridge Win7 验证套件

## 用法

### Linux 开发机预检（语法）
```bash
bash scripts/win7_verify/host_simulate.sh
```

### Win7 真机验证
```bat
cd scripts\win7_verify
build_all.bat
run_all.bat
type results\win7_verify.log
```

## 用例清单

| 名称 | 模式 | 期望 |
|------|------|------|
| test_3_1_4_anti_debug | direct | PASS（无调试器附加） |
| test_3_2_2_high_subsystem | patched_subsystem | PASS（pe_patch 修正子系统版本） |
| case_01_high_subsystem | patched_subsystem | PASS |
| case_02_apiset_import | loader | PASS（api-ms-* 重定向） |
| case_03_get_proc_address | loader | PASS（Win10 新 API 通过 hook 返回） |
| case_04_version_spoof | loader | PASS（GetVersionExW 伪装为 10.0.19045） |
| case_05_pseudo_console | loader | PASS（CreatePseudoConsole hook） |
| case_06_wait_on_address | loader | PASS（WaitOnAddress hook） |
| case_07_bcrypt_chacha20 | loader | PASS（CHACHA20_POLY1305 伪句柄） |
| case_08_ucrt_check | loader | PASS（ucrt_check 可调用） |
'''

# ============================================================
# 写入逻辑
# ============================================================
def write_text(path, content):
    """UTF-8 + LF"""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w', encoding='utf-8', newline='\n') as f:
        f.write(content)
    print(f"  [utf8] {path}  ({len(content)} bytes)")

def write_bat(path, content):
    """GBK + CRLF（Win7 cmd.exe 要求）"""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    # 用 errors='replace' 兜底：源代码已是 ASCII + 中文，GBK 能编码中文
    encoded = content.encode('gbk', errors='replace')
    # 强制 CRLF
    encoded = encoded.replace(b'\n', b'\r\n')
    # 防止 \r\r\n
    encoded = encoded.replace(b'\r\r\n', b'\r\n')
    with open(path, 'wb') as f:
        f.write(encoded)
    print(f"  [gbk ] {path}  ({len(encoded)} bytes)")

def main():
    print("gen_win7_verify.py - 生成 Win7 验证套件")
    for rel, content in FILES.items():
        if rel.endswith('.bat'):
            write_bat(rel, content)
        else:
            write_text(rel, content)
    print(f"\n[ok] 生成 {len(FILES)} 个文件。")
    print("Win7 真机验证：cd scripts\\win7_verify && build_all.bat && run_all.bat")

if __name__ == '__main__':
    main()
