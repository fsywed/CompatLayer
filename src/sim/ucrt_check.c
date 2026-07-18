/*
 * ucrt_check.c - Win7Bridge UCRT 前置检测实现
 *
 * 对应 docs/api-diff.md §2.8：检测 ucrtbase.dll / vcruntime140.dll /
 * msvcp140.dll 是否存在，缺失则提示安装 KB2999226 与 VCRedist 2015-2022。
 *
 * host：用 access() 检查模拟路径（/tmp/ucrtbase.dll 等）。
 * Windows：用 GetSystemDirectory + GetFileAttributes 检查系统目录。
 */
#include "win7bridge/ucrt_check.h"
#include "win7bridge/pe_types.h"   /* DWORD, HANDLE */

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#ifndef _WIN7BRIDGE_UINT_DEFINED
typedef uint32_t UINT;
#define _WIN7BRIDGE_UINT_DEFINED
#endif

#ifdef _WIN32
/* Windows：系统目录 + 文件属性检测                                     */
extern UINT  GetSystemDirectoryA(char* buf, UINT size);
extern DWORD GetFileAttributesA(const char* path);
#define SIM_INVALID_FILE_ATTRIBUTES ((DWORD)0xFFFFFFFF)
#else
/* host：用 access() 检测模拟路径                                       */
#include <unistd.h>
#endif

/* ------------------------------------------------------------------ */
/* 内部：单个 DLL 是否存在                                             */
/* ------------------------------------------------------------------ */
static int sim_dll_exists(const char* path)
{
#ifdef _WIN32
    DWORD attr = GetFileAttributesA(path);
    return attr != SIM_INVALID_FILE_ATTRIBUTES;
#else
    return access(path, F_OK) == 0;
#endif
}

/* ------------------------------------------------------------------ */
/* ucrt_check                                                          */
/* ------------------------------------------------------------------ */
int ucrt_check(UcrtStatus* out)
{
    if (out == NULL) {
        return 1;
    }

#ifdef _WIN32
    {
        char sysdir[260];
        char path[280];
        UINT len = GetSystemDirectoryA(sysdir, (UINT)sizeof(sysdir));
        if (len == 0 || len >= (UINT)sizeof(sysdir)) {
            *out = UCRT_MISSING_UCRTBASE;
            return 0;
        }
        /* 拼接系统目录 + 文件名，逐个检测                              */
#define SIM_CHECK_DLL(name, status)                                     \
        do {                                                            \
            strcpy(path, sysdir);                                       \
            strcat(path, name);                                         \
            if (!sim_dll_exists(path)) { *out = (status); return 0; }   \
        } while (0)

        SIM_CHECK_DLL("\\ucrtbase.dll",     UCRT_MISSING_UCRTBASE);
        SIM_CHECK_DLL("\\vcruntime140.dll", UCRT_MISSING_VCRUNTIME);
        SIM_CHECK_DLL("\\msvcp140.dll",     UCRT_MISSING_MSVCPP);
#undef SIM_CHECK_DLL
        *out = UCRT_OK;
        return 0;
    }
#else
    /* host：检查 /tmp 下的模拟路径（沙箱中通常不存在，返回缺失状态）   */
    if (!sim_dll_exists("/tmp/ucrtbase.dll")) {
        *out = UCRT_MISSING_UCRTBASE;
        return 0;
    }
    if (!sim_dll_exists("/tmp/vcruntime140.dll")) {
        *out = UCRT_MISSING_VCRUNTIME;
        return 0;
    }
    if (!sim_dll_exists("/tmp/msvcp140.dll")) {
        *out = UCRT_MISSING_MSVCPP;
        return 0;
    }
    *out = UCRT_OK;
    return 0;
#endif
}

/* ------------------------------------------------------------------ */
/* ucrt_status_message                                                 */
/* ------------------------------------------------------------------ */
const char* ucrt_status_message(UcrtStatus s)
{
    switch (s) {
        case UCRT_OK:
            return "UCRT 运行时已就绪";
        case UCRT_MISSING_UCRTBASE:
            return "缺少 KB2999226 (UCRT)，请安装";
        case UCRT_MISSING_VCRUNTIME:
            return "缺少 vcruntime140.dll，请安装 VCRedist 2015-2022";
        case UCRT_MISSING_MSVCPP:
            return "缺少 msvcp140.dll，请安装 VCRedist 2015-2022";
        default:
            return "未知 UCRT 检测状态";
    }
}
