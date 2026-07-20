/*
 * spoof.c - Win7Bridge L4 版本伪装层实现
 *
 * 实现 spoof.h 中的接口：
 *   - spoof_init / spoof_get_version：伪装配置与版本三元组
 *   - spoof_get_version_ex_w：填充 OSVERSIONINFOEXW 为伪装 Win10 22H2
 *   - spoof_verify_version_info：解析 conditionMask，逐 VER_* 维度比较
 *     "伪装系统值"与"osvi 请求值"，全部满足返回 TRUE
 *   - spoof_install_hooks：声明桩（实际 hook 由 inline_hook 集成阶段接入）
 *
 * 全部为纯 C 逻辑，无平台依赖，可在原生 gcc 下 host 测试。
 */
#include "win7bridge/spoof.h"

#include <string.h>

/* ------------------------------------------------------------------ */
/* 全局伪装配置（默认 Win10 22H2 = 10.0.19045）                        */
/* ------------------------------------------------------------------ */
static SpoofConfig g_cfg = {
    1,              /* enabled                       */
    SPOOF_MAJOR,    /* major = 10                    */
    SPOOF_MINOR,    /* minor = 0                     */
    SPOOF_BUILD     /* build = 19045                 */
};

/* ------------------------------------------------------------------ */
/* spoof_init                                                          */
/* ------------------------------------------------------------------ */
int spoof_init(SpoofConfig* cfg)
{
    if (cfg == NULL) {
        /* 无配置：使用默认 Win10 22H2 */
        g_cfg.enabled = 1;
        g_cfg.major   = SPOOF_MAJOR;
        g_cfg.minor   = SPOOF_MINOR;
        g_cfg.build   = SPOOF_BUILD;
        return 1;
    }

    g_cfg = *cfg;
    if (!g_cfg.enabled) {
        /* 显式禁用：仍回退为默认伪装值（避免暴露真实 Win7 版本） */
        g_cfg.enabled = 1;
        g_cfg.major   = SPOOF_MAJOR;
        g_cfg.minor   = SPOOF_MINOR;
        g_cfg.build   = SPOOF_BUILD;
    }
    return 1;
}

/* ------------------------------------------------------------------ */
/* spoof_get_version                                                   */
/* ------------------------------------------------------------------ */
int spoof_get_version(WORD* major, WORD* minor, DWORD* build)
{
    if (major) *major = g_cfg.major;
    if (minor) *minor = g_cfg.minor;
    if (build) *build = g_cfg.build;
    return 1;
}

/* ------------------------------------------------------------------ */
/* spoof_get_version_ex_w                                              */
/* ------------------------------------------------------------------ */
int spoof_get_version_ex_w(void* osvi)
{
    OSVERSIONINFOEXW* p = (OSVERSIONINFOEXW*)osvi;
    if (p == NULL) {
        return 0;
    }

    memset(p, 0, sizeof(*p));
    p->dwOSVersionInfoSize = (DWORD)sizeof(*p);
    p->dwMajorVersion      = g_cfg.major;
    p->dwMinorVersion      = g_cfg.minor;
    p->dwBuildNumber       = g_cfg.build;
    p->dwPlatformId        = VER_PLATFORM_WIN32_NT;
    /* szCSDVersion 已由 memset 清零；Win10 22H2 无 Service Pack */
    p->wServicePackMajor   = 0;
    p->wServicePackMinor   = 0;
    p->wSuiteMask          = 0;
    p->wProductType        = VER_NT_WORKSTATION;   /* 客户端工作站 */
    p->wReserved           = 0;
    return 1;
}

/* ------------------------------------------------------------------ */
/* spoof_get_version_legacy - 模拟已废弃的 GetVersion                  */
/*   返回值布局：                                                      */
/*     bits 0-15  : major version                                     */
/*     bits 16-23 : minor version                                     */
/*     bits 24-31 : 0（Win7 上）或 build 低 8 位（Win8+ manifest）    */
/*   伪装 Win10 时返回低 24 位 = (minor << 16) | major；              */
/*   高 8 位填 0（与 Win7 默认行为一致，避免目标程序走 build 分支）。   */
/* ------------------------------------------------------------------ */
DWORD spoof_get_version_legacy(void)
{
    DWORD v = 0;
    v |= (DWORD)(g_cfg.major & 0xFFFF);
    v |= ((DWORD)(g_cfg.minor & 0xFF)) << 16;
    /* 高 8 位保持 0：与 Win7 GetVersion 行为一致 */
    return v;
}

/* ------------------------------------------------------------------ */
/* spoof_rtl_get_version - 模拟 ntdll!RtlGetVersion                    */
/*   总是返回 STATUS_SUCCESS（0），不校验 dwOSVersionInfoSize。        */
/* ------------------------------------------------------------------ */
int spoof_rtl_get_version(void* osvi)
{
    OSVERSIONINFOEXW* p = (OSVERSIONINFOEXW*)osvi;
    if (p == NULL) {
        return 0;   /* STATUS_SUCCESS */
    }

    memset(p, 0, sizeof(*p));
    p->dwOSVersionInfoSize = (DWORD)sizeof(*p);
    p->dwMajorVersion      = g_cfg.major;
    p->dwMinorVersion      = g_cfg.minor;
    p->dwBuildNumber       = g_cfg.build;
    p->dwPlatformId        = VER_PLATFORM_WIN32_NT;
    p->wServicePackMajor   = 0;
    p->wServicePackMinor   = 0;
    p->wSuiteMask          = 0;
    p->wProductType        = VER_NT_WORKSTATION;
    p->wReserved           = 0;
    return 0;   /* STATUS_SUCCESS */
}

/* ------------------------------------------------------------------ */
/* spoof_rtl_get_nt_version_numbers - 模拟 RtlGetNtVersionNumbers      */
/*   build 高 4 位（nibble 15）置 0xF，与真实 ntdll 行为一致。         */
/* ------------------------------------------------------------------ */
void spoof_rtl_get_nt_version_numbers(DWORD* pMajor, DWORD* pMinor,
                                       DWORD* pBuild)
{
    if (pMajor) *pMajor = (DWORD)g_cfg.major;
    if (pMinor) *pMinor = (DWORD)g_cfg.minor;
    if (pBuild) {
        /* 高 4 位置 0xF0000000，与真实 RtlGetNtVersionNumbers 一致 */
        *pBuild = (g_cfg.build & 0x0FFFFFFFu) | 0xF0000000u;
    }
}

/* ------------------------------------------------------------------ */
/* spoof_verify_version_info 内部辅助                                  */
/* ------------------------------------------------------------------ */

/* 取 conditionMask 中第 bit_index 组（3 位）的比较算子 */
static int spoof_get_cond(DWORDLONG mask, int bit_index)
{
    return (int)((mask >> (bit_index * 3)) & (DWORDLONG)0x7);
}

/* 按 op 比较 system 与 requested 两个数值，返回比较结果（0/1） */
static int spoof_cmp_op(DWORD system, DWORD requested, int op)
{
    switch (op) {
        case VER_EQUAL:          return system == requested;
        case VER_GREATER:        return system >  requested;
        case VER_GREATER_EQUAL:  return system >= requested;
        case VER_LESS:           return system <  requested;
        case VER_LESS_EQUAL:     return system <= requested;
        default:                 return 0;   /* 未知算子视为不满足 */
    }
}

/* ------------------------------------------------------------------ */
/* spoof_verify_version_info                                           */
/* ------------------------------------------------------------------ */
int spoof_verify_version_info(const void* osvi, DWORD typeMask,
                              DWORDLONG conditionMask)
{
    const OSVERSIONINFOEXW* p = (const OSVERSIONINFOEXW*)osvi;
    int i;

    if (p == NULL) {
        return 0;
    }
    if (typeMask == 0) {
        /* 无校验维度，视为满足 */
        return 1;
    }

    /*
     * 版本号语义比较（与真实 VerifyVersionInfoW 一致）：
     * 当 typeMask 同时含 VER_MAJORVERSION 与 VER_MINORVERSION 时，作为
     * (major, minor) 整体比较：
     *   - 若 op 为 VER_GREATER_EQUAL 且 system_major > request_major，
     *     则 major 维度已通过，minor 维度自动满足（跳过）；
     *   - 否则按 op 逐维比较。
     * 这避免了"伪装 10.0 vs 请求 >= 6.1"被误判为 FALSE（因为 0 < 1）。
     *
     * 类似地，VER_MAJORVERSION | VER_MINORVERSION | VER_BUILDNUMBER
     * 三联比较时，build 也参与整体版本号比较。
     */
    if ((typeMask & (VER_MAJORVERSION | VER_MINORVERSION))
        == (VER_MAJORVERSION | VER_MINORVERSION)) {
        int op_maj = spoof_get_cond(conditionMask, 1); /* VER_MAJORVERSION bit1 */
        int op_min = spoof_get_cond(conditionMask, 0); /* VER_MINORVERSION bit0 */

        /* 主版本严格大于请求（GREATER 或 GREATER_EQUAL）：整体已通过，
         * minor 维度跳过 */
        if (op_maj == VER_GREATER || op_maj == VER_GREATER_EQUAL) {
            if (g_cfg.major > p->dwMajorVersion) {
                /* major 已严格大于，minor 自动满足，从 typeMask 摘除
                 * VER_MINORVERSION 位，继续校验其他维度 */
                typeMask &= ~VER_MINORVERSION;
            }
        }
        /* 若主版本严格小于请求，整体失败（无论 minor 如何） */
        if (g_cfg.major < p->dwMajorVersion &&
            (op_maj == VER_GREATER || op_maj == VER_GREATER_EQUAL ||
             op_maj == VER_EQUAL)) {
            return 0;
        }
        /* 主版本相等时：major 按 op 比较（GREATER_EQUAL 满足），
         * minor 按 op 比较，由后续通用循环处理 */
        (void)op_min;
    }

    /*
     * typeMask 的 bit i 对应 VER_* 常量（VER_MINORVERSION=bit0 ...）。
     * conditionMask 从低位起每 3 位一组，第 i 组是该维度的比较算子。
     * 逐项比较"伪装系统值"与"osvi 请求值"，任一不满足即返回 FALSE。
     */
    for (i = 0; i < 8; ++i) {
        DWORD bit = (DWORD)1 << i;
        int    op;
        int    ok = 0;

        if ((typeMask & bit) == 0) {
            continue;
        }
        op = spoof_get_cond(conditionMask, i);

        switch (bit) {
            case VER_MINORVERSION:
                /* 次版本：伪装值 vs 请求值 */
                ok = spoof_cmp_op(g_cfg.minor, p->dwMinorVersion, op);
                break;
            case VER_MAJORVERSION:
                /* 主版本：伪装值 vs 请求值（">=Win10" 走此分支） */
                ok = spoof_cmp_op(g_cfg.major, p->dwMajorVersion, op);
                break;
            case VER_BUILDNUMBER:
                /* 构建号：伪装值 vs 请求值 */
                ok = spoof_cmp_op(g_cfg.build, p->dwBuildNumber, op);
                break;
            case VER_PLATFORMID:
                /* 平台：伪装为 VER_PLATFORM_WIN32_NT */
                ok = spoof_cmp_op(VER_PLATFORM_WIN32_NT, p->dwPlatformId, op);
                break;
            case VER_SERVICEPACKMINOR:
                /* Win10 22H2 无 SP，伪装系统值为 0 */
                ok = spoof_cmp_op(0, p->wServicePackMinor, op);
                break;
            case VER_SERVICEPACKMAJOR:
                ok = spoof_cmp_op(0, p->wServicePackMajor, op);
                break;
            case VER_SUITENAME:
                /* 套件掩码：op 应为 VER_AND，判断 (sys & req) == req */
                ok = (op == VER_AND) &&
                     ((0 & p->wSuiteMask) == p->wSuiteMask);
                break;
            case VER_PRODUCT_TYPE:
                /* 产品类型：伪装为 VER_NT_WORKSTATION(1) */
                ok = spoof_cmp_op(VER_NT_WORKSTATION, p->wProductType, op);
                break;
            default:
                ok = 0;
                break;
        }

        if (!ok) {
            return 0;   /* 该维度不满足 -> FALSE */
        }
    }
    return 1;   /* 全部维度满足 -> TRUE */
}

/* ------------------------------------------------------------------ */
/* spoof_install_hooks                                                 */
/* ------------------------------------------------------------------ */
int spoof_install_hooks(void)
{
    /*
     * 声明桩：实际 inline hook 安装在 Windows 集成阶段，通过
     * inline_hook_install 把 GetVersion / GetVersionExW / RtlGetVersion
     * / RtlGetNtVersionNumbers / VerifyVersionInfoW 重定向到本文件的
     * spoof_get_version(_ex_w) / spoof_verify_version_info。
     * host / 语法检查下直接返回 0 表示成功桩。
     */
    return 0;
}
