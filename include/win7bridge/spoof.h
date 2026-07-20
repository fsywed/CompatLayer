/*
 * spoof.h - Win7Bridge L4 版本伪装层接口
 *
 * 目的：Win10 程序自检"系统版本 >= Win10"在 Win7 上会失败退出。本层
 * hook GetVersion / GetVersionEx / RtlGetVersion / RtlGetNtVersionNumbers
 * / VerifyVersionInfo，统一返回伪装的 Win10 版本号，使 IsWindows10OrGreater
 * 等 helper 返回 TRUE。
 *
 * 不依赖 <windows.h>。Windows 基本类型来自 win7bridge/pe_types.h；
 * OSVERSIONINFOEXW 在本头中自定义。可在原生 gcc 下做 host 测试。
 *
 * 参考 docs/api-diff.md §2.6（版本查询 API 行为变化）。
 */
#ifndef WIN7BRIDGE_SPOOF_H
#define WIN7BRIDGE_SPOOF_H

#include <stdint.h>
#include <stddef.h>            /* wchar_t */
#include "win7bridge/pe_types.h"   /* BYTE / WORD / DWORD */

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------ */
/* 伪装目标版本常量：Windows 10 22H2 (10.0.19045)                      */
/* ------------------------------------------------------------------ */
#define SPOOF_MAJOR  10
#define SPOOF_MINOR  0
#define SPOOF_BUILD  19045

/* 64 位条件掩码类型（对标 Windows SDK 的 DWORDLONG）                 */
#ifndef _WIN7BRIDGE_DWORDLONG_DEFINED
typedef uint64_t DWORDLONG;
#define _WIN7BRIDGE_DWORDLONG_DEFINED
#endif

/* ------------------------------------------------------------------ */
/* OSVERSIONINFOEXW：GetVersionExW / VerifyVersionInfo 使用的版本信息  */
/* 结构体。                                                            */
/* Win7 真机：由 <winnt.h> 提供，跳过自定义                            */
/* host/syntax-check：用下面的自定义类型                                */
/* ------------------------------------------------------------------ */
#if defined(_WIN32) && !defined(WIN7BRIDGE_HOST_TEST) && !defined(WIN7BRIDGE_SYNTAX_CHECK)
/* Win7 真机：OSVERSIONINFOEXW 已由 windows.h 提供 */
#else
typedef struct _OSVERSIONINFOEXW {
    DWORD    dwOSVersionInfoSize;
    DWORD    dwMajorVersion;
    DWORD    dwMinorVersion;
    DWORD    dwBuildNumber;
    DWORD    dwPlatformId;
    wchar_t  szCSDVersion[128];   /* Service Pack 字符串（NUL 结尾） */
    WORD     wServicePackMajor;
    WORD     wServicePackMinor;
    WORD     wSuiteMask;
    BYTE     wProductType;
    BYTE     wReserved;
} OSVERSIONINFOEXW;
#endif

/* 版本伪装运行时配置                                                   */
typedef struct _SpoofConfig {
    int   enabled;    /* 是否启用伪装（0=禁用，非 0=启用）            */
    WORD  major;      /* 伪装主版本号                                 */
    WORD  minor;      /* 伪装次版本号                                 */
    DWORD build;      /* 伪装构建号                                   */
} SpoofConfig;

/* ------------------------------------------------------------------ */
/* VerifyVersionInfo 的 VER_* 维度常量（与 Windows SDK 取值一致）       */
/* 仅在未被 <winnt.h> 定义时才定义，避免 Win7 真机重定义警告             */
/* ------------------------------------------------------------------ */
#ifndef VER_MINORVERSION
#define VER_MINORVERSION        0x00000001
#endif
#ifndef VER_MAJORVERSION
#define VER_MAJORVERSION        0x00000002
#endif
#ifndef VER_BUILDNUMBER
#define VER_BUILDNUMBER         0x00000004
#endif
#ifndef VER_PLATFORMID
#define VER_PLATFORMID          0x00000008
#endif
#ifndef VER_SERVICEPACKMINOR
#define VER_SERVICEPACKMINOR    0x00000010
#endif
#ifndef VER_SERVICEPACKMAJOR
#define VER_SERVICEPACKMAJOR    0x00000020
#endif
#ifndef VER_SUITENAME
#define VER_SUITENAME           0x00000040
#endif
#ifndef VER_PRODUCT_TYPE
#define VER_PRODUCT_TYPE        0x00000080
#endif

/* conditionMask 中每 3 位一组的比较算子                              */
#ifndef VER_EQUAL
#define VER_EQUAL               1
#endif
#ifndef VER_GREATER
#define VER_GREATER             2
#endif
#ifndef VER_GREATER_EQUAL
#define VER_GREATER_EQUAL       3
#endif
#ifndef VER_LESS
#define VER_LESS                4
#endif
#ifndef VER_LESS_EQUAL
#define VER_LESS_EQUAL          5
#endif
#ifndef VER_AND
#define VER_AND                 6   /* 仅 VER_SUITENAME 使用          */
#endif

/* dwPlatformId 取值                                                   */
#ifndef VER_PLATFORM_WIN32_NT
#define VER_PLATFORM_WIN32_NT   2
#endif

/* wProductType 取值                                                   */
#ifndef VER_NT_WORKSTATION
#define VER_NT_WORKSTATION      1
#endif

/* ------------------------------------------------------------------ */
/* 接口函数                                                            */
/* ------------------------------------------------------------------ */

/*
 * spoof_init - 初始化版本伪装配置
 *   cfg 为 NULL 时使用默认 Win10 22H2 (10.0.19045)。
 *   cfg 非空但 enabled==0 时也回退为默认值。
 * 返回：1 成功。
 */
int spoof_init(SpoofConfig* cfg);

/*
 * spoof_get_version - 取得伪装版本三元组
 *   任一输出指针为 NULL 则跳过该字段。
 * 返回：1 成功。
 */
int spoof_get_version(WORD* major, WORD* minor, DWORD* build);

/*
 * spoof_get_version_ex_w - 模拟 GetVersionExW
 *   osvi 指向调用方分配的 OSVERSIONINFOEXW，填充伪装 Win10 版本。
 * 返回：1 成功；0 出错（osvi 为空）。
 */
int spoof_get_version_ex_w(void* osvi);

/*
 * spoof_get_version - 模拟 GetVersion（已废弃 API）
 *   返回值布局（与 Windows SDK 一致）：
 *     - 低 16 位 = major
 *     - 接下来 8 位 = minor
 *     - 高 16 位 = build（Win7 上 build 被 GetVersion 截断为 0，
 *       但 Win8+ 起 manifest 加 supportedOS 后会返回真实 build；
 *       伪装为 Win10 时返回 build 19045）
 *   内部用 g_cfg 计算，host 测试可调用。
 */
DWORD spoof_get_version_legacy(void);

/*
 * spoof_rtl_get_version - 模拟 RtlGetVersion（ntdll）
 *   osvi 指向调用方分配的 OSVERSIONINFOEXW，填充伪装 Win10 版本。
 *   与 spoof_get_version_ex_w 的区别：RtlGetVersion 不检查
 *   dwOSVersionInfoSize 字段，且总是返回 STATUS_SUCCESS（0）。
 * 返回：0（STATUS_SUCCESS）；osvi 为空时仍返回 0 但不填充。
 */
int spoof_rtl_get_version(void* osvi);

/*
 * spoof_rtl_get_nt_version_numbers - 模拟 RtlGetNtVersionNumbers
 *   三个出参指针均可为 NULL（跳过）。
 *   pMajor/pMinor 填充主/次版本号；pBuild 填充构建号。
 *   注意：真实 RtlGetNtVersionNumbers 返回的 build 高位会设置
 *   0xF0000000 标志位（表示 nibble 15 是 build）；伪装时也模拟
 *   这个行为，便于反检测一致性。
 */
void spoof_rtl_get_nt_version_numbers(DWORD* pMajor, DWORD* pMinor,
                                       DWORD* pBuild);

/*
 * spoof_verify_version_info - 模拟 VerifyVersionInfoW
 *   osvi        ：调用方构造的请求条件（OSVERSIONINFOEXW）
 *   typeMask    ：VER_* 维度掩码，指示要校验哪些字段
 *   conditionMask：VerSetConditionMask 构造的 64 位条件掩码，每 3 位
 *                  一组（组索引 = 对应 VER_* 常量的 bit 位），值为
 *                  VER_EQUAL/VER_GREATER/...
 *   逐项比较"伪装系统值"与"osvi 请求值"，全部满足返回 1（TRUE）。
 *   典型场景：请求"VER_GREATER_EQUAL Win10"在伪装 10.0.19045 下返回 1。
 * 返回：1 满足（TRUE）；0 不满足（FALSE）。
 */
int spoof_verify_version_info(const void* osvi, DWORD typeMask,
                              DWORDLONG conditionMask);

/*
 * spoof_install_hooks - 安装版本 API 的 inline hook
 *   声明桩：实际安装由 inline_hook 模块在 Windows 集成阶段接入
 *   （hook GetVersion/GetVersionEx/RtlGetVersion/RtlGetNtVersionNumbers
 *    /VerifyVersionInfo 到本文件实现）。host/语法检查下返回 0。
 * 返回：0 成功。
 */
int spoof_install_hooks(void);

#ifdef __cplusplus
}
#endif

#endif /* WIN7BRIDGE_SPOOF_H */
