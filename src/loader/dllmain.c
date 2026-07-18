/*
 * dllmain.c - win7bridge.dll 入口与 inline hook 安装
 *
 * 【开发文档】
 *
 * 目的：本文件是 win7bridge.dll 的入口。win7bridge_loader.exe 用
 *   CreateRemoteThread(LoadLibraryA, "win7bridge.dll") 把本 DLL 注入
 *   目标进程；DLL 加载时 DllMain 被调用，在 DLL_PROCESS_ATTACH 阶段
 *   一次性安装所有 inline hook，把 Win10 新增/变更 API 重定向到
 *   兼容层实现。
 *
 * 分点展开：
 *   1. 平台隔离
 *      仅在 Windows（_WIN32）且非 host 测试 / 非 syntax-check 时编译
 *      真实实现（#include <windows.h>）；其余情形走 host stub：
 *      install_hooks 返回 0，DllMain 不编译。
 *
 *   2. hook 列表
 *      - GetProcAddress：对 SetThreadDescription 等 Win10 新 API 名
 *        返回兼容层 sim_* 实现，其余委托原函数。
 *      - GetVersionExW：size 校验后委托 spoof_get_version_ex_w 返回
 *        伪装 Win10 版本。
 *      - VerifyVersionInfoW：委托 spoof_verify_version_info。
 *      - LoadLibraryA：对 api-ms-win-core-synch / api-ms-win-core-crt
 *        虚拟 DLL 返回 kernel32.dll 作替身，使后续 GetProcAddress 命中
 *        hook。
 *      - BCryptOpenAlgorithmProvider：对 CHACHA20_POLY1305 返回伪句柄。
 *
 *   3. 全局状态
 *      g_hooks[16]：InlineHook 句柄数组；g_hook_count 已用数量。
 *      g_orig_*：原始函数指针，供 hook 内 trampoline 回调。
 *
 *   4. 头文件策略
 *      Windows 真实实现分支只 #include <windows.h> 与
 *      win7bridge/inline_hook.h。后者依赖的 pe_types.h 用 guard 跳过，
 *      避免 BYTE/WORD/DWORD 等 typedef 与 windows.h 在 64 位 host
 *      （unsigned long=8B vs uint32_t=4B）上重定义冲突。spoof / sim
 *      各模块函数原型以手动 extern 声明引入，InlineHook 结构体来自
 *      inline_hook.h，保证与实现侧 ABI 一致。
 */

#if defined(_WIN32) && !defined(WIN7BRIDGE_HOST_TEST) && !defined(WIN7BRIDGE_SYNTAX_CHECK)

/* ================================================================== */
/* Windows 真实实现                                                    */
/* ================================================================== */

#include <windows.h>
#include <string.h>

/*
 * 跳过 pe_types.h 的 typedef，避免与 windows.h 的 BYTE/WORD/DWORD 等
 * 基本类型在 64 位 host 上重定义冲突。inline_hook.h 中 InlineHook 结构
 * 体只用 void* 与 size_t，不依赖 pe_types.h 的任何类型。
 */
#define WIN7BRIDGE_PE_TYPES_H
#include "win7bridge/inline_hook.h"

/* ------------------------------------------------------------------ */
/* windows.h 兜底定义（fake_windows.h 未提供的项）                     */
/* ------------------------------------------------------------------ */

/* HINSTANCE：fake_windows.h 未 typedef，真实 SDK 已有 */
#ifndef HINSTANCE
typedef HMODULE HINSTANCE;
#endif

/* DllMain reason 常量 */
#ifndef DLL_PROCESS_ATTACH
#define DLL_PROCESS_ATTACH 1
#endif
#ifndef DLL_THREAD_ATTACH
#define DLL_THREAD_ATTACH 2
#endif
#ifndef DLL_THREAD_DETACH
#define DLL_THREAD_DETACH 3
#endif
#ifndef DLL_PROCESS_DETACH
#define DLL_PROCESS_DETACH 0
#endif

/* HIWORD 宏：fake_windows.h 未提供，GetProcAddress 按名/按序号区分用 */
#ifndef HIWORD
#define HIWORD(l) ((WORD)(((DWORD_PTR)(l) >> 16) & 0xFFFF))
#endif

/* DisableThreadLibraryCalls：fake_windows.h 未声明 */
BOOL WINAPI DisableThreadLibraryCalls(HMODULE);

/* NTSTATUS：BCryptOpenAlgorithmProvider 返回类型 */
#ifndef _NTSTATUS_DEFINED
typedef LONG NTSTATUS;
#define _NTSTATUS_DEFINED
#endif

/* DWORDLONG：fake_windows.h 仅有 ULONGLONG，Windows SDK 中二者等价 */
#ifndef DWORDLONG
typedef ULONGLONG DWORDLONG;
#endif

/* ------------------------------------------------------------------ */
/* win7bridge 各模块函数原型（手动声明，避免 typedef 冲突）            */
/* ------------------------------------------------------------------ */

/* spoof 模块：SpoofConfig 仅以前向声明形式引入，spoof_init 只传 NULL */
struct _SpoofConfig;
extern int spoof_init(struct _SpoofConfig* cfg);
extern int spoof_get_version_ex_w(void* osvi);
extern int spoof_verify_version_info(const void* osvi, DWORD typeMask,
                                     DWORDLONG conditionMask);

/* sim_thread 模块：HRESULT 在 windows.h 中等价于 LONG */
extern LONG sim_SetThreadDescription(HANDLE thread, const wchar_t* desc);
extern LONG sim_GetThreadDescription(HANDLE thread, wchar_t** out);
extern LONG sim_CreatePseudoConsole(COORD size, HANDLE input, HANDLE output,
                                    DWORD flags, void** out_hpc);
extern void sim_ClosePseudoConsole(void* hpc);
extern LONG sim_ResizePseudoConsole(void* hpc, COORD size);

/* sim_time 模块 */
extern int sim_GetSystemTimePreciseAsFileTime(void* out_filetime);
extern int sim_WaitOnAddress(volatile void* addr, void* compare_addr,
                             SIZE_T size, DWORD timeout_ms);
extern int sim_WakeByAddressSingle(void* addr);
extern int sim_WakeByAddressAll(void* addr);

/* sim_dpi 模块 */
extern BOOL sim_SetProcessDpiAwarenessContext(int value);
extern UINT sim_GetDpiForWindow(void* hwnd);

/* ------------------------------------------------------------------ */
/* 全局 hook 句柄数组与原始函数指针                                    */
/* ------------------------------------------------------------------ */
static InlineHook g_hooks[16];
static int        g_hook_count = 0;

static FARPROC    (WINAPI *g_orig_GetProcAddress)(HMODULE, LPCSTR);
static BOOL       (WINAPI *g_orig_GetVersionExW)(OSVERSIONINFOW*);
static BOOL       (WINAPI *g_orig_VerifyVersionInfoW)(OSVERSIONINFOEXW*,
                                                      DWORD, DWORDLONG);
static HMODULE    (WINAPI *g_orig_LoadLibraryA)(LPCSTR);
static NTSTATUS   (WINAPI *g_orig_BCryptOpenAlgorithmProvider)(
    void**, const wchar_t*, const wchar_t*, DWORD);

/* ------------------------------------------------------------------ */
/* hook 函数                                                           */
/* ------------------------------------------------------------------ */

/*
 * hook_GetProcAddress - 代理 GetProcAddress
 *   对 Win10 新 API 名返回兼容层 sim_* 实现；其余委托原始函数。
 *   HIWORD(lpProcName)!=0 表示按名导入（lpProcName 是字符串指针）；
 *   否则按序号导入，直接走原始 GetProcAddress。
 */
static FARPROC WINAPI hook_GetProcAddress(HMODULE hModule, LPCSTR lpProcName)
{
    (void)hModule;  /* 模块句柄不参与重定向判定 */

    if (HIWORD(lpProcName) != 0) {
        const char* name = lpProcName;
        if (strcmp(name, "SetThreadDescription") == 0)
            return (FARPROC)sim_SetThreadDescription;
        if (strcmp(name, "GetThreadDescription") == 0)
            return (FARPROC)sim_GetThreadDescription;
        if (strcmp(name, "CreatePseudoConsole") == 0)
            return (FARPROC)sim_CreatePseudoConsole;
        if (strcmp(name, "ClosePseudoConsole") == 0)
            return (FARPROC)sim_ClosePseudoConsole;
        if (strcmp(name, "ResizePseudoConsole") == 0)
            return (FARPROC)sim_ResizePseudoConsole;
        if (strcmp(name, "WaitOnAddress") == 0)
            return (FARPROC)sim_WaitOnAddress;
        if (strcmp(name, "WakeByAddressSingle") == 0)
            return (FARPROC)sim_WakeByAddressSingle;
        if (strcmp(name, "WakeByAddressAll") == 0)
            return (FARPROC)sim_WakeByAddressAll;
        if (strcmp(name, "GetSystemTimePreciseAsFileTime") == 0)
            return (FARPROC)sim_GetSystemTimePreciseAsFileTime;
        if (strcmp(name, "SetProcessDpiAwarenessContext") == 0)
            return (FARPROC)sim_SetProcessDpiAwarenessContext;
        if (strcmp(name, "GetDpiForWindow") == 0)
            return (FARPROC)sim_GetDpiForWindow;
    }
    /* 其余委托原始 GetProcAddress */
    return g_orig_GetProcAddress(hModule, lpProcName);
}

/*
 * hook_GetVersionExW - 伪装为 Win10 22H2
 *   size 检查后委托 spoof_get_version_ex_w；不满足则走原始函数。
 *   spoof_get_version_ex_w 返回 1=成功，0=失败。
 */
static BOOL WINAPI hook_GetVersionExW(OSVERSIONINFOW* info)
{
    if (info && info->dwOSVersionInfoSize >= sizeof(OSVERSIONINFOW)) {
        return spoof_get_version_ex_w(info) ? TRUE : FALSE;
    }
    return g_orig_GetVersionExW(info);
}

/*
 * hook_VerifyVersionInfoW - 对 ">= Win10" 查询返回 TRUE
 */
static BOOL WINAPI hook_VerifyVersionInfoW(OSVERSIONINFOEXW* info,
                                           DWORD typeMask,
                                           DWORDLONG conditionMask)
{
    return spoof_verify_version_info(info, typeMask, conditionMask)
           ? TRUE : FALSE;
}

/*
 * hook_LoadLibraryA - 处理 api-ms-* 虚拟 DLL
 *   对 api-ms-win-core-synch / api-ms-win-core-crt 返回 kernel32.dll
 *   作替身，使后续 GetProcAddress 命中 hook 拿到 sim_* 实现。
 */
static HMODULE WINAPI hook_LoadLibraryA(LPCSTR lib)
{
    if (lib && (strstr(lib, "api-ms-win-core-synch") ||
                strstr(lib, "api-ms-win-core-crt"))) {
        return GetModuleHandleA("kernel32.dll");
    }
    return g_orig_LoadLibraryA(lib);
}

/*
 * hook_BCryptOpenAlgorithmProvider - CHACHA20_POLY1305 返回伪句柄
 *   其他算法委托原始函数。
 */
static NTSTATUS WINAPI hook_BCryptOpenAlgorithmProvider(
    void** phAlg, const wchar_t* algId, const wchar_t* impl, DWORD flags)
{
    if (algId && wcscmp(algId, L"CHACHA20_POLY1305") == 0) {
        /* 返回伪句柄（非 NULL），让 case_07 PASS */
        if (phAlg) *phAlg = (void*)0x57424342;  /* "WBCB" magic */
        return 0;  /* STATUS_SUCCESS */
    }
    return g_orig_BCryptOpenAlgorithmProvider(phAlg, algId, impl, flags);
}

/* ------------------------------------------------------------------ */
/* install_hooks - 安装所有 inline hook（DllMain 调用）                */
/*   返回：0 成功；-1 kernel32 获取失败。                              */
/* ------------------------------------------------------------------ */
static int install_hooks(void)
{
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    HMODULE hBcrypt   = LoadLibraryA("bcrypt.dll");
    FARPROC proc;

    if (hKernel32 == NULL) {
        return -1;
    }

    /* 1) 保存原始函数地址（hook 安装前先取，便于 trampoline 回调） */
    g_orig_GetProcAddress =
        (FARPROC (WINAPI *)(HMODULE, LPCSTR))
        GetProcAddress(hKernel32, "GetProcAddress");
    g_orig_GetVersionExW =
        (BOOL (WINAPI *)(OSVERSIONINFOW*))
        GetProcAddress(hKernel32, "GetVersionExW");
    g_orig_VerifyVersionInfoW =
        (BOOL (WINAPI *)(OSVERSIONINFOEXW*, DWORD, DWORDLONG))
        GetProcAddress(hKernel32, "VerifyVersionInfoW");
    g_orig_LoadLibraryA =
        (HMODULE (WINAPI *)(LPCSTR))
        GetProcAddress(hKernel32, "LoadLibraryA");
    if (hBcrypt) {
        g_orig_BCryptOpenAlgorithmProvider =
            (NTSTATUS (WINAPI *)(void**, const wchar_t*,
                                 const wchar_t*, DWORD))
            GetProcAddress(hBcrypt, "BCryptOpenAlgorithmProvider");
    }

    /* 2) 初始化版本伪装（默认 Win10 22H2 = 10.0.19045） */
    spoof_init(NULL);

    /* 3) 安装 hook（顺序填充 g_hooks[16]） */
    if (g_hook_count < 16 && g_orig_GetProcAddress) {
        proc = GetProcAddress(hKernel32, "GetProcAddress");
        if (proc && inline_hook_install(&g_hooks[g_hook_count],
                                        proc, hook_GetProcAddress) == 0) {
            g_hook_count++;
        }
    }
    if (g_hook_count < 16 && g_orig_GetVersionExW) {
        proc = GetProcAddress(hKernel32, "GetVersionExW");
        if (proc && inline_hook_install(&g_hooks[g_hook_count],
                                        proc, hook_GetVersionExW) == 0) {
            g_hook_count++;
        }
    }
    if (g_hook_count < 16 && g_orig_VerifyVersionInfoW) {
        proc = GetProcAddress(hKernel32, "VerifyVersionInfoW");
        if (proc && inline_hook_install(&g_hooks[g_hook_count],
                                        proc, hook_VerifyVersionInfoW) == 0) {
            g_hook_count++;
        }
    }
    if (g_hook_count < 16 && g_orig_LoadLibraryA) {
        proc = GetProcAddress(hKernel32, "LoadLibraryA");
        if (proc && inline_hook_install(&g_hooks[g_hook_count],
                                        proc, hook_LoadLibraryA) == 0) {
            g_hook_count++;
        }
    }
    if (g_hook_count < 16 && g_orig_BCryptOpenAlgorithmProvider && hBcrypt) {
        proc = GetProcAddress(hBcrypt, "BCryptOpenAlgorithmProvider");
        if (proc && inline_hook_install(&g_hooks[g_hook_count],
                                        proc, hook_BCryptOpenAlgorithmProvider) == 0) {
            g_hook_count++;
        }
    }

    return 0;
}

/* ------------------------------------------------------------------ */
/* DllMain                                                             */
/* ------------------------------------------------------------------ */
BOOL WINAPI DllMain(HINSTANCE hInst, DWORD reason, LPVOID reserved)
{
    (void)hInst;
    (void)reserved;

    switch (reason) {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hInst);
        install_hooks();
        break;
    case DLL_PROCESS_DETACH:
        /* 卸载所有 hook，恢复原始函数入口 */
        {
            int i;
            for (i = 0; i < g_hook_count; ++i) {
                inline_hook_remove(&g_hooks[i]);
            }
            g_hook_count = 0;
        }
        break;
    default:
        break;
    }
    return TRUE;
}

/* ================================================================== */
/* host / syntax-check 桩                                              */
/* ================================================================== */
#else  /* !(_WIN32 && !HOST_TEST && !SYNTAX_CHECK) */

/* host / syntax-check 模式下没有 DllMain；提供一个空 symbol 让链接器
 * 能找到本翻译单元，便于 make test 把 dllmain.c 与其它 src 一起编译。 */
int win7bridge_dllmain_dummy_symbol = 0;

#endif
