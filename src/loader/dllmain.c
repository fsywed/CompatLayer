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
 *      - BCryptOpenAlgorithmProvider/Close/GetProperty/GenerateKey/
 *        DestroyKey/Encrypt/Decrypt：对 CHACHA20_POLY1305 经
 *        cng_provider 适配层路由到 cng_chacha20 本地实现；HKDF 仅
 *        Open/Close。其余算法委托原函数。
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
 *      inline_hook.h，保证与实现侧 ABI 一致。cng_provider.h 是平台
 *      无关头（仅 uint8_t/size_t/uint32_t），可直接 include。
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
#include "win7bridge/cng_provider.h"

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
/* BCrypt AEAD 认证信息结构（Windows SDK bcrypt.h 中的定义，本地复制）  */
/*   用于 BCryptEncrypt/BCryptDecrypt 的 pPaddingInfo 参数。            */
/*   字段顺序与 Windows SDK 一致，编译器按目标架构自动对齐。            */
/* ------------------------------------------------------------------ */
#ifndef _BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO_DEFINED
#define _BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO_DEFINED
typedef struct _BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO {
    ULONG      cbSize;
    ULONG      dwInfoVersion;
    PUCHAR     pbNonce;
    ULONG      cbNonce;
    PUCHAR     pbAuthData;
    ULONG      cbAuthData;
    PUCHAR     pbTag;
    ULONG      cbTag;
    PUCHAR     pbMacContext;
    ULONG      cbMacContext;
    ULONG      cbAAD;
    ULONGLONG  cbData;
    ULONGLONG  cbDataOffset;
} BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO;
#endif /* _BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO_DEFINED */

/* NTSTATUS 常量（Windows SDK ntstatus.h 子集） */
#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS 0x00000000uL
#endif
#ifndef STATUS_INVALID_PARAMETER
#define STATUS_INVALID_PARAMETER 0xC000000DuL
#endif
#ifndef STATUS_NOT_FOUND
#define STATUS_NOT_FOUND 0xC0000225uL
#endif
#ifndef STATUS_AUTH_TAG_MISMATCH
#define STATUS_AUTH_TAG_MISMATCH 0xC000A002uL
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
static NTSTATUS   (WINAPI *g_orig_BCryptCloseAlgorithmProvider)(void*, ULONG);
static NTSTATUS   (WINAPI *g_orig_BCryptGetProperty)(
    void*, const wchar_t*, PUCHAR, ULONG, ULONG*, ULONG);
static NTSTATUS   (WINAPI *g_orig_BCryptGenerateSymmetricKey)(
    void*, void**, PUCHAR, ULONG, PUCHAR, ULONG, ULONG);
static NTSTATUS   (WINAPI *g_orig_BCryptDestroyKey)(void*);
static NTSTATUS   (WINAPI *g_orig_BCryptEncrypt)(
    void*, PUCHAR, ULONG, void*, PUCHAR, ULONG,
    PUCHAR, ULONG, ULONG*, ULONG);
static NTSTATUS   (WINAPI *g_orig_BCryptDecrypt)(
    void*, PUCHAR, ULONG, void*, PUCHAR, ULONG,
    PUCHAR, ULONG, ULONG*, ULONG);

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

/* ------------------------------------------------------------------ */
/* BCrypt provider hook 层                                             */
/*   对 CHACHA20_POLY1305 / HKDF 经 cng_provider 适配层路由到本地算法； */
/*   非本地句柄一律委托 g_orig_* 原函数。                              */
/* ------------------------------------------------------------------ */

/* 算法名 → 枚举映射 */
static w7b_alg_type bcrypt_map_alg(const wchar_t* algId)
{
    if (!algId) return W7B_ALG_NONE;
    if (wcscmp(algId, L"CHACHA20_POLY1305") == 0) return W7B_ALG_CHACHA20_POLY1305;
    if (wcscmp(algId, L"HKDF") == 0) return W7B_ALG_HKDF;
    return W7B_ALG_NONE;
}

/* 属性名 → 枚举映射 */
static w7b_prop_id bcrypt_map_prop(const wchar_t* prop)
{
    if (!prop) return W7B_PROP_NONE;
    if (wcscmp(prop, L"KeyLength") == 0)     return W7B_PROP_KEY_LENGTH;
    if (wcscmp(prop, L"AuthTagLength") == 0) return W7B_PROP_AUTH_TAG_LENGTH;
    if (wcscmp(prop, L"ObjectLength") == 0)  return W7B_PROP_OBJECT_LENGTH;
    if (wcscmp(prop, L"BlockLength") == 0)   return W7B_PROP_BLOCK_LENGTH;
    return W7B_PROP_NONE;
}

static NTSTATUS WINAPI hook_BCryptOpenAlgorithmProvider(
    void** phAlg, const wchar_t* algId, const wchar_t* impl, DWORD flags)
{
    w7b_alg_type alg = bcrypt_map_alg(algId);
    if (alg != W7B_ALG_NONE) {
        w7b_alg_handle* h = NULL;
        if (w7b_provider_open_alg(alg, &h) == 0) {
            if (phAlg) *phAlg = (void*)h;
            return STATUS_SUCCESS;
        }
        return STATUS_INVALID_PARAMETER;
    }
    return g_orig_BCryptOpenAlgorithmProvider(phAlg, algId, impl, flags);
}

static NTSTATUS WINAPI hook_BCryptCloseAlgorithmProvider(
    void* hAlg, ULONG flags)
{
    if (w7b_is_alg_handle(hAlg)) {
        w7b_provider_close_alg((w7b_alg_handle*)hAlg);
        return STATUS_SUCCESS;
    }
    return g_orig_BCryptCloseAlgorithmProvider(hAlg, flags);
}

static NTSTATUS WINAPI hook_BCryptGetProperty(
    void* hObject, const wchar_t* pszProperty,
    PUCHAR pbOutput, ULONG cbOutput, ULONG* pcbResult, ULONG flags)
{
    if (w7b_is_alg_handle(hObject)) {
        w7b_prop_id prop = bcrypt_map_prop(pszProperty);
        size_t result = 0;
        int rc;
        if (prop == W7B_PROP_NONE) return STATUS_NOT_FOUND;
        rc = w7b_provider_get_property((w7b_alg_handle*)hObject, prop,
                                        pbOutput, cbOutput, &result);
        if (rc != 0) return STATUS_INVALID_PARAMETER;
        if (pcbResult) *pcbResult = (ULONG)result;
        return STATUS_SUCCESS;
    }
    return g_orig_BCryptGetProperty(hObject, pszProperty,
                                    pbOutput, cbOutput, pcbResult, flags);
}

static NTSTATUS WINAPI hook_BCryptGenerateSymmetricKey(
    void* hAlgorithm, void** phKey,
    PUCHAR pbKeyObject, ULONG cbKeyObject,
    PUCHAR pbSecret, ULONG cbSecret, ULONG flags)
{
    if (w7b_is_alg_handle(hAlgorithm)) {
        w7b_key_handle* kh = NULL;
        int rc = w7b_provider_gen_key((w7b_alg_handle*)hAlgorithm, &kh,
                                       pbSecret, cbSecret);
        if (rc != 0) return STATUS_INVALID_PARAMETER;
        /* pbKeyObject/cbKeyObject 由 provider 自行管理，忽略调用方缓冲 */
        (void)pbKeyObject; (void)cbKeyObject;
        if (phKey) *phKey = (void*)kh;
        return STATUS_SUCCESS;
    }
    return g_orig_BCryptGenerateSymmetricKey(hAlgorithm, phKey,
        pbKeyObject, cbKeyObject, pbSecret, cbSecret, flags);
}

static NTSTATUS WINAPI hook_BCryptDestroyKey(void* hKey)
{
    if (w7b_is_key_handle(hKey)) {
        w7b_provider_destroy_key((w7b_key_handle*)hKey);
        return STATUS_SUCCESS;
    }
    return g_orig_BCryptDestroyKey(hKey);
}

static NTSTATUS WINAPI hook_BCryptEncrypt(
    void* hKey, PUCHAR pbInput, ULONG cbInput, void* pPaddingInfo,
    PUCHAR pbIV, ULONG cbIV,
    PUCHAR pbOutput, ULONG cbOutput, ULONG* pcbResult, ULONG flags)
{
    if (w7b_is_key_handle(hKey)) {
        BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO* auth = NULL;
        const uint8_t* nonce = NULL;
        size_t nonce_len = 0;
        const uint8_t* aad = NULL;
        size_t aad_len = 0;
        uint8_t* tag = NULL;
        size_t tag_len = 0;
        int rc;

        /* AEAD 模式：pPaddingInfo 指向 AUTH_INFO，nonce/AAD/tag 从中提取 */
        if (pPaddingInfo) {
            auth = (BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO*)pPaddingInfo;
            nonce = auth->pbNonce;
            nonce_len = auth->cbNonce;
            aad = auth->pbAuthData;
            aad_len = auth->cbAuthData;
            tag = auth->pbTag;
            tag_len = auth->cbTag;
        }
        /* pbIV/cbIV 对 AEAD 模式无意义（nonce 在 auth info 中） */
        (void)pbIV; (void)cbIV;

        rc = w7b_provider_encrypt((w7b_key_handle*)hKey,
                                   nonce, nonce_len,
                                   aad, aad_len,
                                   pbInput, cbInput,
                                   pbOutput, tag, tag_len);
        if (rc != 0) return STATUS_INVALID_PARAMETER;
        if (pcbResult) *pcbResult = cbInput;  /* 密文长度 == 明文长度 */
        return STATUS_SUCCESS;
    }
    return g_orig_BCryptEncrypt(hKey, pbInput, cbInput, pPaddingInfo,
        pbIV, cbIV, pbOutput, cbOutput, pcbResult, flags);
}

static NTSTATUS WINAPI hook_BCryptDecrypt(
    void* hKey, PUCHAR pbInput, ULONG cbInput, void* pPaddingInfo,
    PUCHAR pbIV, ULONG cbIV,
    PUCHAR pbOutput, ULONG cbOutput, ULONG* pcbResult, ULONG flags)
{
    if (w7b_is_key_handle(hKey)) {
        BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO* auth = NULL;
        const uint8_t* nonce = NULL;
        size_t nonce_len = 0;
        const uint8_t* aad = NULL;
        size_t aad_len = 0;
        const uint8_t* tag = NULL;
        size_t tag_len = 0;
        int rc;

        if (pPaddingInfo) {
            auth = (BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO*)pPaddingInfo;
            nonce = auth->pbNonce;
            nonce_len = auth->cbNonce;
            aad = auth->pbAuthData;
            aad_len = auth->cbAuthData;
            tag = auth->pbTag;
            tag_len = auth->cbTag;
        }
        (void)pbIV; (void)cbIV;

        rc = w7b_provider_decrypt((w7b_key_handle*)hKey,
                                   nonce, nonce_len,
                                   aad, aad_len,
                                   pbInput, cbInput,
                                   tag, tag_len,
                                   pbOutput);
        if (rc != 0) return STATUS_AUTH_TAG_MISMATCH;
        if (pcbResult) *pcbResult = cbInput;
        return STATUS_SUCCESS;
    }
    return g_orig_BCryptDecrypt(hKey, pbInput, cbInput, pPaddingInfo,
        pbIV, cbIV, pbOutput, cbOutput, pcbResult, flags);
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
        g_orig_BCryptCloseAlgorithmProvider =
            (NTSTATUS (WINAPI *)(void*, ULONG))
            GetProcAddress(hBcrypt, "BCryptCloseAlgorithmProvider");
        g_orig_BCryptGetProperty =
            (NTSTATUS (WINAPI *)(void*, const wchar_t*,
                                 PUCHAR, ULONG, ULONG*, ULONG))
            GetProcAddress(hBcrypt, "BCryptGetProperty");
        g_orig_BCryptGenerateSymmetricKey =
            (NTSTATUS (WINAPI *)(void*, void**, PUCHAR, ULONG,
                                 PUCHAR, ULONG, ULONG))
            GetProcAddress(hBcrypt, "BCryptGenerateSymmetricKey");
        g_orig_BCryptDestroyKey =
            (NTSTATUS (WINAPI *)(void*))
            GetProcAddress(hBcrypt, "BCryptDestroyKey");
        g_orig_BCryptEncrypt =
            (NTSTATUS (WINAPI *)(void*, PUCHAR, ULONG, void*,
                                 PUCHAR, ULONG, PUCHAR, ULONG,
                                 ULONG*, ULONG))
            GetProcAddress(hBcrypt, "BCryptEncrypt");
        g_orig_BCryptDecrypt =
            (NTSTATUS (WINAPI *)(void*, PUCHAR, ULONG, void*,
                                 PUCHAR, ULONG, PUCHAR, ULONG,
                                 ULONG*, ULONG))
            GetProcAddress(hBcrypt, "BCryptDecrypt");
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
    if (g_hook_count < 16 && g_orig_BCryptCloseAlgorithmProvider && hBcrypt) {
        proc = GetProcAddress(hBcrypt, "BCryptCloseAlgorithmProvider");
        if (proc && inline_hook_install(&g_hooks[g_hook_count],
                                        proc, hook_BCryptCloseAlgorithmProvider) == 0) {
            g_hook_count++;
        }
    }
    if (g_hook_count < 16 && g_orig_BCryptGetProperty && hBcrypt) {
        proc = GetProcAddress(hBcrypt, "BCryptGetProperty");
        if (proc && inline_hook_install(&g_hooks[g_hook_count],
                                        proc, hook_BCryptGetProperty) == 0) {
            g_hook_count++;
        }
    }
    if (g_hook_count < 16 && g_orig_BCryptGenerateSymmetricKey && hBcrypt) {
        proc = GetProcAddress(hBcrypt, "BCryptGenerateSymmetricKey");
        if (proc && inline_hook_install(&g_hooks[g_hook_count],
                                        proc, hook_BCryptGenerateSymmetricKey) == 0) {
            g_hook_count++;
        }
    }
    if (g_hook_count < 16 && g_orig_BCryptDestroyKey && hBcrypt) {
        proc = GetProcAddress(hBcrypt, "BCryptDestroyKey");
        if (proc && inline_hook_install(&g_hooks[g_hook_count],
                                        proc, hook_BCryptDestroyKey) == 0) {
            g_hook_count++;
        }
    }
    if (g_hook_count < 16 && g_orig_BCryptEncrypt && hBcrypt) {
        proc = GetProcAddress(hBcrypt, "BCryptEncrypt");
        if (proc && inline_hook_install(&g_hooks[g_hook_count],
                                        proc, hook_BCryptEncrypt) == 0) {
            g_hook_count++;
        }
    }
    if (g_hook_count < 16 && g_orig_BCryptDecrypt && hBcrypt) {
        proc = GetProcAddress(hBcrypt, "BCryptDecrypt");
        if (proc && inline_hook_install(&g_hooks[g_hook_count],
                                        proc, hook_BCryptDecrypt) == 0) {
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
