/*
 * appinit.c - Win7Bridge SubTask 3.3 AppInit_DLLs 注册表注入实现
 *
 * 【开发文档】
 *
 * 目的：实现 appinit.h 中的接口，作为 Loader 注入与 PE patch 之外的
 *   兜底注入路径。
 *
 * 分点展开：
 *   1. Windows 实现
 *      用 RegOpenKeyExW(HKEY_LOCAL_MACHINE, ...) 打开
 *      "Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows"
 *      - install：RegSetValueExW(AppInit_DLLs, dll_path, REG_SZ)
 *      - uninstall：RegDeleteValueW(AppInit_DLLs)
 *      - status：RegQueryValueExW 判断值是否存在且非空
 *
 *   2. host 实现
 *      用全局变量 g_installed / g_dll_path 模拟状态，便于测试
 *      install/uninstall 配对。status 返回 g_installed。
 *
 *   3. 风险提示
 *      appinit_risk_notice 返回固定字符串，强调"会触发反调试检测/与
 *      沙箱冲突"，供 UI 显示。字符串内容与 docs/dev-guide.md §7
 *      安全约束保持一致。
 *
 *   4. 可逆性
 *      uninstall 必须能清除 install 写入的值，保证不留系统残留。
 *      host 实现中 uninstall 把 g_installed 置 0、g_dll_path 清空。
 */

#include "win7bridge/appinit.h"

#include <string.h>

/* ------------------------------------------------------------------ */
/* 风险提示常量                                                        */
/* ------------------------------------------------------------------ */
static const char g_risk_notice[] =
    "警告：AppInit_DLLs 注入会触发反调试检测，并与沙箱环境冲突。\n"
    "1. 某些反作弊/反调试软件会扫描 AppInit_DLLs 并判定为注入行为。\n"
    "2. 此设置为全局生效，会影响所有加载 user32.dll 的进程。\n"
    "3. 需要管理员权限写入 HKLM 系统键。\n"
    "建议优先使用 Loader 注入或 PE patch 模式；仅在必要时启用本路径。";

/* ------------------------------------------------------------------ */
/* host 模式全局状态                                                   */
/* ------------------------------------------------------------------ */
#if !defined(_WIN32) || defined(WIN7BRIDGE_HOST_TEST) || defined(WIN7BRIDGE_SYNTAX_CHECK)

static AppInitState g_appinit_state = APPINIT_STATE_UNINSTALLED;
static wchar_t      g_appinit_dll_path[1024];

AppInitResult appinit_install(const wchar_t* dll_path)
{
    size_t len;
    if (dll_path == NULL) {
        return APPINIT_ERR_INVALID_ARG;
    }
    len = wcslen(dll_path);
    if (len == 0 || len >= sizeof(g_appinit_dll_path) / sizeof(wchar_t)) {
        return APPINIT_ERR_INVALID_ARG;
    }
    wcscpy(g_appinit_dll_path, dll_path);
    g_appinit_state = APPINIT_STATE_INSTALLED;
    return APPINIT_OK;
}

AppInitResult appinit_uninstall(void)
{
    g_appinit_dll_path[0] = L'\0';
    g_appinit_state = APPINIT_STATE_UNINSTALLED;
    return APPINIT_OK;
}

AppInitState appinit_status(void)
{
    return g_appinit_state;
}

const char* appinit_risk_notice(void)
{
    return g_risk_notice;
}

#else  /* Windows 真实实现 */

#include <windows.h>

/* AppInit_DLLs 注册表路径与值名                                       */
static const wchar_t g_subkey[] =
    L"Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows";
static const wchar_t g_value_name[] = L"AppInit_DLLs";

/* host 测试用全局变量，与 host 分支保持一致；Windows 真实路径下用
 * 注册表作为权威源，g_appinit_state 仅作快速查询缓存。              */
static AppInitState g_appinit_state = APPINIT_STATE_UNINSTALLED;

AppInitResult appinit_install(const wchar_t* dll_path)
{
    HKEY  hKey = NULL;
    LONG  rc;
    DWORD len_bytes;

    if (dll_path == NULL) {
        return APPINIT_ERR_INVALID_ARG;
    }
    len_bytes = (DWORD)(wcslen(dll_path) + 1) * sizeof(wchar_t);
    if (len_bytes <= sizeof(wchar_t)) {
        return APPINIT_ERR_INVALID_ARG;
    }

    rc = RegOpenKeyExW(HKEY_LOCAL_MACHINE, g_subkey, 0,
                       KEY_SET_VALUE, &hKey);
    if (rc != ERROR_SUCCESS) {
        return APPINIT_ERR_REGISTRY;
    }
    rc = RegSetValueExW(hKey, g_value_name, 0, REG_SZ,
                        (const BYTE*)dll_path, len_bytes);
    RegCloseKey(hKey);
    if (rc != ERROR_SUCCESS) {
        return APPINIT_ERR_REGISTRY;
    }
    g_appinit_state = APPINIT_STATE_INSTALLED;
    return APPINIT_OK;
}

AppInitResult appinit_uninstall(void)
{
    HKEY  hKey = NULL;
    LONG  rc;

    rc = RegOpenKeyExW(HKEY_LOCAL_MACHINE, g_subkey, 0,
                       KEY_SET_VALUE, &hKey);
    if (rc != ERROR_SUCCESS) {
        return APPINIT_ERR_REGISTRY;
    }
    rc = RegDeleteValueW(hKey, g_value_name);
    RegCloseKey(hKey);
    /* RegDeleteValueW 在值不存在时返回 ERROR_FILE_NOT_FOUND，
     * 视为已清除（幂等） */
    if (rc != ERROR_SUCCESS && rc != ERROR_FILE_NOT_FOUND) {
        return APPINIT_ERR_REGISTRY;
    }
    g_appinit_state = APPINIT_STATE_UNINSTALLED;
    return APPINIT_OK;
}

AppInitState appinit_status(void)
{
    HKEY  hKey = NULL;
    LONG  rc;
    DWORD type = 0;
    DWORD len = 0;

    /* 查询注册表当前值是否非空，作为权威状态                       */
    rc = RegOpenKeyExW(HKEY_LOCAL_MACHINE, g_subkey, 0,
                       KEY_QUERY_VALUE, &hKey);
    if (rc != ERROR_SUCCESS) {
        return g_appinit_state;
    }
    rc = RegQueryValueExW(hKey, g_value_name, NULL, &type, NULL, &len);
    RegCloseKey(hKey);
    if (rc == ERROR_SUCCESS && len > sizeof(wchar_t)) {
        return APPINIT_STATE_INSTALLED;
    }
    return APPINIT_STATE_UNINSTALLED;
}

const char* appinit_risk_notice(void)
{
    return g_risk_notice;
}

#endif /* 平台隔离 */
