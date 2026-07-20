/*
 * appinit.h - Win7Bridge SubTask 3.3 AppInit_DLLs 注册表注入接口
 *
 * 【开发文档】
 *
 * 目的：作为 Loader 注入与 PE patch 之外的兜底注入路径，通过写
 *   HKLM\Software\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs
 *   让所有加载 user32.dll 的进程自动加载 win7bridge.dll。
 *
 * 风险（必须在 UI 显式标注）：
 *   1. 会触发反调试检测：某些反作弊/反调试软件会扫描 AppInit_DLLs
 *      并判定为注入行为。
 *   2. 与沙箱冲突：AppInit_DLLs 是全局设置，会影响所有 user32 进程，
 *      沙箱环境可能拒绝或导致不可预期的进程加载行为。
 *   3. 需要管理员权限：HKLM 是系统键，写入需要管理员权限。
 *
 * 接口约定：
 *   - appinit_install：写入 dll_path 到 AppInit_DLLs 值
 *   - appinit_uninstall：清空 AppInit_DLLs 值（保证可逆）
 *   - appinit_status：查询当前安装状态（host 测试用）
 *   - appinit_risk_notice：返回风险提示字符串，供 UI 显示
 *
 * 平台隔离：
 *   Windows 走真实 RegOpenKeyExW/RegSetValueExW/RegDeleteValueW；
 *   host 用全局变量模拟"已安装"状态，便于测试 install/uninstall 配对。
 */
#ifndef WIN7BRIDGE_APPINIT_H
#define WIN7BRIDGE_APPINIT_H

#include <stddef.h>
#include <wchar.h>   /* wchar_t */

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------ */
/* 状态码                                                              */
/* ------------------------------------------------------------------ */
typedef enum {
    APPINIT_OK              = 0,   /* 操作成功                          */
    APPINIT_ERR_INVALID_ARG = 1,   /* 入参非法                          */
    APPINIT_ERR_REGISTRY    = 2,   /* 注册表操作失败（仅 Windows）      */
    APPINIT_ERR_HOST_NOT_SUPPORTED = 3, /* host 模式下无真实注册表       */
} AppInitResult;

/* 安装状态（host 测试查询用）                                          */
typedef enum {
    APPINIT_STATE_UNINSTALLED = 0,
    APPINIT_STATE_INSTALLED   = 1,
} AppInitState;

/*
 * appinit_install - 把 dll_path 写入 AppInit_DLLs 注册表值
 *   dll_path：宽字符 DLL 路径（Windows 下写入 REG_SZ）
 * 返回：APPINIT_OK 成功；其他见 AppInitResult。
 */
AppInitResult appinit_install(const wchar_t* dll_path);

/*
 * appinit_uninstall - 清空 AppInit_DLLs 注册表值（保证可逆）
 * 返回：APPINIT_OK 成功；其他见 AppInitResult。
 */
AppInitResult appinit_uninstall(void);

/*
 * appinit_status - 查询当前安装状态
 *   host 下返回全局变量；Windows 下查询注册表当前值是否非空。
 * 返回：APPINIT_STATE_INSTALLED / APPINIT_STATE_UNINSTALLED。
 */
AppInitState appinit_status(void);

/*
 * appinit_risk_notice - 返回风险提示字符串（UTF-8）
 *   供 UI 显示，强调"会触发反调试检测/与沙箱冲突"。
 */
const char* appinit_risk_notice(void);

#ifdef __cplusplus
}
#endif

#endif /* WIN7BRIDGE_APPINIT_H */
