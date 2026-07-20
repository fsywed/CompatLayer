/*
 * shellext.h - Win7Bridge SubTask 3.4.2 资源管理器右键属性页 Shell 扩展
 *
 * 【开发文档】
 *
 * 目的：在 .exe / exefile 的"属性"对话框新增"Win7Bridge"页，让用户
 *   图形化地启用/关闭兼容层、选择注入路径、调整版本伪装参数，并
 *   通过 W7bProgramConfig 持久化到 per-user 配置目录。
 *
 * 分点展开：
 *   1. 平台隔离
 *      COM/DialogProc/IShellExtInit 是 Windows 专有；本头仅声明
 *      host-testable 纯逻辑接口，Windows COM 主体放在 shellext_dll.c。
 *
 *   2. host-testable 接口
 *      - injection_path 字符串 <-> 组合框索引
 *      - 版本伪装参数校验（major/minor/build 范围）
 *      - enabled 切换时联动其他字段（关闭时强制清零 spoof 等）
 *      - 把当前配置渲染成单行摘要，供属性页 Static 控件显示
 *      - 校验配置合法性（供"应用"按钮启用判定）
 *
 *   3. 调用约定
 *      全部函数无副作用（除显式标注外）；不依赖 <windows.h>；可被
 *      tests/test_shellext.c 直接 link。
 */
#ifndef WIN7BRIDGE_SHELLEXT_H
#define WIN7BRIDGE_SHELLEXT_H

#include "win7bridge/w7b_config.h"

#ifdef __cplusplus
extern "C" {
#endif

/* 注入路径组合框索引（与 DialogProc 中 ComboBox 顺序一一对应） */
enum {
    W7B_INJECT_PATH_LOADER  = 0,   /* "loader"  - 默认                       */
    W7B_INJECT_PATH_PE_PATCH = 1,  /* "pe_patch"                              */
    W7B_INJECT_PATH_APPINIT = 2,   /* "appinit" - 风险路径，UI 需标注         */
    W7B_INJECT_PATH__COUNT
};

/*
 * w7b_shellext_injection_path_to_index - 字符串 -> 组合框索引
 *   s："loader"/"pe_patch"/"appinit"（不区分大小写）；NULL/未知 -> 0
 *   返回值范围 [0, W7B_INJECT_PATH__COUNT-1]
 */
int w7b_shellext_injection_path_to_index(const char* s);

/*
 * w7b_shellext_injection_path_from_index - 索引 -> 静态字符串
 *   idx 越界返回 NULL；否则返回指向常量字符串的指针（不需要释放）
 */
const char* w7b_shellext_injection_path_from_index(int idx);

/*
 * w7b_shellext_validate_spoof - 校验版本伪装参数
 *   返回 1 合法；0 非法
 *   合法范围：major ∈ [1, 99]，minor ∈ [0, 99]，build ∈ [0, 99999]
 *   enabled=0 时一律返回 1（不启用即不校验）
 */
int w7b_shellext_validate_spoof(int enabled, int major, int minor, int build);

/*
 * w7b_shellext_apply_toggle - 根据 enabled 切换 cfg 中联动字段
 *   enabled=0：保持 enabled=0，但不清空其他字段（仅 UI 灰显）
 *   enabled=1：若 version_spoof_enabled/supported 字段为 0，恢复默认
 *   cfg 必须非 NULL；返回 0 成功，-1 入参非法
 */
int w7b_shellext_apply_toggle(W7bProgramConfig* cfg, int enabled);

/*
 * w7b_shellext_summary_text - 渲染单行摘要
 *   out/out_cap：输出缓冲；返回所需字节数（含 NUL）
 *   out_cap=0 时仅返回所需长度，不写入
 *   格式示例：
 *     "已启用 | loader | 伪装 10.0.19041 | 子系统修正"
 *     "未启用 | loader"
 */
int w7b_shellext_summary_text(const W7bProgramConfig* cfg,
                              char* out, size_t out_cap);

/*
 * w7b_shellext_is_config_valid - 综合校验配置可应用性
 *   返回 1 可应用；0 不可应用（摘要/警告需在 UI 中展示）
 *   检查项：cfg 非 NULL、版本伪装参数合法、injection_path 合法
 */
int w7b_shellext_is_config_valid(const W7bProgramConfig* cfg);

#ifdef __cplusplus
}
#endif

#endif /* WIN7BRIDGE_SHELLEXT_H */
