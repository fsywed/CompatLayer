/*
 * shellext_core.c - Win7Bridge SubTask 3.4.2 Shell 扩展 host-testable 逻辑
 *
 * 【开发文档】
 *
 * 目的：把"配置 ↔ UI 状态"映射、校验、摘要渲染等纯逻辑与 Windows COM
 *   DialogProc 解耦，使其可在 host gcc 下测试，遵循项目"先 host 测试、
 *   真机阶段再补 Windows GUI"的工程约定。
 *
 * 分点展开：
 *   1. 路径字符串 <-> 索引：保持组合框显示顺序与 enum 一致
 *   2. 版本伪装校验：major/minor/build 范围足够覆盖 Win10/11 各分支
 *   3. toggle 联动：关闭时不破坏原值（允许快速恢复）；启用时把关键字段
 *      从 0 还原到默认（避免"启用但伪装关闭"的语义错误）
 *   4. 摘要文本：单行紧凑格式，便于属性页 Static 控件直接显示
 *   5. 综合校验：组合多字段判定，作为"应用"按钮的启用条件
 *
 * 全部函数无 <windows.h> 依赖；与 shellext_dll.c 共享 include 头。
 */
#include "win7bridge/shellext.h"

#include <stdio.h>
#include <string.h>

/* ------------------------------------------------------------------ */
/* 内部：注入路径字符串表（与 enum 一一对应）                            */
/* ------------------------------------------------------------------ */
static const char* const kInjectPathNames[W7B_INJECT_PATH__COUNT] = {
    "loader",
    "pe_patch",
    "appinit",
};

/* ------------------------------------------------------------------ */
/* path 字符串 <-> 索引                                                */
/* ------------------------------------------------------------------ */
int w7b_shellext_injection_path_to_index(const char* s)
{
    int i;
    if (s == NULL) return W7B_INJECT_PATH_LOADER;
    for (i = 0; i < W7B_INJECT_PATH__COUNT; ++i) {
        /* 大小写不敏感比较：仅 ASCII 小写表 + 'A'..'Z' -> 'a'..'z' */
        const char* a = s;
        const char* b = kInjectPathNames[i];
        while (*a && *b) {
            char ca = *a, cb = *b;
            if (ca >= 'A' && ca <= 'Z') ca = (char)(ca - 'A' + 'a');
            if (cb >= 'A' && cb <= 'Z') cb = (char)(cb - 'A' + 'a');
            if (ca != cb) break;
            ++a; ++b;
        }
        if (*a == 0 && *b == 0) return i;
    }
    return W7B_INJECT_PATH_LOADER;  /* 未知值回退默认 */
}

const char* w7b_shellext_injection_path_from_index(int idx)
{
    if (idx < 0 || idx >= W7B_INJECT_PATH__COUNT) return NULL;
    return kInjectPathNames[idx];
}

/* ------------------------------------------------------------------ */
/* 版本伪装校验                                                        */
/* ------------------------------------------------------------------ */
int w7b_shellext_validate_spoof(int enabled, int major, int minor, int build)
{
    if (!enabled) return 1;
    if (major < 1 || major > 99) return 0;
    if (minor < 0 || minor > 99) return 0;
    if (build < 0 || build > 99999) return 0;
    return 1;
}

/* ------------------------------------------------------------------ */
/* toggle 联动                                                          */
/* ------------------------------------------------------------------ */
int w7b_shellext_apply_toggle(W7bProgramConfig* cfg, int enabled)
{
    if (cfg == NULL) return -1;
    cfg->enabled = enabled ? 1 : 0;
    if (enabled) {
        /* 启用时：若关键运行期字段被人为清零，恢复默认 */
        if (cfg->version_spoof_enabled == 0) cfg->version_spoof_enabled = 1;
        if (cfg->spoof_major == 0)           cfg->spoof_major = 10;
        if (cfg->spoof_minor == 0)           cfg->spoof_minor = 0;
        if (cfg->spoof_build == 0)           cfg->spoof_build = 19041;
        if (cfg->fix_subsystem_version == 0) cfg->fix_subsystem_version = 1;
        if (cfg->strip_bound_imports == 0)   cfg->strip_bound_imports = 1;
        if (cfg->injection_path[0] == 0) {
            strcpy(cfg->injection_path, "loader");
        }
    }
    /* 关闭时不清空其他字段，保留用户配置便于重新启用 */
    return 0;
}

/* ------------------------------------------------------------------ */
/* 摘要文本                                                            */
/* ------------------------------------------------------------------ */
int w7b_shellext_summary_text(const W7bProgramConfig* cfg,
                              char* out, size_t out_cap)
{
    char        local[256];
    const char* path_str;
    int         n;

    if (cfg == NULL) {
        if (out && out_cap > 0) out[0] = 0;
        return 1;
    }
    path_str = w7b_shellext_injection_path_from_index(
        w7b_shellext_injection_path_to_index(cfg->injection_path));
    if (path_str == NULL) path_str = "loader";

    if (cfg->enabled) {
        n = snprintf(local, sizeof(local),
            "已启用 | %s", path_str);
        if (cfg->version_spoof_enabled) {
            int m = snprintf(local + n, sizeof(local) - (size_t)n,
                " | 伪装 %d.%d.%d",
                cfg->spoof_major, cfg->spoof_minor, cfg->spoof_build);
            if (m > 0) n += m;
        }
        if (cfg->fix_subsystem_version) {
            int m = snprintf(local + n, sizeof(local) - (size_t)n,
                " | 子系统修正");
            if (m > 0) n += m;
        }
        if (cfg->strip_bound_imports) {
            int m = snprintf(local + n, sizeof(local) - (size_t)n,
                " | 剥离 bound import");
            if (m > 0) n += m;
        }
    } else {
        n = snprintf(local, sizeof(local), "未启用 | %s", path_str);
    }

    /* n 现为 local 中已写字节数（不含 NUL）；总长度 = n + 1 */
    {
        int total = n + 1;
        if (out == NULL || out_cap == 0) return total;
        if (out_cap < (size_t)total) {
            /* 截断：尽可能多写，但保证 NUL 结尾 */
            size_t copy_n = out_cap - 1;
            memcpy(out, local, copy_n);
            out[copy_n] = 0;
        } else {
            memcpy(out, local, (size_t)total);
        }
        return total;
    }
}

/* ------------------------------------------------------------------ */
/* 综合校验                                                            */
/* ------------------------------------------------------------------ */
int w7b_shellext_is_config_valid(const W7bProgramConfig* cfg)
{
    int idx;
    if (cfg == NULL) return 0;
    idx = w7b_shellext_injection_path_to_index(cfg->injection_path);
    if (idx < 0 || idx >= W7B_INJECT_PATH__COUNT) return 0;
    if (!w7b_shellext_validate_spoof(cfg->version_spoof_enabled,
                                     cfg->spoof_major,
                                     cfg->spoof_minor,
                                     cfg->spoof_build)) {
        return 0;
    }
    /* 启用状态额外检查：必须有非空 EXE 基名 */
    if (cfg->enabled && cfg->exe_basename[0] == 0) return 0;
    return 1;
}
