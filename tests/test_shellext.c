/*
 * test_shellext.c - Win7Bridge SubTask 3.4.2 Shell 扩展 host 测试
 *
 * 验证 shellext_core.c 的 5 个 host-testable 接口：
 *   1) injection_path_to_index / from_index 互转 + 边界
 *   2) validate_spoof 范围与 enabled 短路
 *   3) apply_toggle on/off 联动
 *   4) summary_text 各字段渲染与截断
 *   5) is_config_valid 综合校验
 *
 * 仅在定义 WIN7BRIDGE_HOST_TEST 时编译 main。
 */

#include "win7bridge/shellext.h"
#include "win7bridge/w7b_config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------ */
/* 简单断言                                                            */
/* ------------------------------------------------------------------ */
static int g_fail = 0;
#define CHECK(cond, msg)                                                  \
    do {                                                                  \
        if (!(cond)) {                                                    \
            printf("[FAIL] %s:%d %s\n", __FILE__, __LINE__, (msg));       \
            g_fail = 1;                                                   \
        } else {                                                          \
            printf("[ok]   %s\n", (msg));                                 \
        }                                                                 \
    } while (0)

/* ------------------------------------------------------------------ */
/* 用例 1：injection_path 互转                                          */
/* ------------------------------------------------------------------ */
static void test_path_index(void)
{
    int i;
    printf("==== 用例 1：injection_path_to_index/from_index ====\n");

    CHECK(w7b_shellext_injection_path_to_index("loader") ==
          W7B_INJECT_PATH_LOADER, "\"loader\" -> 0");
    CHECK(w7b_shellext_injection_path_to_index("LOADER") ==
          W7B_INJECT_PATH_LOADER, "\"LOADER\" -> 0 (大小写不敏感)");
    CHECK(w7b_shellext_injection_path_to_index("pe_patch") ==
          W7B_INJECT_PATH_PE_PATCH, "\"pe_patch\" -> 1");
    CHECK(w7b_shellext_injection_path_to_index("Pe_Patch") ==
          W7B_INJECT_PATH_PE_PATCH, "\"Pe_Patch\" -> 1");
    CHECK(w7b_shellext_injection_path_to_index("appinit") ==
          W7B_INJECT_PATH_APPINIT, "\"appinit\" -> 2");
    CHECK(w7b_shellext_injection_path_to_index(NULL) ==
          W7B_INJECT_PATH_LOADER, "NULL -> 0 (回退默认)");
    CHECK(w7b_shellext_injection_path_to_index("unknown") ==
          W7B_INJECT_PATH_LOADER, "\"unknown\" -> 0 (回退)");
    CHECK(w7b_shellext_injection_path_to_index("") ==
          W7B_INJECT_PATH_LOADER, "空串 -> 0");

    CHECK(w7b_shellext_injection_path_from_index(0) != NULL &&
          strcmp(w7b_shellext_injection_path_from_index(0), "loader") == 0,
          "from_index(0) == \"loader\"");
    CHECK(w7b_shellext_injection_path_from_index(1) != NULL &&
          strcmp(w7b_shellext_injection_path_from_index(1), "pe_patch") == 0,
          "from_index(1) == \"pe_patch\"");
    CHECK(w7b_shellext_injection_path_from_index(2) != NULL &&
          strcmp(w7b_shellext_injection_path_from_index(2), "appinit") == 0,
          "from_index(2) == \"appinit\"");
    CHECK(w7b_shellext_injection_path_from_index(-1) == NULL,
          "from_index(-1) == NULL");
    CHECK(w7b_shellext_injection_path_from_index(W7B_INJECT_PATH__COUNT)
          == NULL,
          "from_index(COUNT) == NULL");

    /* 双向往返 */
    for (i = 0; i < W7B_INJECT_PATH__COUNT; ++i) {
        const char* s = w7b_shellext_injection_path_from_index(i);
        CHECK(s != NULL && w7b_shellext_injection_path_to_index(s) == i,
              "往返 idx->str->idx 一致");
    }
}

/* ------------------------------------------------------------------ */
/* 用例 2：validate_spoof 范围                                          */
/* ------------------------------------------------------------------ */
static void test_validate_spoof(void)
{
    printf("==== 用例 2：validate_spoof ====\n");

    /* enabled=0：一律合法 */
    CHECK(w7b_shellext_validate_spoof(0, 0, 0, 0) == 1,
          "enabled=0 -> 合法（不校验）");
    CHECK(w7b_shellext_validate_spoof(0, 999, 999, 999999) == 1,
          "enabled=0 极端值仍合法");

    /* enabled=1 合法区间 */
    CHECK(w7b_shellext_validate_spoof(1, 10, 0, 19041) == 1,
          "Win10 10.0.19041 合法");
    CHECK(w7b_shellext_validate_spoof(1, 1, 0, 0) == 1,
          "最小值 1.0.0 合法");
    CHECK(w7b_shellext_validate_spoof(1, 99, 99, 99999) == 1,
          "最大值 99.99.99999 合法");

    /* 边界非法 */
    CHECK(w7b_shellext_validate_spoof(1, 0, 0, 0) == 0,
          "major=0 非法");
    CHECK(w7b_shellext_validate_spoof(1, 100, 0, 0) == 0,
          "major=100 非法");
    CHECK(w7b_shellext_validate_spoof(1, 10, -1, 0) == 0,
          "minor=-1 非法");
    CHECK(w7b_shellext_validate_spoof(1, 10, 100, 0) == 0,
          "minor=100 非法");
    CHECK(w7b_shellext_validate_spoof(1, 10, 0, -1) == 0,
          "build=-1 非法");
    CHECK(w7b_shellext_validate_spoof(1, 10, 0, 100000) == 0,
          "build=100000 非法");
}

/* ------------------------------------------------------------------ */
/* 用例 3：apply_toggle on/off 联动                                     */
/* ------------------------------------------------------------------ */
static void test_apply_toggle(void)
{
    W7bProgramConfig cfg;
    printf("==== 用例 3：apply_toggle ====\n");

    /* 入参非法 */
    CHECK(w7b_shellext_apply_toggle(NULL, 1) == -1, "cfg=NULL 返回 -1");

    /* 启用路径：从清零状态恢复默认 */
    memset(&cfg, 0, sizeof(cfg));
    w7b_config_set_defaults(&cfg, "C:\\app.exe");
    /* 故意把关键字段清零模拟"用户之前关闭过" */
    cfg.version_spoof_enabled = 0;
    cfg.spoof_major = 0;
    cfg.spoof_minor = 0;
    cfg.spoof_build = 0;
    cfg.fix_subsystem_version = 0;
    cfg.strip_bound_imports = 0;
    cfg.injection_path[0] = 0;

    w7b_shellext_apply_toggle(&cfg, 1);
    CHECK(cfg.enabled == 1, "enabled=1");
    CHECK(cfg.version_spoof_enabled == 1, "version_spoof_enabled 恢复 1");
    CHECK(cfg.spoof_major == 10, "spoof_major 恢复 10");
    CHECK(cfg.spoof_minor == 0, "spoof_minor 恢复 0");
    CHECK(cfg.spoof_build == 19041, "spoof_build 恢复 19041");
    CHECK(cfg.fix_subsystem_version == 1, "fix_subsystem_version 恢复 1");
    CHECK(cfg.strip_bound_imports == 1, "strip_bound_imports 恢复 1");
    CHECK(strcmp(cfg.injection_path, "loader") == 0,
          "injection_path 恢复 loader");

    /* 关闭路径：不清空其他字段 */
    cfg.version_spoof_enabled = 1;
    cfg.spoof_major = 11;
    w7b_shellext_apply_toggle(&cfg, 0);
    CHECK(cfg.enabled == 0, "关闭后 enabled=0");
    CHECK(cfg.version_spoof_enabled == 1, "关闭后 version_spoof 保留");
    CHECK(cfg.spoof_major == 11, "关闭后 spoof_major 保留");

    /* 启用时不覆盖已设的非零值 */
    w7b_shellext_apply_toggle(&cfg, 1);
    CHECK(cfg.spoof_major == 11, "启用时 spoof_major=11 保留");
    CHECK(cfg.version_spoof_enabled == 1, "启用时 spoof_enabled=1 保留");
}

/* ------------------------------------------------------------------ */
/* 用例 4：summary_text 渲染                                            */
/* ------------------------------------------------------------------ */
static void test_summary_text(void)
{
    W7bProgramConfig cfg;
    char buf[256];
    int  n;
    printf("==== 用例 4：summary_text ====\n");

    /* NULL 入参 */
    n = w7b_shellext_summary_text(NULL, buf, sizeof(buf));
    CHECK(n == 1 && buf[0] == 0, "cfg=NULL 返回 1 且 buf 为空串");

    /* 启用 + 全默认 */
    w7b_config_set_defaults(&cfg, "C:\\app.exe");
    n = w7b_shellext_summary_text(&cfg, buf, sizeof(buf));
    CHECK(n > 0, "默认配置摘要长度 > 0");
    CHECK(strstr(buf, "已启用") != NULL, "含 \"已启用\"");
    CHECK(strstr(buf, "loader") != NULL, "含 \"loader\"");
    CHECK(strstr(buf, "伪装 10.0.19041") != NULL, "含版本伪装");
    CHECK(strstr(buf, "子系统修正") != NULL, "含子系统修正");
    CHECK(strstr(buf, "剥离 bound import") != NULL, "含剥离 bound import");

    /* 关闭：仅显示 "未启用 | path" */
    cfg.enabled = 0;
    n = w7b_shellext_summary_text(&cfg, buf, sizeof(buf));
    CHECK(strstr(buf, "未启用") != NULL, "关闭时含 \"未启用\"");
    CHECK(strstr(buf, "伪装") == NULL, "关闭时不渲染伪装");
    CHECK(strstr(buf, "子系统") == NULL, "关闭时不渲染子系统");

    /* 关闭版本伪装：启用但 spoof_enabled=0 */
    cfg.enabled = 1;
    cfg.version_spoof_enabled = 0;
    n = w7b_shellext_summary_text(&cfg, buf, sizeof(buf));
    CHECK(strstr(buf, "已启用") != NULL, "启用状态正确");
    CHECK(strstr(buf, "伪装") == NULL, "关闭伪装时不渲染版本");

    /* 自定义注入路径 */
    strcpy(cfg.injection_path, "appinit");
    cfg.version_spoof_enabled = 1;
    n = w7b_shellext_summary_text(&cfg, buf, sizeof(buf));
    CHECK(strstr(buf, "appinit") != NULL, "自定义 path 渲染");

    /* 截断：out_cap=5 */
    {
        char tiny[5];
        int  need = w7b_shellext_summary_text(&cfg, NULL, 0);
        CHECK(need > 5, "完整摘要长度 > 5");
        n = w7b_shellext_summary_text(&cfg, tiny, sizeof(tiny));
        CHECK(n == need, "返回值仍为所需长度");
        CHECK((int)strlen(tiny) == 4, "tiny 被截断到 4 字符 + NUL");
        CHECK(tiny[4] == 0, "NUL 结尾正确");
    }
}

/* ------------------------------------------------------------------ */
/* 用例 5：is_config_valid                                             */
/* ------------------------------------------------------------------ */
static void test_is_config_valid(void)
{
    W7bProgramConfig cfg;
    printf("==== 用例 5：is_config_valid ====\n");

    CHECK(w7b_shellext_is_config_valid(NULL) == 0, "NULL -> 0");

    /* 默认配置应合法 */
    w7b_config_set_defaults(&cfg, "C:\\app.exe");
    CHECK(w7b_shellext_is_config_valid(&cfg) == 1, "默认配置合法");

    /* 启用但基名为空：非法 */
    {
        W7bProgramConfig bad;
        w7b_config_set_defaults(&bad, NULL);
        bad.enabled = 1;
        bad.exe_basename[0] = 0;
        CHECK(w7b_shellext_is_config_valid(&bad) == 0,
              "启用但基名空 -> 0");
    }

    /* 版本伪装参数非法 */
    cfg.version_spoof_enabled = 1;
    cfg.spoof_major = 0;
    CHECK(w7b_shellext_is_config_valid(&cfg) == 0,
          "spoof_major=0 -> 0");

    /* 修正后合法 */
    cfg.spoof_major = 10;
    CHECK(w7b_shellext_is_config_valid(&cfg) == 1,
          "修正后 -> 1");

    /* injection_path 未知 -> 默认 loader，仍合法 */
    strcpy(cfg.injection_path, "unknown");
    CHECK(w7b_shellext_is_config_valid(&cfg) == 1,
          "未知 injection_path 回退默认仍合法");

    /* 关闭版本伪装时 build 越界也合法 */
    cfg.version_spoof_enabled = 0;
    cfg.spoof_build = 999999;
    CHECK(w7b_shellext_is_config_valid(&cfg) == 1,
          "关闭伪装时不校验 build");
}

/* ------------------------------------------------------------------ */
/* main                                                                */
/* ------------------------------------------------------------------ */
#ifdef WIN7BRIDGE_HOST_TEST
int main(void)
{
    test_path_index();
    test_validate_spoof();
    test_apply_toggle();
    test_summary_text();
    test_is_config_valid();

    if (g_fail) {
        printf("\n==== 存在失败用例 ====\n");
        return 1;
    }
    printf("\n==== 全部通过 ====\n");
    return 0;
}
#endif
