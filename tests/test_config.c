/*
 * test_config.c - Win7Bridge 按程序粒度配置存储 host 测试
 *
 * 覆盖 docs/per-program-config.md §8 的 9 个用例：
 *   1) set_defaults 填默认值
 *   2) default_dir 返回非空且以分隔符结尾
 *   3) path_for 拼接正确
 *   4) round-trip save/load 字段保持
 *   5) load 缺文件返回 1，cfg 用默认值
 *   6) load 坏 JSON 返回 -1，cfg 用默认值
 *   7) load 含未知字段，已知字段仍正确解析
 *   8) apiset_overlays 数组 round-trip
 *   9) save 到非法路径返回 -1
 *
 * 仅在定义 WIN7BRIDGE_HOST_TEST 时编译 main。
 */
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

/* 写文本到文件（用于构造测试输入） */
static int write_text_file(const char* path, const char* content)
{
    FILE* fp = fopen(path, "wb");
    if (fp == NULL) return -1;
    fputs(content, fp);
    fclose(fp);
    return 0;
}

/* ------------------------------------------------------------------ */
/* 用例 1：set_defaults                                                 */
/* ------------------------------------------------------------------ */
static void case_1_set_defaults(void)
{
    W7bProgramConfig cfg;
    w7b_config_set_defaults(&cfg, "C:\\games\\foo.exe");

    CHECK(cfg.enabled == 1, "case1 enabled default 1");
    CHECK(cfg.version_spoof_enabled == 1, "case1 version_spoof_enabled default 1");
    CHECK(cfg.spoof_major == 10, "case1 spoof_major default 10");
    CHECK(cfg.spoof_minor == 0, "case1 spoof_minor default 0");
    CHECK(cfg.spoof_build == 19041, "case1 spoof_build default 19041");
    CHECK(cfg.fix_subsystem_version == 1, "case1 fix_subsystem_version default 1");
    CHECK(cfg.strip_bound_imports == 1, "case1 strip_bound_imports default 1");
    CHECK(cfg.log_level == 1, "case1 log_level default INFO(1)");
    CHECK(cfg.diag_report_on_exit == 0, "case1 diag_report_on_exit default 0");
    CHECK(strcmp(cfg.injection_path, "loader") == 0,
          "case1 injection_path default loader");
    CHECK(strcmp(cfg.exe_basename, "foo.exe") == 0,
          "case1 exe_basename extracted");
    CHECK(strcmp(cfg.exe_path, "C:\\games\\foo.exe") == 0,
          "case1 exe_path stored");
    CHECK(cfg.apiset_overlays_count == 0,
          "case1 apiset_overlays_count default 0");
}

/* ------------------------------------------------------------------ */
/* 用例 2：default_dir                                                  */
/* ------------------------------------------------------------------ */
static void case_2_default_dir(void)
{
    char buf[512];
    int  rc;
    size_t n;

    rc = w7b_config_default_dir(buf, sizeof(buf));
    CHECK(rc == 0, "case2 default_dir returns 0");

    n = strlen(buf);
    CHECK(n > 0, "case2 default_dir non-empty");
    CHECK(buf[n - 1] == '/' || buf[n - 1] == '\\',
          "case2 default_dir ends with separator");
    CHECK(strstr(buf, "Win7Bridge") != NULL,
          "case2 default_dir contains Win7Bridge");
    CHECK(strstr(buf, "configs") != NULL,
          "case2 default_dir contains configs");
}

/* ------------------------------------------------------------------ */
/* 用例 3：path_for                                                     */
/* ------------------------------------------------------------------ */
static void case_3_path_for(void)
{
    char buf[512];
    int  rc;

    rc = w7b_config_path_for("C:\\games\\foo.exe", "/tmp/cfgs",
                             buf, sizeof(buf));
    CHECK(rc == 0, "case3 path_for returns 0");
    /* 期望结尾是 foo.exe.json */
    {
        const char* suffix = "foo.exe.json";
        size_t blen = strlen(buf);
        size_t slen = strlen(suffix);
        CHECK(blen >= slen &&
              strcmp(buf + blen - slen, suffix) == 0,
              "case3 path ends with foo.exe.json");
    }
    CHECK(strstr(buf, "tmp") != NULL,
          "case3 path contains config_dir");

    /* NULL exe_path + NULL config_dir：应回退到 default + "default.exe" */
    rc = w7b_config_path_for(NULL, NULL, buf, sizeof(buf));
    CHECK(rc == 0, "case3 path_for(NULL,NULL) returns 0");
    CHECK(strstr(buf, "default.exe.json") != NULL,
          "case3 path_for NULL falls back to default.exe.json");
}

/* ------------------------------------------------------------------ */
/* 用例 4：round-trip                                                   */
/* ------------------------------------------------------------------ */
static void case_4_round_trip(void)
{
    W7bProgramConfig a, b;
    const char* path = "build/test/test_config_case4.json";
    int rc;

    w7b_config_set_defaults(&a, "C:\\games\\bar.exe");
    /* 修改若干字段 */
    a.enabled               = 0;
    a.version_spoof_enabled = 0;
    a.spoof_build           = 14393;
    a.log_level             = 2;  /* WARN */
    a.diag_report_on_exit   = 1;
    strcpy(a.injection_path, "pe_patch");
    strcpy(a.diag_report_path, "C:\\tmp\\bar.diag");

    rc = w7b_config_save(path, &a);
    CHECK(rc == 0, "case4 save returns 0");

    rc = w7b_config_load(path, &b);
    CHECK(rc == 0, "case4 load returns 0");

    CHECK(b.enabled == 0, "case4 enabled preserved");
    CHECK(b.version_spoof_enabled == 0, "case4 version_spoof_enabled preserved");
    CHECK(b.spoof_build == 14393, "case4 spoof_build preserved");
    CHECK(b.spoof_major == 10, "case4 spoof_major preserved (default)");
    CHECK(b.log_level == 2, "case4 log_level preserved (WARN)");
    CHECK(b.diag_report_on_exit == 1, "case4 diag_report_on_exit preserved");
    CHECK(strcmp(b.injection_path, "pe_patch") == 0,
          "case4 injection_path preserved");
    CHECK(strcmp(b.diag_report_path, "C:\\tmp\\bar.diag") == 0,
          "case4 diag_report_path preserved");
    CHECK(strcmp(b.exe_path, "C:\\games\\bar.exe") == 0,
          "case4 exe_path preserved");
    CHECK(strcmp(b.exe_basename, "bar.exe") == 0,
          "case4 exe_basename preserved");

    remove(path);
}

/* ------------------------------------------------------------------ */
/* 用例 5：load 缺文件                                                   */
/* ------------------------------------------------------------------ */
static void case_5_load_missing(void)
{
    W7bProgramConfig cfg;
    int rc = w7b_config_load("build/test/nonexistent_xyz.json", &cfg);
    CHECK(rc == 1, "case5 missing file returns 1");
    /* cfg 应有默认值 */
    CHECK(cfg.enabled == 1, "case5 cfg has default enabled");
    CHECK(cfg.spoof_build == 19041, "case5 cfg has default spoof_build");
}

/* ------------------------------------------------------------------ */
/* 用例 6：load 坏 JSON                                                  */
/* ------------------------------------------------------------------ */
static void case_6_load_bad_json(void)
{
    W7bProgramConfig cfg;
    const char* path = "build/test/test_config_case6.json";
    int rc;

    write_text_file(path, "{ this is not valid json,,, }");
    rc = w7b_config_load(path, &cfg);
    CHECK(rc == -1, "case6 bad JSON returns -1");
    CHECK(cfg.enabled == 1, "case6 cfg has default enabled after failure");

    remove(path);
}

/* ------------------------------------------------------------------ */
/* 用例 7：load 含未知字段                                              */
/* ------------------------------------------------------------------ */
static void case_7_unknown_fields(void)
{
    W7bProgramConfig cfg;
    const char* path = "build/test/test_config_case7.json";
    int rc;
    const char* json =
        "{\n"
        "  \"schema\": \"win7bridge.config/v1\",\n"
        "  \"exe_path\": \"D:\\\\app\\\\x.exe\",\n"
        "  \"exe_basename\": \"x.exe\",\n"
        "  \"enabled\": false,\n"
        "  \"injection_path\": \"appinit\",\n"
        "  \"version_spoof\": {\n"
        "    \"enabled\": true,\n"
        "    \"major\": 10,\n"
        "    \"minor\": 0,\n"
        "    \"build\": 17763\n"
        "  },\n"
        "  \"pe_fixes\": {\n"
        "    \"fix_subsystem_version\": false,\n"
        "    \"strip_bound_imports\": true\n"
        "  },\n"
        "  \"log_level\": \"debug\",\n"
        "  \"diag_report\": {\n"
        "    \"on_exit\": true,\n"
        "    \"path\": \"D:\\\\diag.log\"\n"
        "  },\n"
        "  \"api_emulation\": [{\"api\":\"X\",\"strategy\":\"noop\"}],\n"
        "  \"manifest\": {\"present\": true},\n"
        "  \"unresolvable\": [{\"dll\":\"d3d12.dll\"}],\n"
        "  \"warnings\": [\"foo\"]\n"
        "}\n";

    write_text_file(path, json);
    rc = w7b_config_load(path, &cfg);
    CHECK(rc == 0, "case7 load returns 0");

    CHECK(strcmp(cfg.exe_path, "D:\\app\\x.exe") == 0,
          "case7 exe_path parsed");
    CHECK(strcmp(cfg.exe_basename, "x.exe") == 0,
          "case7 exe_basename parsed");
    CHECK(cfg.enabled == 0, "case7 enabled parsed");
    CHECK(strcmp(cfg.injection_path, "appinit") == 0,
          "case7 injection_path parsed");
    CHECK(cfg.version_spoof_enabled == 1, "case7 version_spoof.enabled parsed");
    CHECK(cfg.spoof_build == 17763, "case7 version_spoof.build parsed");
    CHECK(cfg.fix_subsystem_version == 0, "case7 pe_fixes.fix_subsystem_version parsed");
    CHECK(cfg.strip_bound_imports == 1, "case7 pe_fixes.strip_bound_imports parsed");
    CHECK(cfg.log_level == 0, "case7 log_level=debug parsed");
    CHECK(cfg.diag_report_on_exit == 1, "case7 diag_report.on_exit parsed");
    CHECK(strcmp(cfg.diag_report_path, "D:\\diag.log") == 0,
          "case7 diag_report.path parsed");

    remove(path);
}

/* ------------------------------------------------------------------ */
/* 用例 8：apiset_overlays round-trip                                   */
/* ------------------------------------------------------------------ */
static void case_8_apiset_overlays(void)
{
    W7bProgramConfig a, b;
    const char* path = "build/test/test_config_case8.json";
    int rc;

    w7b_config_set_defaults(&a, NULL);
    strcpy(a.apiset_overlays[0], "apiset-extra.json");
    strcpy(a.apiset_overlays[1], "C:\\configs\\my-rules.json");
    strcpy(a.apiset_overlays[2], "../shared/overlay.json");
    a.apiset_overlays_count = 3;

    rc = w7b_config_save(path, &a);
    CHECK(rc == 0, "case8 save returns 0");

    rc = w7b_config_load(path, &b);
    CHECK(rc == 0, "case8 load returns 0");

    CHECK(b.apiset_overlays_count == 3,
          "case8 overlays_count preserved");
    CHECK(strcmp(b.apiset_overlays[0], "apiset-extra.json") == 0,
          "case8 overlay[0] preserved");
    CHECK(strcmp(b.apiset_overlays[1], "C:\\configs\\my-rules.json") == 0,
          "case8 overlay[1] preserved");
    CHECK(strcmp(b.apiset_overlays[2], "../shared/overlay.json") == 0,
          "case8 overlay[2] preserved");

    remove(path);
}

/* ------------------------------------------------------------------ */
/* 用例 9：save 到非法路径                                              */
/* ------------------------------------------------------------------ */
static void case_9_save_bad_path(void)
{
    W7bProgramConfig cfg;
    int rc;
    w7b_config_set_defaults(&cfg, NULL);
    rc = w7b_config_save("/nonexistent_dir_xyz/x.json", &cfg);
    CHECK(rc == -1, "case9 save to bad path returns -1");
}

/* ------------------------------------------------------------------ */
/* main                                                                */
/* ------------------------------------------------------------------ */
#ifdef WIN7BRIDGE_HOST_TEST
int main(void)
{
    printf("=== test_config ===\n");
    case_1_set_defaults();
    case_2_default_dir();
    case_3_path_for();
    case_4_round_trip();
    case_5_load_missing();
    case_6_load_bad_json();
    case_7_unknown_fields();
    case_8_apiset_overlays();
    case_9_save_bad_path();
    printf("=== %s ===\n", g_fail ? "FAIL" : "PASS");
    return g_fail ? 1 : 0;
}
#endif
