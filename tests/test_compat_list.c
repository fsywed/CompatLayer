/*
 * test_compat_list.c - Win7Bridge SubTask 5.2.3 兼容性清单 host 测试
 *
 * 验证：
 *   1) 加载合法 JSON：条目数正确、字段值正确
 *   2) 大小写不敏感查询存在 / 不存在基名
 *   3) status_to_str / status_from_str 互转 + 边界
 *   4) 健壮性：文件不存在（返回 1）、损坏 JSON（返回 -1）、空数组
 *   5) known_issues 数组解析
 *
 * 仅在定义 WIN7BRIDGE_HOST_TEST 时编译 main。
 */

#include "win7bridge/compat_list.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

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
/* 用例 1：加载合法 JSON                                                */
/* ------------------------------------------------------------------ */
static void test_load_valid(void)
{
    const char* path = "/tmp/test_compat_valid.json";
    FILE* fp = fopen(path, "wb");
    W7bCompatList list = {0};
    int rc;
    const W7bCompatListEntry* e;

    printf("==== 用例 1：加载合法 JSON ====\n");
    fputs(
        "[\n"
        "  {\n"
        "    \"exe_basename\": \"foo.exe\",\n"
        "    \"publisher\": \"TestCo\",\n"
        "    \"status\": \"works\",\n"
        "    \"tested_with\": \"win7sp1+x64\",\n"
        "    \"notes\": \"正常工作\",\n"
        "    \"known_issues\": []\n"
        "  },\n"
        "  {\n"
        "    \"exe_basename\": \"Bar.EXE\",\n"
        "    \"status\": \"limited\",\n"
        "    \"known_issues\": [\"issue 1\", \"issue 2\"]\n"
        "  }\n"
        "]\n", fp);
    fclose(fp);

    rc = w7b_compat_list_load(path, &list);
    CHECK(rc == 0, "load 返回 0");
    CHECK(list.count == 2, "count == 2");

    e = w7b_compat_list_lookup(&list, "foo.exe");
    CHECK(e != NULL, "lookup foo.exe 命中");
    CHECK(e != NULL && strcmp(e->publisher, "TestCo") == 0,
          "publisher 字段正确");
    CHECK(e != NULL && e->status == W7B_COMPAT_STATUS_WORKS,
          "status == WORKS");
    CHECK(e != NULL && strcmp(e->tested_with, "win7sp1+x64") == 0,
          "tested_with 字段正确");
    CHECK(e != NULL && strcmp(e->notes, "正常工作") == 0,
          "notes 字段正确（UTF-8）");
    CHECK(e != NULL && e->known_issues_count == 0,
          "known_issues_count == 0（空数组）");

    /* 大小写不敏感 */
    e = w7b_compat_list_lookup(&list, "FOO.EXE");
    CHECK(e != NULL, "大小写不敏感查找 FOO.EXE 命中");
    e = w7b_compat_list_lookup(&list, "bar.exe");
    CHECK(e != NULL, "大小写不敏感查找 bar.exe 命中");
    CHECK(e != NULL && e->status == W7B_COMPAT_STATUS_LIMITED,
          "bar.exe status == LIMITED");
    CHECK(e != NULL && e->known_issues_count == 2,
          "bar.exe known_issues_count == 2");
    CHECK(e != NULL && strcmp(e->known_issues[0], "issue 1") == 0,
          "bar.exe known_issues[0] == \"issue 1\"");
    CHECK(e != NULL && strcmp(e->known_issues[1], "issue 2") == 0,
          "bar.exe known_issues[1] == \"issue 2\"");

    /* 不存在 */
    e = w7b_compat_list_lookup(&list, "nope.exe");
    CHECK(e == NULL, "不存在基名返回 NULL");

    w7b_compat_list_free(&list);
    CHECK(list.entries == NULL, "free 后 entries == NULL");
    CHECK(list.count == 0, "free 后 count == 0");
    unlink(path);
}

/* ------------------------------------------------------------------ */
/* 用例 2：status_to_str / from_str 互转                                */
/* ------------------------------------------------------------------ */
static void test_status_str(void)
{
    printf("==== 用例 2：status 互转 ====\n");
    CHECK(strcmp(w7b_compat_status_to_str(W7B_COMPAT_STATUS_WORKS),
                 "works") == 0, "WORKS -> \"works\"");
    CHECK(strcmp(w7b_compat_status_to_str(W7B_COMPAT_STATUS_LIMITED),
                 "limited") == 0, "LIMITED -> \"limited\"");
    CHECK(strcmp(w7b_compat_status_to_str(W7B_COMPAT_STATUS_BROKEN),
                 "broken") == 0, "BROKEN -> \"broken\"");
    CHECK(strcmp(w7b_compat_status_to_str(W7B_COMPAT_STATUS_UNKNOWN),
                 "unknown") == 0, "UNKNOWN -> \"unknown\"");
    CHECK(strcmp(w7b_compat_status_to_str((W7bCompatStatus)99),
                 "unknown") == 0, "非法 enum -> \"unknown\"");

    CHECK(w7b_compat_status_from_str("works") == W7B_COMPAT_STATUS_WORKS,
          "\"works\" -> WORKS");
    CHECK(w7b_compat_status_from_str("LIMITED") == W7B_COMPAT_STATUS_LIMITED,
          "\"LIMITED\" -> LIMITED（大小写不敏感）");
    CHECK(w7b_compat_status_from_str("Broken") == W7B_COMPAT_STATUS_BROKEN,
          "\"Broken\" -> BROKEN");
    CHECK(w7b_compat_status_from_str("unknown") == W7B_COMPAT_STATUS_UNKNOWN,
          "\"unknown\" -> UNKNOWN");
    CHECK(w7b_compat_status_from_str("foo") == W7B_COMPAT_STATUS_UNKNOWN,
          "\"foo\" -> UNKNOWN");
    CHECK(w7b_compat_status_from_str(NULL) == W7B_COMPAT_STATUS_UNKNOWN,
          "NULL -> UNKNOWN");
}

/* ------------------------------------------------------------------ */
/* 用例 3：文件不存在 -> 返回 1                                          */
/* ------------------------------------------------------------------ */
static void test_missing_file(void)
{
    W7bCompatList list = {0};
    int rc;
    printf("==== 用例 3：文件不存在 ====\n");
    rc = w7b_compat_list_load("/tmp/does_not_exist_compat.json", &list);
    CHECK(rc == 1, "文件不存在返回 1");
    CHECK(list.entries == NULL && list.count == 0,
          "list 仍为空");
}

/* ------------------------------------------------------------------ */
/* 用例 4：损坏 JSON -> 返回 -1                                          */
/* ------------------------------------------------------------------ */
static void test_corrupt_json(void)
{
    const char* path = "/tmp/test_compat_corrupt.json";
    FILE* fp;
    W7bCompatList list = {0};
    int rc;

    printf("==== 用例 4：损坏 JSON ====\n");
    fp = fopen(path, "wb");
    fputs("{ \"not_an_array\": true }", fp);
    fclose(fp);
    rc = w7b_compat_list_load(path, &list);
    CHECK(rc == -1, "非数组 JSON 返回 -1");
    CHECK(list.entries == NULL, "失败后 entries == NULL");
    unlink(path);

    /* 缺闭合括号 */
    fp = fopen(path, "wb");
    fputs("[ { \"exe_basename\": \"a.exe\", \"status\": \"works\" ", fp);
    fclose(fp);
    rc = w7b_compat_list_load(path, &list);
    CHECK(rc == -1, "缺闭合括号返回 -1");
    CHECK(list.entries == NULL, "失败后 entries == NULL（已释放）");
    unlink(path);
}

/* ------------------------------------------------------------------ */
/* 用例 5：空数组                                                       */
/* ------------------------------------------------------------------ */
static void test_empty_array(void)
{
    const char* path = "/tmp/test_compat_empty.json";
    FILE* fp;
    W7bCompatList list = {0};
    int rc;

    printf("==== 用例 5：空数组 ====\n");
    fp = fopen(path, "wb");
    fputs("[\n]\n", fp);
    fclose(fp);
    rc = w7b_compat_list_load(path, &list);
    CHECK(rc == 0, "空数组返回 0");
    CHECK(list.count == 0, "count == 0");
    w7b_compat_list_free(&list);
    unlink(path);
}

/* ------------------------------------------------------------------ */
/* 用例 6：未知字段跳过                                                 */
/* ------------------------------------------------------------------ */
static void test_unknown_field(void)
{
    const char* path = "/tmp/test_compat_unknown.json";
    FILE* fp;
    W7bCompatList list = {0};
    int rc;
    const W7bCompatListEntry* e;

    printf("==== 用例 6：未知字段跳过 ====\n");
    fp = fopen(path, "wb");
    fputs(
        "[ { "
        "\"exe_basename\": \"unknown.exe\", "
        "\"status\": \"broken\", "
        "\"unknown_string\": \"foo\", "
        "\"unknown_number\": 42, "
        "\"unknown_array\": [1, 2, 3], "
        "\"unknown_obj\": { \"a\": 1 } "
        "} ]\n", fp);
    fclose(fp);
    rc = w7b_compat_list_load(path, &list);
    CHECK(rc == 0, "含未知字段返回 0");
    CHECK(list.count == 1, "count == 1");
    e = w7b_compat_list_lookup(&list, "unknown.exe");
    CHECK(e != NULL && e->status == W7B_COMPAT_STATUS_BROKEN,
          "未知字段不影响已知字段解析");
    w7b_compat_list_free(&list);
    unlink(path);
}

/* ------------------------------------------------------------------ */
/* 用例 7：加载项目自带 data/compat_list.json                          */
/* ------------------------------------------------------------------ */
static void test_builtin_list(void)
{
    W7bCompatList list = {0};
    int rc;
    const W7bCompatListEntry* e;

    printf("==== 用例 7：项目内置 data/compat_list.json ====\n");
    rc = w7b_compat_list_load("data/compat_list.json", &list);
    CHECK(rc == 0, "加载项目清单成功");
    CHECK(list.count >= 8, "至少 8 条记录（含测试用例占位）");

    e = w7b_compat_list_lookup(&list, "case_high_subsys.exe");
    CHECK(e != NULL && e->status == W7B_COMPAT_STATUS_WORKS,
          "case_high_subsys.exe -> WORKS");

    e = w7b_compat_list_lookup(&list, "case_pseudo_console.exe");
    CHECK(e != NULL && e->status == W7B_COMPAT_STATUS_LIMITED,
          "case_pseudo_console.exe -> LIMITED");
    CHECK(e != NULL && e->known_issues_count >= 1,
          "limited 项含至少 1 个 known_issues");

    e = w7b_compat_list_lookup(&list, "d3d12_app.exe");
    CHECK(e != NULL && e->status == W7B_COMPAT_STATUS_BROKEN,
          "d3d12_app.exe -> BROKEN");

    e = w7b_compat_list_lookup(&list, "winrt_uwp_app.exe");
    CHECK(e != NULL && e->status == W7B_COMPAT_STATUS_BROKEN,
          "winrt_uwp_app.exe -> BROKEN");

    e = w7b_compat_list_lookup(&list, "vbs_attestation_app.exe");
    CHECK(e != NULL && e->status == W7B_COMPAT_STATUS_BROKEN,
          "vbs_attestation_app.exe -> BROKEN");

    e = w7b_compat_list_lookup(&list, "tpm2_attestation_app.exe");
    CHECK(e != NULL && e->status == W7B_COMPAT_STATUS_BROKEN,
          "tpm2_attestation_app.exe -> BROKEN");

    w7b_compat_list_free(&list);
}

/* ------------------------------------------------------------------ */
/* main                                                                */
/* ------------------------------------------------------------------ */
#ifdef WIN7BRIDGE_HOST_TEST
int main(void)
{
    test_load_valid();
    test_status_str();
    test_missing_file();
    test_corrupt_json();
    test_empty_array();
    test_unknown_field();
    test_builtin_list();

    if (g_fail) {
        printf("\n==== 存在失败用例 ====\n");
        return 1;
    }
    printf("\n==== 全部通过 ====\n");
    return 0;
}
#endif
