/*
 * test_apiset_json.c - Win7Bridge L2 API Set JSON 配置加载器 host 测试
 *
 * 覆盖：
 *   1) 基本加载：单条 to_real_dll 条目，lookup 命中、字段正确
 *   2) 多类型混合：to_real_dll + to_local + unsolvable 各一条
 *   3) 注释跳过：JSON 含 // 行注释和块注释
 *   4) 字符串转义：note 含 \n、\"、\\，原样恢复
 *   5) 缺 host_dll：to_real_dll 缺 host_dll → APISET_ERR_PARSE
 *   6) 非法 kind：kind="foo" → APISET_ERR_PARSE
 *   7) schema 不匹配：schema="wrong" → APISET_ERR_SCHEMA
 *   8) 文件加载：写临时文件后 apiset_load_from_file 命中
 *
 * 仅在定义 WIN7BRIDGE_HOST_TEST 时编译 main，用原生 gcc 运行。
 * 返回 0 表示全部通过，非 0 表示有失败。
 */
#include "win7bridge/apiset.h"

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
/* 用例 1：基本加载                                                     */
/* ------------------------------------------------------------------ */
static void case_1_basic(void)
{
    static const char json[] =
        "{\n"
        "  \"schema\": \"win7bridge.apiset/v1\",\n"
        "  \"entries\": [\n"
        "    {\n"
        "      \"virtual_name\": \"api-ms-win-core-timezone-l1-1-0\",\n"
        "      \"kind\": \"to_real_dll\",\n"
        "      \"host_dll\": \"kernel32.dll\",\n"
        "      \"note\": \"Win7 kernel32 含时区 API\"\n"
        "    }\n"
        "  ]\n"
        "}\n";
    ApiSetMap m;
    ApiSetEntry e;
    void* arena = NULL;
    int rc;

    apiset_init(&m);
    rc = apiset_load_from_json(&m, json, &arena);
    CHECK(rc == APISET_OK, "case1 load_from_json returns OK");
    CHECK(m.count == 1, "case1 single entry loaded");

    rc = apiset_lookup(&m, "api-ms-win-core-timezone-l1-1-0", &e);
    CHECK(rc == 1, "case1 lookup hits");
    CHECK(e.kind == APISET_TO_REAL_DLL, "case1 kind=TO_REAL_DLL");
    CHECK(e.host_dll != NULL && strcmp(e.host_dll, "kernel32.dll") == 0,
          "case1 host_dll=kernel32.dll");
    CHECK(e.note != NULL && strcmp(e.note, "Win7 kernel32 含时区 API") == 0,
          "case1 note correct");

    apiset_free(&m);
    apiset_free_arena(arena);
}

/* ------------------------------------------------------------------ */
/* 用例 2：多类型混合                                                   */
/* ------------------------------------------------------------------ */
static void case_2_mixed(void)
{
    static const char json[] =
        "{\n"
        "  \"schema\": \"win7bridge.apiset/v1\",\n"
        "  \"entries\": [\n"
        "    {\"virtual_name\":\"api-ms-win-core-file-l1-2-0\","
        " \"kind\":\"to_real_dll\",\"host_dll\":\"kernel32.dll\"},\n"
        "    {\"virtual_name\":\"api-ms-win-core-synch-l1-2-0\","
        " \"kind\":\"to_local\",\"host_dll\":\"win7bridge_local\"},\n"
        "    {\"virtual_name\":\"api-ms-win-core-winrt-l1-1-0\","
        " \"kind\":\"unsolvable\"}\n"
        "  ]\n"
        "}\n";
    ApiSetMap m;
    ApiSetEntry e;
    void* arena = NULL;
    int rc;

    apiset_init(&m);
    rc = apiset_load_from_json(&m, json, &arena);
    CHECK(rc == APISET_OK, "case2 load OK");
    CHECK(m.count == 3, "case2 three entries loaded");

    rc = apiset_lookup(&m, "api-ms-win-core-file-l1-2-0", &e);
    CHECK(rc == 1 && e.kind == APISET_TO_REAL_DLL &&
          strcmp(e.host_dll, "kernel32.dll") == 0,
          "case2 to_real_dll entry");

    rc = apiset_lookup(&m, "api-ms-win-core-synch-l1-2-0", &e);
    CHECK(rc == 1 && e.kind == APISET_TO_LOCAL &&
          strcmp(e.host_dll, "win7bridge_local") == 0,
          "case2 to_local entry");

    rc = apiset_lookup(&m, "api-ms-win-core-winrt-l1-1-0", &e);
    CHECK(rc == 1 && e.kind == APISET_UNSOLVABLE && e.host_dll == NULL,
          "case2 unsolvable entry");

    apiset_free(&m);
    apiset_free_arena(arena);
}

/* ------------------------------------------------------------------ */
/* 用例 3：注释跳过                                                     */
/* ------------------------------------------------------------------ */
static void case_3_comments(void)
{
    static const char json[] =
        "{\n"
        "  // schema field\n"
        "  \"schema\": \"win7bridge.apiset/v1\",\n"
        "  /* entries block\n"
        "     multi-line comment */\n"
        "  \"entries\": [\n"
        "    // single entry\n"
        "    {\n"
        "      \"virtual_name\": \"api-ms-win-core-com-l1-1-1\", // COM\n"
        "      \"kind\": \"to_real_dll\",\n"
        "      \"host_dll\": \"ole32.dll\"\n"
        "    }\n"
        "  ]\n"
        "}\n";
    ApiSetMap m;
    ApiSetEntry e;
    void* arena = NULL;
    int rc;

    apiset_init(&m);
    rc = apiset_load_from_json(&m, json, &arena);
    CHECK(rc == APISET_OK, "case3 load OK with comments");
    CHECK(m.count == 1, "case3 one entry parsed through comments");

    rc = apiset_lookup(&m, "api-ms-win-core-com-l1-1-1", &e);
    CHECK(rc == 1 && e.kind == APISET_TO_REAL_DLL &&
          strcmp(e.host_dll, "ole32.dll") == 0,
          "case3 entry content correct");

    apiset_free(&m);
    apiset_free_arena(arena);
}

/* ------------------------------------------------------------------ */
/* 用例 4：字符串转义                                                   */
/* ------------------------------------------------------------------ */
static void case_4_escapes(void)
{
    /* note 内容：a"b\c<d>e\nL2，其中 \n 是真实换行符 */
    static const char json[] =
        "{\n"
        "  \"schema\": \"win7bridge.apiset/v1\",\n"
        "  \"entries\": [\n"
        "    {\n"
        "      \"virtual_name\": \"api-ms-win-crt-heap-l1-1-0\",\n"
        "      \"kind\": \"to_real_dll\",\n"
        "      \"host_dll\": \"ucrtbase.dll\",\n"
        "      \"note\": \"a\\\"b\\\\c\\nd\\te\"\n"
        "    }\n"
        "  ]\n"
        "}\n";
    ApiSetMap m;
    ApiSetEntry e;
    void* arena = NULL;
    int rc;
    static const char expected_note[] = "a\"b\\c\nd\te";

    apiset_init(&m);
    rc = apiset_load_from_json(&m, json, &arena);
    CHECK(rc == APISET_OK, "case4 load OK with escapes");

    rc = apiset_lookup(&m, "api-ms-win-crt-heap-l1-1-0", &e);
    CHECK(rc == 1, "case4 lookup hits");
    CHECK(e.note != NULL && strcmp(e.note, expected_note) == 0,
          "case4 escape sequences decoded correctly");

    apiset_free(&m);
    apiset_free_arena(arena);
}

/* ------------------------------------------------------------------ */
/* 用例 5：缺 host_dll                                                 */
/* ------------------------------------------------------------------ */
static void case_5_missing_host(void)
{
    static const char json[] =
        "{\n"
        "  \"schema\": \"win7bridge.apiset/v1\",\n"
        "  \"entries\": [\n"
        "    {\"virtual_name\":\"api-ms-win-core-x-l1-1-0\","
        " \"kind\":\"to_real_dll\"}\n"
        "  ]\n"
        "}\n";
    ApiSetMap m;
    void* arena = NULL;
    int rc;

    apiset_init(&m);
    rc = apiset_load_from_json(&m, json, &arena);
    CHECK(rc == APISET_ERR_PARSE, "case5 missing host_dll -> PARSE error");
    CHECK(m.count == 0, "case5 map unchanged on failure");
    CHECK(arena == NULL, "case5 arena NULL on failure");

    apiset_free(&m);
}

/* ------------------------------------------------------------------ */
/* 用例 6：非法 kind                                                   */
/* ------------------------------------------------------------------ */
static void case_6_bad_kind(void)
{
    static const char json[] =
        "{\n"
        "  \"schema\": \"win7bridge.apiset/v1\",\n"
        "  \"entries\": [\n"
        "    {\"virtual_name\":\"api-ms-win-core-x-l1-1-0\","
        " \"kind\":\"foo\",\"host_dll\":\"a.dll\"}\n"
        "  ]\n"
        "}\n";
    ApiSetMap m;
    void* arena = NULL;
    int rc;

    apiset_init(&m);
    rc = apiset_load_from_json(&m, json, &arena);
    CHECK(rc == APISET_ERR_PARSE, "case6 bad kind -> PARSE error");
    CHECK(m.count == 0, "case6 map unchanged on failure");

    apiset_free(&m);
}

/* ------------------------------------------------------------------ */
/* 用例 7：schema 不匹配                                                */
/* ------------------------------------------------------------------ */
static void case_7_bad_schema(void)
{
    static const char json[] =
        "{\n"
        "  \"schema\": \"wrong\",\n"
        "  \"entries\": []\n"
        "}\n";
    ApiSetMap m;
    void* arena = NULL;
    int rc;

    apiset_init(&m);
    rc = apiset_load_from_json(&m, json, &arena);
    CHECK(rc == APISET_ERR_SCHEMA, "case7 wrong schema -> SCHEMA error");
    CHECK(m.count == 0, "case7 map unchanged on failure");

    apiset_free(&m);
}

/* ------------------------------------------------------------------ */
/* 用例 8：文件加载                                                     */
/* ------------------------------------------------------------------ */
static void case_8_file_load(void)
{
    static const char json[] =
        "{\n"
        "  \"schema\": \"win7bridge.apiset/v1\",\n"
        "  \"entries\": [\n"
        "    {\"virtual_name\":\"api-ms-win-shcore-scaling-l1-1-0\","
        " \"kind\":\"to_local\",\"host_dll\":\"win7bridge_local\","
        " \"note\":\"DPI\"}\n"
        "  ]\n"
        "}\n";
    const char* path = "build/test/test_apiset_json_case8.json";
    ApiSetMap m;
    ApiSetEntry e;
    void* arena = NULL;
    FILE* fp;
    int rc;
    size_t written;

    /* 写入临时文件 */
    fp = fopen(path, "wb");
    CHECK(fp != NULL, "case8 create temp file");
    if (fp == NULL) return;
    written = fwrite(json, 1, strlen(json), fp);
    fclose(fp);
    CHECK(written == strlen(json), "case8 wrote temp file");

    apiset_init(&m);
    rc = apiset_load_from_file(&m, path, &arena);
    CHECK(rc == APISET_OK, "case8 load_from_file OK");
    CHECK(m.count == 1, "case8 single entry loaded from file");

    rc = apiset_lookup(&m, "api-ms-win-shcore-scaling-l1-1-0", &e);
    CHECK(rc == 1 && e.kind == APISET_TO_LOCAL &&
          strcmp(e.host_dll, "win7bridge_local") == 0,
          "case8 entry content correct");

    apiset_free(&m);
    apiset_free_arena(arena);

    /* 清理临时文件 */
    remove(path);
}

/* ------------------------------------------------------------------ */
/* 用例 9：叠加在 load_default 之上                                    */
/* ------------------------------------------------------------------ */
static void case_9_overlay_default(void)
{
    static const char json[] =
        "{\n"
        "  \"schema\": \"win7bridge.apiset/v1\",\n"
        "  \"entries\": [\n"
        "    {\"virtual_name\":\"api-ms-win-core-realtime-l1-1-0\","
        " \"kind\":\"to_local\",\"host_dll\":\"win7bridge_local\"}\n"
        "  ]\n"
        "}\n";
    ApiSetMap m;
    ApiSetEntry e_default;
    ApiSetEntry e_custom;
    void* arena = NULL;
    int rc;

    apiset_init(&m);
    rc = apiset_load_default(&m);
    CHECK(rc == APISET_OK, "case9 load_default OK");
    {
        size_t default_count = m.count;
        rc = apiset_load_from_json(&m, json, &arena);
        CHECK(rc == APISET_OK, "case9 overlay load_from_json OK");
        CHECK(m.count == default_count + 1, "case9 overlay added 1 entry");
    }

    /* 默认条目仍可查到 */
    rc = apiset_lookup(&m, "api-ms-win-core-synch-l1-2-0", &e_default);
    CHECK(rc == 1 && e_default.kind == APISET_TO_LOCAL,
          "case9 default entry preserved");

    /* 自定义条目也可查到 */
    rc = apiset_lookup(&m, "api-ms-win-core-realtime-l1-1-0", &e_custom);
    CHECK(rc == 1 && e_custom.kind == APISET_TO_LOCAL &&
          strcmp(e_custom.host_dll, "win7bridge_local") == 0,
          "case9 custom entry added via JSON");

    apiset_free(&m);
    apiset_free_arena(arena);
}

/* ------------------------------------------------------------------ */
/* main                                                                */
/* ------------------------------------------------------------------ */
#ifdef WIN7BRIDGE_HOST_TEST
int main(void)
{
    printf("=== test_apiset_json ===\n");
    case_1_basic();
    case_2_mixed();
    case_3_comments();
    case_4_escapes();
    case_5_missing_host();
    case_6_bad_kind();
    case_7_bad_schema();
    case_8_file_load();
    case_9_overlay_default();
    printf("=== %s ===\n", g_fail ? "FAIL" : "PASS");
    return g_fail ? 1 : 0;
}
#endif
