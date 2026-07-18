/*
 * test_diag.c - Win7Bridge 一键诊断报告 host 测试
 *
 * 覆盖 docs/diag-report.md §8 的 9 个用例：
 *   1) 空输入仍能生成报告
 *   2) 进程信息写入 section 1
 *   3) UCRT 状态写入 section 2
 *   4) API Set 状态 + 依赖缺失树（section 3 / 3.1）
 *   5) Engine 规则写入 section 4.1 / 4.2
 *   6) Inline hooks 写入 section 5
 *   7) 调用流摘要 + 去重（section 6）
 *   8) 完整日志（section 7）
 *   9) 文件打开失败返回 -1
 *
 * 仅在定义 WIN7BRIDGE_HOST_TEST 时编译 main。
 */
#include "win7bridge/w7b_diag.h"
#include "win7bridge/w7b_log.h"

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

/* 读整个报告文件到 malloc 缓冲区；调用方负责 free */
static char* read_file_all(const char* path)
{
    FILE* fp = fopen(path, "rb");
    long  sz;
    char* buf;
    if (fp == NULL) return NULL;
    fseek(fp, 0, SEEK_END);
    sz = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    if (sz < 0) { fclose(fp); return NULL; }
    buf = (char*)malloc((size_t)sz + 1);
    if (buf == NULL) { fclose(fp); return NULL; }
    if (fread(buf, 1, (size_t)sz, fp) != (size_t)sz) {
        free(buf); fclose(fp); return NULL;
    }
    buf[sz] = 0;
    fclose(fp);
    return buf;
}

static int contains(const char* hay, const char* needle)
{
    return strstr(hay, needle) != NULL;
}

/* ------------------------------------------------------------------ */
/* 用例 1：空输入                                                       */
/* ------------------------------------------------------------------ */
static void case_1_empty_input(void)
{
    W7bDiagInput input;
    const char*  path = "build/test/test_diag_case1.log";
    int          rc;
    char*        text;

    memset(&input, 0, sizeof(input));
    w7b_log_init();
    w7b_log_set_level(W7B_LOG_DEBUG);

    rc = w7b_diag_export_report(path, &input);
    CHECK(rc == 0, "case1 empty input returns 0");

    text = read_file_all(path);
    CHECK(text != NULL, "case1 report file readable");
    if (text != NULL) {
        CHECK(contains(text, "# Win7Bridge Diagnostic Report"),
              "case1 has report header");
        CHECK(contains(text, "## 1. Process"),
              "case1 has section 1");
        CHECK(contains(text, "## 2. UCRT Status"),
              "case1 has section 2");
        CHECK(contains(text, "## 3. API Set Map"),
              "case1 has section 3");
        CHECK(contains(text, "## 4. Engine Rules"),
              "case1 has section 4");
        CHECK(contains(text, "## 5. Inline Hooks"),
              "case1 has section 5");
        CHECK(contains(text, "## 6. Call Flow Summary"),
              "case1 has section 6");
        CHECK(contains(text, "## 7. Full Log Dump"),
              "case1 has section 7");
        free(text);
    }
    remove(path);
    w7b_log_shutdown();
}

/* ------------------------------------------------------------------ */
/* 用例 2：进程信息                                                     */
/* ------------------------------------------------------------------ */
static void case_2_process_info(void)
{
    W7bDiagInput input;
    const char*  path = "build/test/test_diag_case2.log";
    char*        text;

    memset(&input, 0, sizeof(input));
    input.target_exe  = "C:\\games\\foo.exe";
    input.target_arch = "x64";

    w7b_log_init();
    w7b_log_set_level(W7B_LOG_DEBUG);

    CHECK(w7b_diag_export_report(path, &input) == 0,
          "case2 export returns 0");

    text = read_file_all(path);
    CHECK(text != NULL, "case2 report file readable");
    if (text != NULL) {
        CHECK(contains(text, "C:\\\\games\\\\foo.exe") ||
              contains(text, "C:\\games\\foo.exe"),
              "case2 target_exe written");
        CHECK(contains(text, "x64"), "case2 target_arch written");
        free(text);
    }
    remove(path);
    w7b_log_shutdown();
}

/* ------------------------------------------------------------------ */
/* 用例 3：UCRT 状态                                                    */
/* ------------------------------------------------------------------ */
static void case_3_ucrt_status(void)
{
    W7bDiagInput input;
    const char*  path = "build/test/test_diag_case3.log";
    char*        text;

    memset(&input, 0, sizeof(input));
    input.ucrt_status = UCRT_MISSING_UCRTBASE;

    w7b_log_init();
    w7b_log_set_level(W7B_LOG_DEBUG);

    CHECK(w7b_diag_export_report(path, &input) == 0,
          "case3 export returns 0");

    text = read_file_all(path);
    CHECK(text != NULL, "case3 report file readable");
    if (text != NULL) {
        CHECK(contains(text, "UCRT_MISSING_UCRTBASE"),
              "case3 status name written");
        CHECK(contains(text, "KB2999226"),
              "case3 status message contains KB2999226 hint");
        free(text);
    }
    remove(path);
    w7b_log_shutdown();
}

/* ------------------------------------------------------------------ */
/* 用例 4：API Set + 依赖缺失树                                         */
/* ------------------------------------------------------------------ */
static void case_4_apiset(void)
{
    W7bDiagInput input;
    ApiSetMap    m;
    const char*  path = "build/test/test_diag_case4.log";
    char*        text;

    memset(&input, 0, sizeof(input));
    apiset_init(&m);
    apiset_add(&m, "api-ms-win-core-winrt-l1-1-0",
               APISET_UNSOLVABLE, NULL,
               "WinRT API set not present on Win7");
    apiset_add(&m, "api-ms-win-core-synch-l1-1-0",
               APISET_TO_REAL_DLL, "kernel32.dll", "synch primitives");
    apiset_add(&m, "api-ms-win-core-synch-l1-2-0",
               APISET_TO_LOCAL, "win7bridge_local", "WaitOnAddress");
    input.apiset = &m;

    w7b_log_init();
    w7b_log_set_level(W7B_LOG_DEBUG);

    CHECK(w7b_diag_export_report(path, &input) == 0,
          "case4 export returns 0");

    text = read_file_all(path);
    CHECK(text != NULL, "case4 report file readable");
    if (text != NULL) {
        CHECK(contains(text, "entries: 3"),
              "case4 apiset total count == 3");
        CHECK(contains(text, "to_real_dll: 1"),
              "case4 to_real_dll count == 1");
        CHECK(contains(text, "to_local:    1"),
              "case4 to_local count == 1");
        CHECK(contains(text, "unsolvable:  1"),
              "case4 unsolvable count == 1");
        CHECK(contains(text, "api-ms-win-core-winrt-l1-1-0"),
              "case4 unsolvable entry listed");
        CHECK(contains(text, "WinRT API set not present on Win7"),
              "case4 unsolvable note listed");
        free(text);
    }
    remove(path);
    apiset_free(&m);
    w7b_log_shutdown();
}

/* ------------------------------------------------------------------ */
/* 用例 5：Engine 规则                                                  */
/* ------------------------------------------------------------------ */
static void case_5_engine(void)
{
    W7bDiagInput    input;
    RewriteEngine   e;
    const char*     path = "build/test/test_diag_case5.log";
    char*           text;
    static void*    fake_repl = (void*)0x1234;

    memset(&input, 0, sizeof(input));
    engine_init(&e);
    engine_add_dll_redirect(&e, "kernel32.dll", "kernel33.dll");
    engine_add_dll_redirect(&e, "user32.dll", "user33.dll");
    engine_add_func_redirect(&e, "kernel32.dll", "SetThreadDescription",
                             REWRITE_REPLACE_FUNC, fake_repl);
    input.engine = &e;

    w7b_log_init();
    w7b_log_set_level(W7B_LOG_DEBUG);

    CHECK(w7b_diag_export_report(path, &input) == 0,
          "case5 export returns 0");

    text = read_file_all(path);
    CHECK(text != NULL, "case5 report file readable");
    if (text != NULL) {
        CHECK(contains(text, "dll_redirects:  2"),
              "case5 dll_redirects count == 2");
        CHECK(contains(text, "func_redirects: 1"),
              "case5 func_redirects count == 1");
        CHECK(contains(text, "kernel32.dll -> kernel33.dll"),
              "case5 dll redirect listed");
        CHECK(contains(text, "kernel32.dll!SetThreadDescription"),
              "case5 func redirect listed");
        CHECK(contains(text, "REPLACE_FUNC"),
              "case5 rewrite kind listed");
        free(text);
    }
    remove(path);
    w7b_log_shutdown();
}

/* ------------------------------------------------------------------ */
/* 用例 6：Inline Hooks                                                 */
/* ------------------------------------------------------------------ */
static void case_6_hooks(void)
{
    W7bDiagInput input;
    InlineHook   hooks[2];
    const char*  path = "build/test/test_diag_case6.log";
    char*        text;

    memset(&input, 0, sizeof(input));
    memset(hooks, 0, sizeof(hooks));
    hooks[0].target     = (void*)0x1000;
    hooks[0].detour     = (void*)0x2000;
    hooks[0].patch_size = 5;
    hooks[1].target     = (void*)0x3000;
    hooks[1].detour     = (void*)0x4000;
    hooks[1].patch_size = 14;
    input.hooks       = hooks;
    input.hooks_count = 2;

    w7b_log_init();
    w7b_log_set_level(W7B_LOG_DEBUG);

    CHECK(w7b_diag_export_report(path, &input) == 0,
          "case6 export returns 0");

    text = read_file_all(path);
    CHECK(text != NULL, "case6 report file readable");
    if (text != NULL) {
        CHECK(contains(text, "installed: 2"),
              "case6 hooks_count listed");
        CHECK(contains(text, "patch_size=5"),
              "case6 hook 0 patch_size listed");
        CHECK(contains(text, "patch_size=14"),
              "case6 hook 1 patch_size listed");
        free(text);
    }
    remove(path);
    w7b_log_shutdown();
}

/* ------------------------------------------------------------------ */
/* 用例 7 + 8：调用流摘要 + 完整日志                                    */
/* ------------------------------------------------------------------ */
static void case_7_8_callflow_and_logdump(void)
{
    W7bDiagInput input;
    const char*  path = "build/test/test_diag_case7.log";
    char*        text;

    memset(&input, 0, sizeof(input));

    w7b_log_init();
    w7b_log_set_level(W7B_LOG_DEBUG);

    /* 3 条 API_INTERCEPT，2 个不同 API（前 2 条同 API 重复） */
    w7b_log_write(W7B_LOG_INFO, W7B_LOGCAT_API_INTERCEPT,
                  "hook", "BCryptOpenAlgorithmProvider(CHACHA20_POLY1305)");
    w7b_log_write(W7B_LOG_INFO, W7B_LOGCAT_API_INTERCEPT,
                  "hook", "BCryptOpenAlgorithmProvider(CHACHA20_POLY1305)");
    w7b_log_write(W7B_LOG_INFO, W7B_LOGCAT_API_INTERCEPT,
                  "hook", "SetThreadDescription");

    /* 2 条 MISSING_EXPORT，1 个不同查询（重复） */
    w7b_log_write(W7B_LOG_WARN, W7B_LOGCAT_MISSING_EXPORT,
                  "hook", "QueryMissing: D3D12CreateDevice");
    w7b_log_write(W7B_LOG_WARN, W7B_LOGCAT_MISSING_EXPORT,
                  "hook", "QueryMissing: D3D12CreateDevice");

    /* 1 条 VERSION_SPOOF */
    w7b_log_write(W7B_LOG_INFO, W7B_LOGCAT_VERSION_SPOOF,
                  "spoof", "GetVersionEx -> 10.0.19041");

    CHECK(w7b_diag_export_report(path, &input) == 0,
          "case7 export returns 0");

    text = read_file_all(path);
    CHECK(text != NULL, "case7 report file readable");
    if (text != NULL) {
        /* section 6 摘要 */
        CHECK(contains(text, "total log entries: 6"),
              "case7 total log count == 6");
        CHECK(contains(text, "API_INTERCEPT:   3   distinct APIs: 2"),
              "case7 api_intercept count + distinct");
        CHECK(contains(text, "MISSING_EXPORT:  2   distinct queries: 1"),
              "case7 missing_export count + distinct");
        CHECK(contains(text, "VERSION_SPOOF:   1"),
              "case7 version_spoof count");

        /* section 6.1 去重列表 */
        CHECK(contains(text, "BCryptOpenAlgorithmProvider(CHACHA20_POLY1305)"),
              "case7 intercepted API listed (dedup)");
        CHECK(contains(text, "SetThreadDescription"),
              "case7 intercepted API 2 listed (dedup)");

        /* section 6.2 去重列表 */
        CHECK(contains(text, "QueryMissing: D3D12CreateDevice"),
              "case7 missing query listed (dedup)");

        /* section 7 完整日志：原 API 调用名至少出现 2 次
         * （dedup 后 section 6.1 出现 1 次；section 7 出现 2 次；>=2 即可）*/
        {
            const char* p = text;
            int hits = 0;
            while ((p = strstr(p, "BCryptOpenAlgorithmProvider")) != NULL) {
                ++hits; ++p;
            }
            CHECK(hits >= 2,
                  "case7 full log section contains repeated API calls");
        }
        free(text);
    }
    remove(path);
    w7b_log_shutdown();
}

/* ------------------------------------------------------------------ */
/* 用例 9：文件打开失败                                                 */
/* ------------------------------------------------------------------ */
static void case_9_open_fail(void)
{
    W7bDiagInput input;
    int          rc;
    memset(&input, 0, sizeof(input));
    rc = w7b_diag_export_report("/nonexistent_dir_xyz/x.log", &input);
    CHECK(rc == -1, "case9 open failure returns -1");
}

/* ------------------------------------------------------------------ */
/* main                                                                */
/* ------------------------------------------------------------------ */
#ifdef WIN7BRIDGE_HOST_TEST
int main(void)
{
    printf("=== test_diag ===\n");
    case_1_empty_input();
    case_2_process_info();
    case_3_ucrt_status();
    case_4_apiset();
    case_5_engine();
    case_6_hooks();
    case_7_8_callflow_and_logdump();
    case_9_open_fail();
    printf("=== %s ===\n", g_fail ? "FAIL" : "PASS");
    return g_fail ? 1 : 0;
}
#endif
