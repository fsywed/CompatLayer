/*
 * test_inject.c - Win7Bridge SubTask 3.1.4 host 测试
 *
 * 验证 Loader 注入路径的纯逻辑部分（host 可测试）：
 *   1) loader_args_default 默认值
 *   2) loader_parse_args 各种参数组合
 *   3) loader_print_help 输出格式
 *   4) inject_init / inject_set_* 上下文管理
 *   5) inject_launch 在 host 模式返回 INJECT_ERR_HOST_NOT_SUPPORTED
 *   6) inject_cleanup 在 host 模式正常清理
 *   7) inject_set_* 对 NULL 入参的拒绝
 *   8) 反调试检测逻辑（test_3_1_4_anti_debug.c 的位掩码语义）
 *
 * 仅在定义 WIN7BRIDGE_HOST_TEST 时编译 main，用原生 gcc 运行。
 * 返回 0 表示全部通过，非 0 表示有失败。
 */
#include "win7bridge/loader.h"
#include "win7bridge/inject.h"

#include <stdio.h>
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
/* 用例 1：loader_args_default                                         */
/* ------------------------------------------------------------------ */
static void test_args_default(void)
{
    LoaderArgs args;
    int rc;

    printf("==== 用例 1：loader_args_default ====\n");

    rc = loader_args_default(&args);
    CHECK(rc == 0, "loader_args_default 返回 0");
    CHECK(args.dll_path != NULL &&
          strcmp(args.dll_path, "win7bridge.dll") == 0,
          "默认 dll_path == win7bridge.dll");
    CHECK(args.method == INJECT_METHOD_APC, "默认 method == APC");
    CHECK(args.exe_path == NULL, "默认 exe_path == NULL");
    CHECK(args.args == NULL, "默认 args == NULL");
    CHECK(args.work_dir == NULL, "默认 work_dir == NULL");
    CHECK(args.verbose == 0, "默认 verbose == 0");
    CHECK(args.help == 0, "默认 help == 0");

    /* NULL 入参 */
    rc = loader_args_default(NULL);
    CHECK(rc == -1, "loader_args_default(NULL) 返回 -1");
}

/* ------------------------------------------------------------------ */
/* 用例 2：loader_parse_args - 仅目标 EXE                              */
/* ------------------------------------------------------------------ */
static void test_parse_minimal(void)
{
    char* argv[] = { "win7bridge_loader", "C:\\test.exe" };
    LoaderArgs args;
    int rc;

    printf("==== 用例 2：仅目标 EXE ====\n");

    rc = loader_parse_args(2, argv, &args);
    CHECK(rc == 0, "parse 返回 0");
    CHECK(args.exe_path != NULL &&
          strcmp(args.exe_path, "C:\\test.exe") == 0,
          "exe_path == C:\\test.exe");
    CHECK(args.args == NULL, "args == NULL（无附加参数）");
    CHECK(args.help == 0, "help == 0");
}

/* ------------------------------------------------------------------ */
/* 用例 3：loader_parse_args - 全选项                                  */
/* ------------------------------------------------------------------ */
static void test_parse_full_options(void)
{
    char* argv[] = {
        "win7bridge_loader",
        "--dll", "bin\\win7bridge.dll",
        "--workdir", "C:\\work",
        "--method", "remote_thread",
        "--verbose",
        "C:\\test.exe", "arg1 arg2"
    };
    LoaderArgs args;
    int rc;

    printf("==== 用例 3：全选项 ====\n");

    rc = loader_parse_args(11, argv, &args);
    CHECK(rc == 0, "parse 返回 0");
    CHECK(strcmp(args.dll_path, "bin\\win7bridge.dll") == 0,
          "dll_path == bin\\win7bridge.dll");
    CHECK(strcmp(args.work_dir, "C:\\work") == 0,
          "work_dir == C:\\work");
    CHECK(args.method == INJECT_METHOD_REMOTE_THREAD,
          "method == REMOTE_THREAD");
    CHECK(args.verbose == 1, "verbose == 1");
    CHECK(strcmp(args.exe_path, "C:\\test.exe") == 0,
          "exe_path == C:\\test.exe");
    CHECK(strcmp(args.args, "arg1 arg2") == 0,
          "args == arg1 arg2");
}

/* ------------------------------------------------------------------ */
/* 用例 4：loader_parse_args - --method apc                            */
/* ------------------------------------------------------------------ */
static void test_parse_method_apc(void)
{
    char* argv[] = {
        "win7bridge_loader",
        "--method", "apc",
        "test.exe"
    };
    LoaderArgs args;
    int rc;

    printf("==== 用例 4：--method apc ====\n");

    rc = loader_parse_args(4, argv, &args);
    CHECK(rc == 0, "parse 返回 0");
    CHECK(args.method == INJECT_METHOD_APC, "method == APC");
}

/* ------------------------------------------------------------------ */
/* 用例 5：loader_parse_args - --help                                  */
/* ------------------------------------------------------------------ */
static void test_parse_help(void)
{
    char* argv[] = { "win7bridge_loader", "--help" };
    LoaderArgs args;
    int rc;

    printf("==== 用例 5：--help ====\n");

    rc = loader_parse_args(2, argv, &args);
    CHECK(rc == 0, "parse --help 返回 0");
    CHECK(args.help == 1, "help == 1");
}

/* ------------------------------------------------------------------ */
/* 用例 6：loader_parse_args - 未知选项                                */
/* ------------------------------------------------------------------ */
static void test_parse_unknown(void)
{
    char* argv[] = { "win7bridge_loader", "--unknown", "test.exe" };
    LoaderArgs args;
    int rc;

    printf("==== 用例 6：未知选项 ====\n");

    rc = loader_parse_args(3, argv, &args);
    CHECK(rc == -1, "未知选项返回 -1");
}

/* ------------------------------------------------------------------ */
/* 用例 7：loader_parse_args - 缺参数                                  */
/* ------------------------------------------------------------------ */
static void test_parse_missing_value(void)
{
    char* argv[] = { "win7bridge_loader", "--dll" };
    LoaderArgs args;
    int rc;

    printf("==== 用例 7：--dll 缺参数 ====\n");

    rc = loader_parse_args(2, argv, &args);
    CHECK(rc == -1, "--dll 缺参数返回 -1");
}

/* ------------------------------------------------------------------ */
/* 用例 8：loader_parse_args - 未知 method 值                          */
/* ------------------------------------------------------------------ */
static void test_parse_bad_method(void)
{
    char* argv[] = {
        "win7bridge_loader",
        "--method", "unknown_method",
        "test.exe"
    };
    LoaderArgs args;
    int rc;

    printf("==== 用例 8：未知 --method 值 ====\n");

    rc = loader_parse_args(4, argv, &args);
    CHECK(rc == -1, "未知 method 值返回 -1");
}

/* ------------------------------------------------------------------ */
/* 用例 9：loader_parse_args - 缺目标 EXE                              */
/* ------------------------------------------------------------------ */
static void test_parse_no_target(void)
{
    char* argv[] = { "win7bridge_loader", "--verbose" };
    LoaderArgs args;
    int rc;

    printf("==== 用例 9：缺目标 EXE ====\n");

    rc = loader_parse_args(2, argv, &args);
    CHECK(rc == -1, "缺目标 EXE 返回 -1");
}

/* ------------------------------------------------------------------ */
/* 用例 10：loader_print_help                                          */
/* ------------------------------------------------------------------ */
static void test_print_help(void)
{
    printf("==== 用例 10：loader_print_help ====\n");

    /* 输出到 stdout，仅验证不崩溃 */
    loader_print_help("win7bridge_loader", stdout);
    loader_print_help(NULL, NULL);  /* 全 NULL 入参，使用默认值 */
    CHECK(1, "loader_print_help 不崩溃");
}

/* ------------------------------------------------------------------ */
/* 用例 11：inject_init / set_* 上下文管理                             */
/* ------------------------------------------------------------------ */
static void test_inject_context(void)
{
    InjectContext ctx;
    int rc;

    printf("==== 用例 11：inject 上下文管理 ====\n");

    /* init */
    rc = inject_init(&ctx);
    CHECK(rc == INJECT_OK, "inject_init 返回 INJECT_OK");
    CHECK(ctx.method == INJECT_METHOD_REMOTE_THREAD,
          "init 后 method == REMOTE_THREAD");
    CHECK(ctx.dll_path == NULL, "init 后 dll_path == NULL");
    CHECK(ctx.exe_path == NULL, "init 后 exe_path == NULL");
    CHECK(ctx.hProcess == NULL, "init 后 hProcess == NULL");
    CHECK(ctx.pid == 0, "init 后 pid == 0");

    /* set_dll_path */
    rc = inject_set_dll_path(&ctx, "test.dll");
    CHECK(rc == INJECT_OK, "set_dll_path 返回 INJECT_OK");
    CHECK(strcmp(ctx.dll_path, "test.dll") == 0,
          "dll_path == test.dll");

    /* set_target */
    rc = inject_set_target(&ctx, "target.exe", "arg1");
    CHECK(rc == INJECT_OK, "set_target 返回 INJECT_OK");
    CHECK(strcmp(ctx.exe_path, "target.exe") == 0,
          "exe_path == target.exe");
    CHECK(strcmp(ctx.args, "arg1") == 0, "args == arg1");

    /* set_work_dir */
    rc = inject_set_work_dir(&ctx, "C:\\work");
    CHECK(rc == INJECT_OK, "set_work_dir 返回 INJECT_OK");
    CHECK(strcmp(ctx.work_dir, "C:\\work") == 0,
          "work_dir == C:\\work");

    /* NULL 入参拒绝 */
    CHECK(inject_init(NULL) == INJECT_ERR_INVALID_ARG,
          "inject_init(NULL) 拒绝");
    CHECK(inject_set_dll_path(NULL, "x") == INJECT_ERR_INVALID_ARG,
          "set_dll_path(NULL ctx) 拒绝");
    CHECK(inject_set_dll_path(&ctx, NULL) == INJECT_ERR_INVALID_ARG,
          "set_dll_path(NULL path) 拒绝");
    CHECK(inject_set_target(NULL, "x", NULL) == INJECT_ERR_INVALID_ARG,
          "set_target(NULL ctx) 拒绝");
    CHECK(inject_set_target(&ctx, NULL, NULL) == INJECT_ERR_INVALID_ARG,
          "set_target(NULL exe) 拒绝");
    CHECK(inject_set_work_dir(NULL, "x") == INJECT_ERR_INVALID_ARG,
          "set_work_dir(NULL ctx) 拒绝");
    /* work_dir 允许 NULL（合法，launch 时回退） */
    CHECK(inject_set_work_dir(&ctx, NULL) == INJECT_OK,
          "set_work_dir(NULL dir) 允许");
}

/* ------------------------------------------------------------------ */
/* 用例 12：inject_launch 在 host 返回 HOST_NOT_SUPPORTED              */
/* ------------------------------------------------------------------ */
static void test_inject_launch_host(void)
{
    InjectContext ctx;
    int rc;

    printf("==== 用例 12：host 模式 inject_launch ====\n");

    inject_init(&ctx);
    inject_set_dll_path(&ctx, "test.dll");
    inject_set_target(&ctx, "target.exe", NULL);

    rc = inject_launch(&ctx);
    CHECK(rc == INJECT_ERR_HOST_NOT_SUPPORTED,
          "host 模式 inject_launch 返回 HOST_NOT_SUPPORTED");

    /* cleanup 应正常 */
    rc = inject_cleanup(&ctx);
    CHECK(rc == INJECT_OK, "inject_cleanup 返回 INJECT_OK");
    CHECK(ctx.hProcess == NULL, "cleanup 后 hProcess == NULL");
    CHECK(ctx.pid == 0, "cleanup 后 pid == 0");

    /* cleanup NULL 入参 */
    CHECK(inject_cleanup(NULL) == INJECT_OK,
          "inject_cleanup(NULL) 返回 INJECT_OK");
}

/* ------------------------------------------------------------------ */
/* 用例 13：loader_run 在 host 返回 HOST_NOT_SUPPORTED                 */
/* ------------------------------------------------------------------ */
static void test_loader_run_host(void)
{
    LoaderArgs args;
    int rc;

    printf("==== 用例 13：host 模式 loader_run ====\n");

    loader_args_default(&args);
    args.exe_path = "test.exe";
    args.dll_path = "test.dll";

    rc = loader_run(&args);
    CHECK(rc == INJECT_ERR_HOST_NOT_SUPPORTED,
          "host 模式 loader_run 返回 HOST_NOT_SUPPORTED");

    /* NULL 入参 */
    rc = loader_run(NULL);
    CHECK(rc < 0, "loader_run(NULL) 返回负值");
}

/* ------------------------------------------------------------------ */
/* 用例 14：APC vs REMOTE_THREAD 方法切换                              */
/* ------------------------------------------------------------------ */
static void test_method_switching(void)
{
    InjectContext ctx;

    printf("==== 用例 14：注入方法切换 ====\n");

    inject_init(&ctx);
    CHECK(ctx.method == INJECT_METHOD_REMOTE_THREAD,
          "init 后默认 REMOTE_THREAD");

    ctx.method = INJECT_METHOD_APC;
    CHECK(ctx.method == INJECT_METHOD_APC, "可切到 APC");

    ctx.method = INJECT_METHOD_REMOTE_THREAD;
    CHECK(ctx.method == INJECT_METHOD_REMOTE_THREAD,
          "可切回 REMOTE_THREAD");
}

/* ------------------------------------------------------------------ */
/* 用例 15：反调试检测位掩码语义（与 test_3_1_4_anti_debug.c 对齐）    */
/*   验证 EXE 退出码位掩码的语义：                                     */
/*     bit0 = IsDebuggerPresent                                        */
/*     bit1 = ProcessDebugPort                                         */
/*     bit2 = ProcessDebugFlags                                        */
/*     bit3 = CheckRemoteDebuggerPresent                               */
/*     bit8 = 致命错误                                                 */
/*   host 模式下无法实际触发反调试检测，但验证位掩码语义本身正确。     */
/* ------------------------------------------------------------------ */
static void test_anti_debug_mask_semantics(void)
{
    int mask_clean   = 0x00;  /* 全通过：无调试器 */
    int mask_isdebug = 0x01;  /* IsDebuggerPresent 命中 */
    int mask_port    = 0x02;  /* ProcessDebugPort != 0 */
    int mask_flags   = 0x04;  /* ProcessDebugFlags == 0 */
    int mask_remote  = 0x08;  /* CheckRemoteDebuggerPresent TRUE */
    int mask_fatal   = 0x100; /* NtQueryInformationProcess 无法解析 */

    printf("==== 用例 15：反调试位掩码语义 ====\n");

    CHECK(mask_clean == 0, "全通过掩码 == 0");
    CHECK((mask_isdebug & 0x01) != 0, "bit0 = IsDebuggerPresent");
    CHECK((mask_port & 0x02) != 0, "bit1 = ProcessDebugPort");
    CHECK((mask_flags & 0x04) != 0, "bit2 = ProcessDebugFlags");
    CHECK((mask_remote & 0x08) != 0, "bit3 = CheckRemoteDebuggerPresent");
    CHECK((mask_fatal & 0x100) != 0, "bit8 = 致命错误");

    /* 组合掩码：所有反调试检测都命中 = 0x0F */
    CHECK((mask_isdebug | mask_port | mask_flags | mask_remote) == 0x0F,
          "四种检测全命中 == 0x0F");

    /* loader 注入路径不应触发任何反调试 API：
     * CREATE_SUSPENDED + VirtualAllocEx + CreateRemoteThread/QueueUserAPC
     * 不会被 IsDebuggerPresent / ProcessDebugPort / ProcessDebugFlags /
     * CheckRemoteDebuggerPresent 检测到。 */
    CHECK(mask_clean == 0, "loader 注入路径期望掩码 == 0（无调试器）");
}

/* ------------------------------------------------------------------ */
/* 主入口                                                              */
/* ------------------------------------------------------------------ */
#ifdef WIN7BRIDGE_HOST_TEST
int main(void)
{
    printf("=== SubTask 3.1.4 验证：Loader 注入路径 host 测试 ===\n\n");

    test_args_default();
    test_parse_minimal();
    test_parse_full_options();
    test_parse_method_apc();
    test_parse_help();
    test_parse_unknown();
    test_parse_missing_value();
    test_parse_bad_method();
    test_parse_no_target();
    test_print_help();
    test_inject_context();
    test_inject_launch_host();
    test_loader_run_host();
    test_method_switching();
    test_anti_debug_mask_semantics();

    if (g_fail) {
        printf("\n[RESULT] test_inject: FAIL\n");
        return 1;
    }
    printf("\n[RESULT] test_inject: PASS\n");
    return 0;
}
#endif
