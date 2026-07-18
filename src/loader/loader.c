/*
 * loader.c - Win7Bridge Loader EXE 主程序
 *
 * 【开发文档】
 *
 * 目的：win7bridge_loader.exe 的入口，解析命令行后串联 inject 模块
 *   完成对目标 EXE 的 DLL 注入。
 *
 * 分点展开：
 *   1. 参数解析 loader_parse_args
 *      纯字符串解析，host 可测试。未知参数写到 stderr 并返回 -1。
 *
 *   2. loader_run
 *      调用 inject_init → set_dll_path → set_target → set_work_dir
 *      → launch → WaitForSingleObject → GetExitCodeProcess → cleanup。
 *
 *   3. main
 *      仅 Windows 下编译（host 模式由 WIN7BRIDGE_HOST_TEST 排除）。
 */

#include "win7bridge/loader.h"

#include <stdio.h>
#include <string.h>

/* ------------------------------------------------------------------ */
/* loader_args_default                                                 */
/* ------------------------------------------------------------------ */
int loader_args_default(LoaderArgs* args)
{
    if (args == NULL) return -1;
    memset(args, 0, sizeof(*args));
    args->dll_path = "win7bridge.dll";
    args->method   = INJECT_METHOD_APC;
    return 0;
}

/* ------------------------------------------------------------------ */
/* loader_print_help                                                   */
/* ------------------------------------------------------------------ */
void loader_print_help(const char* prog, void* stream)
{
    FILE* fp = (FILE*)stream;
    if (fp == NULL) fp = stdout;
    if (prog == NULL) prog = "win7bridge_loader";
    fprintf(fp,
        "Win7Bridge Loader - 把 win7bridge.dll 注入目标 EXE\n"
        "\n"
        "用法: %s [选项] <target.exe> [args...]\n"
        "\n"
        "选项:\n"
        "  --dll <path>          DLL 路径（默认 win7bridge.dll）\n"
        "  --workdir <dir>       工作目录（默认 目标 EXE 所在目录）\n"
        "  --method <name>       注入方法: remote_thread | apc（默认 apc）\n"
        "  --verbose             打印详细日志\n"
        "  --help                显示本帮助\n"
        "\n"
        "示例:\n"
        "  %s --dll bin\\win7bridge.dll bin\\case_02.exe\n",
        prog, prog);
}

/* ------------------------------------------------------------------ */
/* loader_parse_args                                                   */
/* ------------------------------------------------------------------ */
int loader_parse_args(int argc, char** argv, LoaderArgs* out)
{
    int i;
    if (out == NULL) return -1;
    loader_args_default(out);

    for (i = 1; i < argc; ++i) {
        const char* a = argv[i];
        if (strcmp(a, "--help") == 0) {
            out->help = 1;
            return 0;
        } else if (strcmp(a, "--verbose") == 0) {
            out->verbose = 1;
        } else if (strcmp(a, "--dll") == 0) {
            if (++i >= argc) { fprintf(stderr, "--dll 缺参数\n"); return -1; }
            out->dll_path = argv[i];
        } else if (strcmp(a, "--workdir") == 0) {
            if (++i >= argc) { fprintf(stderr, "--workdir 缺参数\n"); return -1; }
            out->work_dir = argv[i];
        } else if (strcmp(a, "--method") == 0) {
            const char* m;
            if (++i >= argc) { fprintf(stderr, "--method 缺参数\n"); return -1; }
            m = argv[i];
            if (strcmp(m, "remote_thread") == 0) {
                out->method = INJECT_METHOD_REMOTE_THREAD;
            } else if (strcmp(m, "apc") == 0) {
                out->method = INJECT_METHOD_APC;
            } else {
                fprintf(stderr, "未知 --method: %s\n", m);
                return -1;
            }
        } else if (a[0] == '-' && a[1] == '-') {
            fprintf(stderr, "未知参数: %s\n", a);
            return -1;
        } else {
            /* 第一个非选项参数为目标 EXE；剩余拼为 args */
            out->exe_path = a;
            if (i + 1 < argc) {
                out->args = argv[i + 1];
            }
            return 0;
        }
    }
    fprintf(stderr, "缺少目标 EXE 路径\n");
    return -1;
}

/* ------------------------------------------------------------------ */
/* loader_run                                                          */
/* ------------------------------------------------------------------ */
#if defined(_WIN32) && !defined(WIN7BRIDGE_HOST_TEST) && !defined(WIN7BRIDGE_SYNTAX_CHECK)

#include <windows.h>

#ifndef INFINITE
#define INFINITE 0xFFFFFFFF
#endif

int loader_run(const LoaderArgs* args)
{
    InjectContext ctx;
    int           rc;
    DWORD         exit_code = 0;

    if (args == NULL || args->exe_path == NULL) return -1;

    if (args->verbose) {
        printf("[loader] target  = %s\n", args->exe_path);
        printf("[loader] dll     = %s\n", args->dll_path);
        printf("[loader] workdir = %s\n",
               args->work_dir ? args->work_dir : "(exe dir)");
        printf("[loader] method  = %s\n",
               args->method == INJECT_METHOD_APC ? "apc" : "remote_thread");
    }

    inject_init(&ctx);
    ctx.method = args->method;
    inject_set_dll_path(&ctx, args->dll_path);
    inject_set_target(&ctx, args->exe_path, args->args);
    inject_set_work_dir(&ctx, args->work_dir);

    rc = inject_launch(&ctx);
    if (rc != INJECT_OK) {
        fprintf(stderr, "[loader] inject_launch 失败: %d\n", rc);
        inject_cleanup(&ctx);
        return rc;
    }

    if (args->verbose) {
        printf("[loader] 进程已启动 pid=%lu，等待退出...\n",
               (unsigned long)ctx.pid);
    }
    WaitForSingleObject(ctx.hProcess, INFINITE);
    GetExitCodeProcess(ctx.hProcess, &exit_code);
    inject_cleanup(&ctx);

    if (args->verbose) {
        printf("[loader] 进程退出 code=%lu\n",
               (unsigned long)exit_code);
    }
    return (int)exit_code;
}

#else  /* host / syntax-check */

int loader_run(const LoaderArgs* args)
{
    (void)args;
    return INJECT_ERR_HOST_NOT_SUPPORTED;
}

#endif

/* ------------------------------------------------------------------ */
/* main：仅 Windows 编译                                              */
/* ------------------------------------------------------------------ */
#if defined(_WIN32) && !defined(WIN7BRIDGE_HOST_TEST) && !defined(WIN7BRIDGE_SYNTAX_CHECK)

int main(int argc, char** argv)
{
    LoaderArgs args;
    int        rc;

    if (loader_parse_args(argc, argv, &args) != 0) {
        loader_print_help(argv[0], stderr);
        return 2;
    }
    if (args.help) {
        loader_print_help(argv[0], stdout);
        return 0;
    }
    if (args.exe_path == NULL) {
        fprintf(stderr, "缺少目标 EXE\n");
        loader_print_help(argv[0], stderr);
        return 2;
    }
    rc = loader_run(&args);
    return rc < 0 ? 1 : (rc & 0xFF);
}

#endif
