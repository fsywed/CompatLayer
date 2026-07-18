/*
 * loader.h - Win7Bridge Loader EXE 接口
 *
 * 【开发文档】
 *
 * 目的：win7bridge_loader.exe 的命令行入口，负责解析参数、串联
 *   inject 模块完成 DLL 注入。
 *
 * 分点展开：
 *   1. 用法：
 *        win7bridge_loader.exe [--dll <path>] [--workdir <dir>]
 *                              [--method remote_thread|apc]
 *                              [--verbose] [--help] <target.exe> [args...]
 *
 *   2. 默认值：
 *        --dll       win7bridge.dll（与 loader 同目录）
 *        --method    apc（回退为 remote_thread）
 *        --workdir   目标 EXE 所在目录
 *
 *   3. 平台隔离：loader_parse_args 为纯字符串解析，host 测试可调用；
 *      loader_run 调用 inject_launch，Windows 之外返回
 *      INJECT_ERR_HOST_NOT_SUPPORTED。
 */
#ifndef WIN7BRIDGE_LOADER_H
#define WIN7BRIDGE_LOADER_H

#include "win7bridge/inject.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------ */
/* LoaderArgs - 命令行解析结果                                         */
/* ------------------------------------------------------------------ */
typedef struct _LoaderArgs {
    const char* exe_path;     /* 目标 EXE 路径（必填）                  */
    const char* dll_path;     /* DLL 路径（默认 "win7bridge.dll"）       */
    const char* work_dir;     /* 工作目录（默认 NULL，用 EXE 所在目录） */
    const char* args;         /* 传给目标 EXE 的附加参数（NULL 表示无） */
    InjectMethod method;      /* 注入方法                              */
    int verbose;              /* 非 0 打印详细日志                     */
    int help;                 /* 非 0 表示请求 --help                  */
} LoaderArgs;

/* 默认值初始化。返回 0。*/
int loader_args_default(LoaderArgs* args);

/*
 * loader_parse_args - 解析命令行
 *   argv/argc：main 的参数（argv[0] 为程序名）
 *   out      ：解析结果（调用方分配）
 *   未知参数写到 stderr 并返回 -1；--help 设置 out->help=1 并返回 0。
 * 返回：0 成功；-1 出错。
 */
int loader_parse_args(int argc, char** argv, LoaderArgs* out);

/* 打印用法到 stream。*/
void loader_print_help(const char* prog, void* stream /* FILE* */);

/*
 * loader_run - 按 args 启动注入并等待目标进程退出
 *   返回目标进程退出码（0..255）；出错返回负值。
 */
int loader_run(const LoaderArgs* args);

#ifdef __cplusplus
}
#endif

#endif /* WIN7BRIDGE_LOADER_H */
