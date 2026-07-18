/*
 * w7b_config.h - Win7Bridge 按程序粒度配置存储接口
 *
 * 每个目标 EXE 一份 JSON 配置文件，存于 per-user 目录（不写 HKLM 系统键）。
 * schema 与 scripts/config_gen.py 输出的 win7bridge.config/v1 兼容；运行期
 * 不直接消费的字段（pe / api_set_mapping / api_emulation / manifest /
 * unresolvable / warnings）加载时跳过、保存时不写出，避免与 config_gen.py
 * 输出冲突。
 *
 * 设计目标见 docs/per-program-config.md。不依赖 <windows.h>。
 */
#ifndef WIN7BRIDGE_W7B_CONFIG_H
#define WIN7BRIDGE_W7B_CONFIG_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------ */
/* 配置结构                                                            */
/* ------------------------------------------------------------------ */
#define W7B_CONFIG_EXE_PATH_MAX        512
#define W7B_CONFIG_BASENAME_MAX        256
#define W7B_CONFIG_INJECTION_PATH_MAX  32
#define W7B_CONFIG_DIAG_PATH_MAX       512
#define W7B_CONFIG_OVERLAY_MAX         8
#define W7B_CONFIG_OVERLAY_PATH_MAX    256

typedef struct {
    char    exe_path[W7B_CONFIG_EXE_PATH_MAX];        /* 目标 EXE 全路径  */
    char    exe_basename[W7B_CONFIG_BASENAME_MAX];    /* 仅基名（含 .exe）*/
    int     enabled;                 /* 是否启用兼容层（默认 1）          */
    char    injection_path[W7B_CONFIG_INJECTION_PATH_MAX];
                                     /* "loader" / "pe_patch" / "appinit" */
    int     version_spoof_enabled;   /* 默认 1                            */
    int     spoof_major;             /* 默认 10                           */
    int     spoof_minor;             /* 默认 0                            */
    int     spoof_build;             /* 默认 19041                        */
    int     fix_subsystem_version;   /* 默认 1                            */
    int     strip_bound_imports;     /* 默认 1                            */
    int     log_level;               /* 0=DEBUG 1=INFO 2=WARN 3=ERROR     */
    int     diag_report_on_exit;     /* 默认 0                            */
    char    diag_report_path[W7B_CONFIG_DIAG_PATH_MAX];
                                     /* 空=用默认路径                     */
    char    apiset_overlays[W7B_CONFIG_OVERLAY_MAX][W7B_CONFIG_OVERLAY_PATH_MAX];
    size_t  apiset_overlays_count;
} W7bProgramConfig;

/* ------------------------------------------------------------------ */
/* API                                                                 */
/* ------------------------------------------------------------------ */

/*
 * w7b_config_default_dir - 推荐配置目录（per-user，不写 HKLM）
 *   Win7:  %APPDATA%\Win7Bridge\configs\
 *   host:  ./win7bridge_configs/   (相对当前工作目录)
 * 返回 0 成功；-1 缓冲区不足或获取失败。
 */
int w7b_config_default_dir(char* out, size_t out_cap);

/*
 * w7b_config_path_for - 根据目标 EXE 路径计算配置文件路径
 *   <config_dir>/<exe_basename>.json
 *   exe_path   ：可为 NULL（此时 cfg 的 exe_basename 字段需已填好）
 *   config_dir ：可为 NULL（用 default_dir）
 *   out        ：接收 NUL 结尾路径
 *   out_cap    ：out 缓冲区容量（含 NUL）
 * 返回 0 成功；-1 缓冲区不足或入参非法。
 */
int w7b_config_path_for(const char* exe_path,
                        const char* config_dir,
                        char* out, size_t out_cap);

/*
 * w7b_config_set_defaults - 用默认值填充 cfg
 *   exe_path 可为 NULL；非空时同时填 exe_path 与 exe_basename
 */
void w7b_config_set_defaults(W7bProgramConfig* cfg, const char* exe_path);

/*
 * w7b_config_load - 从 JSON 文件加载
 *   path ：JSON 文件路径
 *   cfg  ：接收配置；解析前先用 set_defaults 填默认值
 * 返回：0 成功；1 文件不存在（用默认值填充）；-1 解析或 IO 失败（默认值）。
 */
int w7b_config_load(const char* path, W7bProgramConfig* cfg);

/*
 * w7b_config_save - 把 cfg 序列化为 JSON 写到 path（覆盖）
 * 返回：0 成功；-1 IO 失败。
 */
int w7b_config_save(const char* path, const W7bProgramConfig* cfg);

#ifdef __cplusplus
}
#endif

#endif /* WIN7BRIDGE_W7B_CONFIG_H */
