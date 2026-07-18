# Win7Bridge 按程序粒度配置存储（SubTask 3.4.1）开发文档

> Spec 要求（tasks.md SubTask 3.4.1）："实现按程序粒度配置存储（配置文件，
> 不写 HKLM 系统键）"。本任务提供配置文件读写 API，支撑后续 GUI（3.4.2）与
> 自动推荐（3.4.3）；不实现 GUI 本身。
>
> 设计原则：
> - **不写 HKLM**：所有配置存到 per-user 文件目录（Win7 `%APPDATA%`，
>   host 测试用临时目录）。规避 UAC 提权与系统键污染。
> - **一程序一文件**：每个目标 EXE 对应一份独立 JSON，按 EXE 基名命名，
>   便于人工查看/备份/迁移。
> - **schema 与 config_gen.py 对齐**：复用 `win7bridge.config/v1`，并把
>   config_gen.py 输出的 `pe_fixes` / `version_spoof` / `injection` 等
>   字段子集落地为运行期可读写的字段。

## 1. 目标

- 提供 C API：根据目标 EXE 路径计算配置文件路径、加载、保存、写默认值。
- 字段覆盖：启用开关、注入路径、版本伪装、PE 修复、日志级别、诊断报告开关、
  apiset 覆盖文件列表。
- 平台隔离：Win7 用 `GetEnvironmentVariableA("APPDATA")`；host 用 `getenv`。
- 单测覆盖：默认值、路径计算、round-trip save/load、缺文件、坏 JSON、字段覆盖。

## 2. 接口

新增头 `include/win7bridge/w7b_config.h`：

```c
/* 每个目标 EXE 一份配置；字段为零值时表示"用默认" */
typedef struct {
    char    exe_path[512];         /* 目标 EXE 全路径                   */
    char    exe_basename[256];     /* 仅基名（含 .exe）                 */
    int     enabled;               /* 是否启用兼容层（默认 1）          */
    char    injection_path[32];    /* "loader" / "pe_patch" / "appinit" */
    int     version_spoof_enabled; /* 默认 1                            */
    int     spoof_major;           /* 默认 10                           */
    int     spoof_minor;           /* 默认 0                            */
    int     spoof_build;           /* 默认 19041                        */
    int     fix_subsystem_version; /* 默认 1                            */
    int     strip_bound_imports;   /* 默认 1                            */
    int     log_level;             /* 0=DEBUG 1=INFO 2=WARN 3=ERROR     */
    int     diag_report_on_exit;   /* 默认 0                            */
    char    diag_report_path[512]; /* 空=用默认路径                     */
    char    apiset_overlays[8][256];
    size_t  apiset_overlays_count;
} W7bProgramConfig;

/* 推荐配置目录（per-user，不写 HKLM）：
 *   Win7:  %APPDATA%\Win7Bridge\configs\
 *   host:  ./win7bridge_configs/   (相对当前工作目录)
 * 返回 0 成功；-1 缓冲区不足或获取失败。
 */
int w7b_config_default_dir(char* out, size_t out_cap);

/* 根据目标 EXE 路径 + 配置目录，计算配置文件路径：
 *   <config_dir>\<exe_basename>.json
 * exe_path 可为 NULL（仅用 basename 字段）；config_dir 可为 NULL（用 default）。
 * 返回 0 成功；-1 缓冲区不足。 */
int w7b_config_path_for(const char* exe_path,
                        const char* config_dir,
                        char* out, size_t out_cap);

/* 用默认值填充 cfg；exe_path 可为 NULL。 */
void w7b_config_set_defaults(W7bProgramConfig* cfg, const char* exe_path);

/* 从 JSON 文件加载；exe_path 写入 cfg.exe_path（用于运行期校验身份）。
 * 返回：0 成功；1 文件不存在（用默认值填充，不视为错误）；
 *      -1 解析或 IO 失败（用默认值填充）。 */
int w7b_config_load(const char* path, W7bProgramConfig* cfg);

/* 把 cfg 序列化为 JSON 写到 path（覆盖）。
 * 返回：0 成功；-1 IO 失败。 */
int w7b_config_save(const char* path, const W7bProgramConfig* cfg);
```

## 3. JSON schema

输出/输入 JSON 兼容 `win7bridge.config/v1`（与 `scripts/config_gen.py` 一致），
但仅保留运行期需要的字段；config_gen.py 输出的 `pe` / `api_set_mapping` /
`api_emulation` / `manifest` / `unresolvable` / `warnings` 等运行期不直接消费的
字段，加载时跳过（向前兼容），保存时不写出（避免与 config_gen.py 输出冲突）。

```json
{
  "schema": "win7bridge.config/v1",
  "exe_path": "C:\\games\\foo.exe",
  "exe_basename": "foo.exe",
  "enabled": true,
  "injection_path": "loader",
  "version_spoof": {
    "enabled": true,
    "major": 10,
    "minor": 0,
    "build": 19041
  },
  "pe_fixes": {
    "fix_subsystem_version": true,
    "strip_bound_imports": true
  },
  "log_level": "info",
  "diag_report": {
    "on_exit": false,
    "path": ""
  },
  "apiset_overlays": [
    "apiset-extra.json"
  ]
}
```

## 4. 解析策略

- 复用 apiset.c 的极简递归下降思路：`JsonParser` 结构 + 跳过空白/注释 +
  按字段名分发到具体类型解析。
- 未知字段一律 `json_skip_value` 跳过（向前兼容）。
- 字符串解析复用 apiset.c 的转义处理逻辑；由于不复用 apiset.c 的 arena，
  本模块字符串直接拷到固定缓冲区并截断。
- log_level 字符串映射：`debug`/`info`/`warn`/`error` -> 0/1/2/3。
- 保存时按上面 schema 顺序写出，缩进 2 空格，CRLF 不强制（用 `\n`）。

## 5. 平台隔离

- Win7：`GetEnvironmentVariableA("APPDATA", buf, cap)`；CRT `fopen` 写文件。
- host：`getenv("APPDATA")` 失败回退 `getenv("HOME")`；都失败用 `./`。
- 不引入新 extern Win32 声明；与 w7b_log 同样用
  `#if defined(_WIN32) && !defined(WIN7BRIDGE_HOST_TEST)` 分支。

## 6. 错误处理

- `w7b_config_load`：文件不存在返回 1（默认值），解析失败返回 -1（默认值）。
  调用方据此决定是否提示用户"配置缺失"。
- `w7b_config_save`：IO 失败返回 -1，不写半截文件（先写临时文件再 rename）。
- 路径缓冲不足：返回 -1，不截断（避免写出半路径）。

## 7. 集成点

- `dllmain.c` 在 `DllMain(DLL_PROCESS_ATTACH)` 时根据目标 EXE 路径调用
  `w7b_config_path_for` → `w7b_config_load`，按 `cfg` 配置 engine / apiset /
  spoof / log level。本任务暂不实现该集成，仅提供 API。
- `scripts/config_gen.py` 后续可加 `--save` 选项直接调用 `w7b_config_save` 的
  等价 Python 实现；目前保留 Python 与 C 双轨。

## 8. 测试用例（tests/test_config.c）

1. **set_defaults**：cfg 各字段填默认值（enabled=1, spoof_build=19041, ...）。
2. **default_dir**：`w7b_config_default_dir` 返回非空字符串、以 `/` 或 `\` 结尾。
3. **path_for**：exe=`C:\games\foo.exe`, dir=`/tmp/cfgs` ->
   `/tmp/cfgs/foo.exe.json`（路径分隔符按平台）。
4. **round-trip**：set_defaults + 修改若干字段 + save + load + 字段相等。
5. **load missing**：路径不存在 -> 返回 1，cfg 用默认值填充。
6. **load bad JSON**：写一份坏 JSON -> 返回 -1，cfg 仍用默认值填充。
7. **load with unknown fields**：JSON 含 `api_emulation` 等未知字段 -> 跳过，
   已知字段仍正确解析。
8. **apiset_overlays round-trip**：3 条 overlay 路径 save + load 后保持。
9. **save to bad path**：`/nonexistent_dir/x.json` -> 返回 -1。
