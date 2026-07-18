# Win7Bridge 一键诊断报告（SubTask 5.1.2）开发文档

> 配套 `docs/logging-framework.md`：日志框架（5.1.1）已落地，本任务在其之上提供
> 一键导出的"诊断报告"，聚合运行期各模块状态，输出人类可读的 Markdown 文本。
>
> Spec 要求（tasks.md SubTask 5.1.2）："实现一键导出诊断报告（依赖缺失树、
> 调用流摘要）"。

## 1. 目标

- 一键导出单一文本文件，包含：进程信息、UCRT 检测、API Set 状态、engine 规则、
  inline hook 状态、**依赖缺失树**、**调用流摘要**、完整日志。
- 不引入新外部依赖；仅 `<stdio.h>` / `<string.h>` / `<time.h>`。
- 平台隔离同 w7b_log：host 下 `time()` 取时间戳；Win7 下复用 `GetTickCount`。
- 单测覆盖：空输入、各 section 写入、依赖缺失树聚合、调用流摘要聚合。

## 2. 接口

新增头 `include/win7bridge/w7b_diag.h`：

```c
typedef struct {
    const char*          target_exe;       /* 可空：目标 EXE 路径           */
    const char*          target_arch;      /* 可空："x86" / "x64"           */
    UcrtStatus           ucrt_status;      /* UCRT_OK 表示未检测            */
    const ApiSetMap*     apiset;           /* 可空                          */
    const RewriteEngine* engine;           /* 可空                          */
    const InlineHook*    hooks;            /* 可空数组                      */
    size_t               hooks_count;
} W7bDiagInput;

/* 一键导出诊断报告
 *   path ：输出文件路径（UTF-8 / ASCII）
 *   input：聚合输入；各字段可空（NULL / 0），对应 section 跳过
 * 返回：0 成功；-1 文件打开失败；-2 入参非法。
 * 注意：不负责初始化日志框架；调用方应先 w7b_log_init。
 */
int w7b_diag_export_report(const char* path, const W7bDiagInput* input);
```

## 3. 报告结构

输出文本采用 Markdown 风格节标题（`## ...`），便于人类阅读与后续工具解析：

```
# Win7Bridge Diagnostic Report
generated_at: <YYYY-MM-DD HH:MM:SS>    version: 0.1.0

## 1. Process
  target: <target_exe or "(unset)">
  arch:   <target_arch or "(unset)">

## 2. UCRT Status
  status: <name>  message: <text>

## 3. API Set Map
  entries: <count>
  - to_real_dll: <n>
  - to_local:    <n>
  - unsolvable:  <n>

### 3.1 Unsolvable Entries (Dependency Missing Tree)
  - <virtual_name>  host=<host_dll or "">  note=<note>
  - ...

## 4. Engine Rules
  dll_redirects:  <n>
  func_redirects: <n>

### 4.1 DLL Redirects
  - <orig> -> <forward>
  - ...

### 4.2 Function Redirects
  - <dll>!<func>  kind=<kind>  replacement=<ptr>
  - ...

## 5. Inline Hooks
  installed: <hooks_count>
  - target=<ptr>  detour=<ptr>  patch_size=<n>
  - ...

## 6. Call Flow Summary (from log buffer)
  total log entries: <n>
  - API_INTERCEPT:   <n>   distinct APIs: <m>
  - MISSING_EXPORT:  <n>   distinct queries: <m>
  - ANTI_DEBUG:      <n>
  - VERSION_SPOOF:   <n>
  - APISET:          <n>
  - GENERAL:         <n>

### 6.1 Intercepted APIs (distinct)
  - <module>: <message>
  - ...

### 6.2 Missing Export Queries (distinct)
  - <module>: <message>
  - ...

## 7. Full Log Dump
  [ts] LEVEL CATEGORY module: message
  ...
```

## 4. 聚合策略

- 通过 `w7b_log_foreach` 单次遍历，配合回调上下文统计：
  - `W7bDiagAgg` 结构含各类别计数；两个去重表：
    `intercepted[32]` 与 `missing[32]`，每条记录 `(module, message)` 指针对。
  - 去重表上限 32；超出的仅计数（`distinct_overflow=1`），列出前 32 条。
- 去重比较：module 与 message 均按字符串完全相等。
  日志条目 module 为字面量、message 已截断定长，可直接用 `==` 比较指针不安全
  （不同条目 message 数组位置不同），改用 `strcmp`。
- 回调对每条日志：按 category 累加；若为 API_INTERCEPT / MISSING_EXPORT，
  扫描对应去重表，未命中则追加。

## 5. 平台隔离

- 时间戳：host 用 `time(NULL)` + `gmtime` 输出 UTC；Win7 真实目标同样可用
  `<time.h>`（CRT 在 Win7 可用，无需 windows.h）。
- 不引入新 extern 声明；所有 Win7 专有路径已在 w7b_log 隔离。
- 报告写文件用 `fopen("wb")`，跨平台一致。

## 6. 错误处理

- `path == NULL` 或 `input == NULL` 返回 -2。
- `fopen` 失败返回 -1。
- 各 section 内部失败（如 fprintf 返回负）记录到 `ctx->error`，最终返回 -1。
- 即使某 section 失败也继续写后续 section，便于排查。

## 7. 集成点

- `dllmain.c` 在 `DllMain(DLL_PROCESS_DETACH)` 时若环境变量
  `WIN7BRIDGE_DIAG_REPORT` 设置，则调用 `w7b_diag_export_report` 落盘。
  （本任务暂不实现该集成，仅提供 API；集成留给后续阶段。）

## 8. 测试用例（tests/test_diag.c）

1. **空输入**：input 各字段为 NULL/0，报告仍含 header + 各 section 标题。
2. **进程信息**：target_exe / target_arch 写入 section 1。
3. **UCRT 状态**：UCRT_MISSING_UCRTBASE 写入 section 2 含提示。
4. **API Set 状态**：构造 ApiSetMap（load_default + 1 条 UNSOLVABLE），
   section 3 含 count 与 unsolvable 列表。
5. **Engine 规则**：add 2 条 dll_redirect + 1 条 func_redirect，section 4 列出。
6. **Inline hooks**：传 2 个 InlineHook（target/detour 任意非 NULL），section 5 列出。
7. **调用流摘要 + 去重**：写 5 条日志（3 条 API_INTERCEPT 含 2 个不同 API，
   2 条 MISSING_EXPORT 含 1 个重复查询），section 6 含正确计数与去重列表。
8. **完整日志**：section 7 含每条日志原文。
9. **文件打开失败**：path="/nonexistent_dir/x.log" 返回 -1。
