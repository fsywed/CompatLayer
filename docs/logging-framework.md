# 细粒度日志框架开发文档（Task 5.1.1）

## 简洁概要

为 win7bridge 增加统一的细粒度日志框架，记录四类关键事件：被拦截的 API、缺失导出查询、反调试触发点、版本伪装命中。日志以固定容量的环形缓冲区形式存储在内存中，按需落盘或通过诊断报告导出。日志接口线程安全、平台无关、零外部依赖。

## 分点展开

### 1. 日志事件分类

| 类别 (W7B_LOGCAT_*) | 触发点 | 示例 |
|---|---|---|
| `API_INTERCEPT` | inline hook 命中、GetProcAddress 重定向 | `BCryptOpenAlgorithmProvider("CHACHA20_POLY1305") -> local` |
| `MISSING_EXPORT` | GetProcAddress 查询未识别的 Win10 新 API | `GetProcAddress("D3D12CreateDevice") -> NOT FOUND` |
| `ANTI_DEBUG` | 反调试检测点（IsDebuggerPresent/NtQueryInfo 拦截） | `NtQueryInformationProcess(ProcessDebugPort) spoofed` |
| `VERSION_SPOOF` | GetVersionExW/VerifyVersionInfoW 命中伪装 | `GetVersionExW -> 10.0.19041` |
| `APISET` | API set 映射查表命中 | `api-ms-win-core-synch-l1-2-0 -> win7bridge_local` |
| `GENERAL` | 其他运行时事件 | `DLL attached, 12 hooks installed` |

### 2. 日志级别

```c
typedef enum {
    W7B_LOG_DEBUG = 0,
    W7B_LOG_INFO  = 1,
    W7B_LOG_WARN  = 2,
    W7B_LOG_ERROR = 3,
} w7b_log_level;
```

运行时按级别过滤，默认 `INFO`。可通过配置提升到 `DEBUG` 排障。

### 3. 日志条目结构

```c
typedef struct {
    uint32_t         timestamp_ms;   /* GetTickCount()，0 表示未知      */
    w7b_log_level    level;
    w7b_log_category category;
    const char*      module;         /* 模块名（静态字符串字面量）       */
    const char*      message;        /* 消息（指向 arena 或静态串）      */
} w7b_log_entry;
```

- 消息文本最长 256 字节（截断）
- 模块名只接受静态字符串字面量（不复制）
- timestamp 用 `GetTickCount`（Win7 已含），host 测试下用 `clock()`

### 4. 环形缓冲区设计

```c
#define W7B_LOG_CAPACITY  512   /* 最多保留 512 条                  */

typedef struct {
    w7b_log_entry entries[W7B_LOG_CAPACITY];
    size_t        head;          /* 下一个写入位置                    */
    size_t        count;         /* 已写入条数（饱和到 CAPACITY）     */
    w7b_log_level min_level;     /* 最低记录级别                      */
    /* 平台相关锁字段（Win7 下 CRITICAL_SECTION；host 下空操作）       */
    void*         lock_storage[8];
} w7b_log_buffer;
```

- 写满后覆盖最旧条目（ring）
- 读出按时间顺序遍历 `head` 起的 `min(count, CAPACITY)` 条

### 5. 公共 API

```c
/* 初始化全局日志缓冲区；返回 0 成功 */
int w7b_log_init(void);

/* 关闭日志缓冲区，释放锁资源 */
void w7b_log_shutdown(void);

/* 设置最低记录级别（运行时调级） */
void w7b_log_set_level(w7b_log_level level);

/* 写一条日志；module 应为字符串字面量；fmt 是 printf 风格 */
void w7b_log_write(w7b_log_level level, w7b_log_category cat,
                   const char* module, const char* fmt, ...);

/* 便捷宏 */
#define W7B_LOG_INFO(cat, mod, ...)  w7b_log_write(W7B_LOG_INFO,  cat, mod, __VA_ARGS__)
#define W7B_LOG_WARN(cat, mod, ...)  w7b_log_write(W7B_LOG_WARN,  cat, mod, __VA_ARGS__)
#define W7B_LOG_ERROR(cat, mod, ...) w7b_log_write(W7B_LOG_ERROR, cat, mod, __VA_ARGS__)
#define W7B_LOG_DEBUG(cat, mod, ...) w7b_log_write(W7B_LOG_DEBUG, cat, mod, __VA_ARGS__)

/* 遍历日志条目；callback 返回非 0 立即停止；返回遍历数 */
size_t w7b_log_foreach(int (*callback)(const w7b_log_entry* e, void* ctx),
                       void* ctx);

/* 把全部日志写到文件（标准 C fopen/fprintf/fclose） */
int w7b_log_dump_to_file(const char* path);

/* 取当前已记录条数 */
size_t w7b_log_count(void);
```

### 6. 线程安全

- Win7 目标下用 `CRITICAL_SECTION`（InitializeCriticalSection / EnterCriticalSection / LeaveCriticalSection）
- host 测试下锁为空操作（单线程）
- 用 `void* lock_storage[8]` 预留 64 字节，容纳 CRITICAL_SECTION（约 40 字节）
- 平台隔离通过 `#if defined(_WIN32) && !defined(WIN7BRIDGE_HOST_TEST)` 控制

### 7. 平台隔离

- `w7b_log.h` 不依赖 `<windows.h>`
- 时间戳获取在 `w7b_log.c` 内部分支：
  - Win7：`GetTickCount()`
  - host：`clock()` 转 ms
- 文件 IO 用标准 C `fopen/fprintf/fclose`

### 8. 与现有代码的整合

- `dllmain.c` 的 `DllMain` 在 `DLL_PROCESS_ATTACH` 阶段调 `w7b_log_init`、`DLL_PROCESS_DETACH` 调 `w7b_log_shutdown`
- 每个 hook 函数（`hook_GetProcAddress`、`hook_GetVersionExW` 等）插入 `W7B_LOG_INFO` 调用
- `apiset_resolve_imports` 命中时记一条 `APISET` 日志
- Task 5.1.2（诊断报告导出）会调用 `w7b_log_foreach` 或 `w7b_log_dump_to_file`

### 9. 测试用例（test_logging.c）

| # | 名称 | 验证点 |
|---|------|--------|
| 1 | 基本写入与遍历 | 写 3 条不同级别日志，foreach 数到 3 条 |
| 2 | 级别过滤 | min_level=WARN 时 DEBUG/INFO 不入缓冲区 |
| 3 | 环形覆盖 | 写入 CAPACITY+10 条后 count==CAPACITY |
| 4 | 多类别混合 | API_INTERCEPT/MISSING_EXPORT/VERSION_SPOOF 各一条 |
| 5 | 文件导出 | dump_to_file 后文件含全部日志文本 |
| 6 | 时间戳非零 | host 下 clock() 转 ms，timestamp_ms > 0 |
| 7 | 长消息截断 | >256 字节消息被截断且 NUL 结尾 |
| 8 | 重新初始化 | init→write→shutdown→init→write，count 重置 |

### 10. 与开发文档要求的对照

- `docs/dev-guide.md` §3 L4："细粒度日志（被拦截的 API、缺失导出、版本伪装命中）" — ✓ 全部四类支持
- `docs/dev-guide.md` §10："提交前快速语法检查，确保能编译" — ✓ 走 `make check` 与 `make test`
- 用户约束 "搜索更多win10的API，不依赖win7补丁" — ✓ 日志记录所有 Win10 API 拦截与缺失查询，便于发现需要本地实现的新 API
