/*
 * w7b_log.c - Win7Bridge 细粒度日志框架实现
 *
 * 设计目标见 docs/logging-framework.md：
 *   - 固定容量环形缓冲区（W7B_LOG_CAPACITY 条）
 *   - 线程安全（Win7 CRITICAL_SECTION；host 下空操作）
 *   - 平台无关（不依赖 windows.h；时间戳分支：Win7 GetTickCount / host clock）
 *   - printf 风格消息，截断到 W7B_LOG_MSG_MAX-1
 *
 * 全局状态：单一 w7b_log_buffer g_log；通过 init/shutdown 管理生命周期。
 */
#include "win7bridge/w7b_log.h"

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <time.h>

/* ------------------------------------------------------------------ */
/* 平台隔离                                                            */
/* ------------------------------------------------------------------ */
#if defined(_WIN32) && !defined(WIN7BRIDGE_HOST_TEST)
/* Win7 真实目标：CRITICAL_SECTION + GetTickCount */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

typedef CRITICAL_SECTION w7b_critsec;

#define W7B_LOG_LOCK_INIT(cs)   InitializeCriticalSection(&(cs))
#define W7B_LOG_LOCK_DELETE(cs) DeleteCriticalSection(&(cs))
#define W7B_LOCK(cs)            EnterCriticalSection(&(cs))
#define W7B_UNLOCK(cs)          LeaveCriticalSection(&(cs))
#define W7B_LOG_TIMESTAMP_MS()  ((uint32_t)GetTickCount())
#else
/* host 测试或 syntax-check：锁为空操作，时间戳用 clock() */
typedef struct {
    char _unused;
} w7b_critsec;

#define W7B_LOG_LOCK_INIT(cs)   ((void)0)
#define W7B_LOG_LOCK_DELETE(cs) ((void)0)
#define W7B_LOCK(cs)            ((void)0)
#define W7B_UNLOCK(cs)          ((void)0)

static uint32_t w7b_log_timestamp_ms_host(void)
{
    return (uint32_t)((clock() * 1000) / CLOCKS_PER_SEC);
}
#define W7B_LOG_TIMESTAMP_MS()  w7b_log_timestamp_ms_host()
#endif

/* ------------------------------------------------------------------ */
/* 全局日志缓冲区                                                      */
/* ------------------------------------------------------------------ */
typedef struct {
    w7b_log_entry  entries[W7B_LOG_CAPACITY];
    size_t         head;        /* 下一个写入位置（环形）              */
    size_t         count;       /* 已写入条数（饱和到 CAPACITY）       */
    w7b_log_level  min_level;   /* 最低记录级别                        */
    w7b_critsec    lock;        /* 平台锁                              */
    int            initialized; /* 0=未初始化；1=已初始化              */
} w7b_log_buffer;

static w7b_log_buffer g_log;

/* ------------------------------------------------------------------ */
/* 内部辅助                                                            */
/* ------------------------------------------------------------------ */

/* 级别名称（用于 dump_to_file） */
static const char* level_name(w7b_log_level l)
{
    switch (l) {
        case W7B_LOG_DEBUG: return "DEBUG";
        case W7B_LOG_INFO:  return "INFO";
        case W7B_LOG_WARN:  return "WARN";
        case W7B_LOG_ERROR: return "ERROR";
        default:            return "????";
    }
}

/* 类别名称（用于 dump_to_file） */
static const char* category_name(w7b_log_category c)
{
    switch (c) {
        case W7B_LOGCAT_GENERAL:        return "GENERAL";
        case W7B_LOGCAT_API_INTERCEPT:  return "API_INTERCEPT";
        case W7B_LOGCAT_MISSING_EXPORT: return "MISSING_EXPORT";
        case W7B_LOGCAT_ANTI_DEBUG:     return "ANTI_DEBUG";
        case W7B_LOGCAT_VERSION_SPOOF:  return "VERSION_SPOOF";
        case W7B_LOGCAT_APISET:         return "APISET";
        default:                        return "UNKNOWN";
    }
}

/* 把 vsnprintf 结果拷贝到固定缓冲区并截断 */
static void copy_truncated(char* dst, size_t dst_cap,
                           const char* fmt, va_list ap)
{
    int n;
    if (dst_cap == 0) return;
    /* vsnprintf 在 host 下返回所需长度；MSVCRT 在 _WIN32 下返回 -1
       当缓冲不足时；二者都通过截断到 dst_cap-1 处理。 */
    n = vsnprintf(dst, dst_cap, fmt, ap);
    if (n < 0) {
        /* 旧式 MSVCRT：缓冲不足，无法确定长度；保证 NUL 结尾 */
        dst[dst_cap - 1] = 0;
    } else if ((size_t)n >= dst_cap) {
        /* 截断 */
        dst[dst_cap - 1] = 0;
    }
    /* 否则 n < dst_cap，dst 已正确 NUL 结尾 */
}

/* ------------------------------------------------------------------ */
/* 公共 API                                                            */
/* ------------------------------------------------------------------ */

int w7b_log_init(void)
{
    /* 已初始化则先清理 */
    if (g_log.initialized) {
        W7B_LOG_LOCK_DELETE(g_log.lock);
    }
    memset(&g_log, 0, sizeof(g_log));
    g_log.min_level   = W7B_LOG_INFO;
    g_log.initialized = 1;
    W7B_LOG_LOCK_INIT(g_log.lock);
    return 0;
}

void w7b_log_shutdown(void)
{
    if (!g_log.initialized) return;
    W7B_LOCK(g_log.lock);
    W7B_LOG_LOCK_DELETE(g_log.lock);
    memset(&g_log, 0, sizeof(g_log));
    /* 注意：DeleteCriticalSection 之后 memset；shutdown 后 initialized=0 */
}

void w7b_log_set_level(w7b_log_level level)
{
    if (!g_log.initialized) return;
    W7B_LOCK(g_log.lock);
    g_log.min_level = level;
    W7B_UNLOCK(g_log.lock);
}

void w7b_log_write(w7b_log_level level, w7b_log_category cat,
                   const char* module, const char* fmt, ...)
{
    va_list ap;
    w7b_log_entry* e;

    if (!g_log.initialized) return;
    if (level < g_log.min_level) return;
    if (fmt == NULL) return;

    W7B_LOCK(g_log.lock);

    e = &g_log.entries[g_log.head];
    e->timestamp_ms = W7B_LOG_TIMESTAMP_MS();
    e->level        = level;
    e->category     = cat;
    e->module       = (module != NULL) ? module : "";

    va_start(ap, fmt);
    copy_truncated(e->message, W7B_LOG_MSG_MAX, fmt, ap);
    va_end(ap);

    g_log.head = (g_log.head + 1) % W7B_LOG_CAPACITY;
    if (g_log.count < W7B_LOG_CAPACITY) {
        ++g_log.count;
    }

    W7B_UNLOCK(g_log.lock);
}

size_t w7b_log_foreach(int (*callback)(const w7b_log_entry* e, void* ctx),
                       void* ctx)
{
    size_t visited = 0;
    size_t i;
    size_t start;

    if (!g_log.initialized || callback == NULL) return 0;

    W7B_LOCK(g_log.lock);

    if (g_log.count < W7B_LOG_CAPACITY) {
        /* 缓冲未满：从 0 开始的 count 条 */
        start = 0;
    } else {
        /* 缓冲已满：从 head 开始的 CAPACITY 条（最旧） */
        start = g_log.head;
    }

    for (i = 0; i < g_log.count; ++i) {
        size_t idx = (start + i) % W7B_LOG_CAPACITY;
        int rc;
        /* callback 内部一般不调用 w7b_log_*；若调用会重入锁，
           Win7 CRITICAL_SECTION 支持递归，host 下锁为空操作也安全 */
        rc = callback(&g_log.entries[idx], ctx);
        ++visited;
        if (rc != 0) break;
    }

    W7B_UNLOCK(g_log.lock);
    return visited;
}

/* dump_to_file 的遍历上下文 */
typedef struct {
    FILE* fp;
    int   error;
} dump_ctx;

static int dump_callback(const w7b_log_entry* e, void* ctx_)
{
    dump_ctx* dc = (dump_ctx*)ctx_;
    if (fprintf(dc->fp, "[%u] %-5s %-15s %s: %s\n",
                (unsigned)e->timestamp_ms,
                level_name(e->level),
                category_name(e->category),
                e->module ? e->module : "",
                e->message) < 0) {
        dc->error = 1;
        return 1;
    }
    return 0;
}

int w7b_log_dump_to_file(const char* path)
{
    dump_ctx dc;
    size_t   n;

    if (path == NULL) return -1;
    if (!g_log.initialized) return -1;

    dc.fp    = fopen(path, "wb");
    dc.error = 0;
    if (dc.fp == NULL) return -1;

    fprintf(dc.fp, "# Win7Bridge log dump\n");
    fprintf(dc.fp, "# entries: %lu / %d\n\n",
            (unsigned long)g_log.count, W7B_LOG_CAPACITY);

    n = w7b_log_foreach(dump_callback, &dc);
    fclose(dc.fp);

    if (dc.error) return -1;
    (void)n;
    return 0;
}

size_t w7b_log_count(void)
{
    size_t c;
    if (!g_log.initialized) return 0;
    W7B_LOCK(g_log.lock);
    c = g_log.count;
    W7B_UNLOCK(g_log.lock);
    return c;
}
