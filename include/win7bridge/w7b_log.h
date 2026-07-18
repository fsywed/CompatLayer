/*
 * w7b_log.h - Win7Bridge 细粒度日志框架接口
 *
 * 提供线程安全、平台无关、零外部依赖的日志记录能力。日志存于固定容量
 * 的环形缓冲区，按需通过 w7b_log_foreach 遍历或 w7b_log_dump_to_file
 * 落盘。设计目标见 docs/logging-framework.md。
 *
 * 四类关键事件：
 *   - API_INTERCEPT：inline hook 命中、GetProcAddress 重定向
 *   - MISSING_EXPORT：GetProcAddress 查询未识别的 Win10 新 API
 *   - ANTI_DEBUG：反调试检测点
 *   - VERSION_SPOOF：版本伪装命中
 *   - APISET：API set 映射查表命中
 *   - GENERAL：其他运行时事件
 *
 * 不依赖 <windows.h>。
 */
#ifndef WIN7BRIDGE_W7B_LOG_H
#define WIN7BRIDGE_W7B_LOG_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------ */
/* 日志级别                                                            */
/* ------------------------------------------------------------------ */
typedef enum {
    W7B_LOG_DEBUG = 0,   /* 调试细节                           */
    W7B_LOG_INFO  = 1,   /* 一般信息（默认级别）                */
    W7B_LOG_WARN  = 2,   /* 警告                                */
    W7B_LOG_ERROR = 3,   /* 错误                                */
} w7b_log_level;

/* ------------------------------------------------------------------ */
/* 日志类别                                                            */
/* ------------------------------------------------------------------ */
typedef enum {
    W7B_LOGCAT_GENERAL        = 0,  /* 通用运行时事件                */
    W7B_LOGCAT_API_INTERCEPT  = 1,  /* 被 hook 拦截的 API 调用       */
    W7B_LOGCAT_MISSING_EXPORT = 2,  /* GetProcAddress 缺失导出查询   */
    W7B_LOGCAT_ANTI_DEBUG     = 3,  /* 反调试触发点                  */
    W7B_LOGCAT_VERSION_SPOOF  = 4,  /* 版本伪装命中                  */
    W7B_LOGCAT_APISET         = 5,  /* API set 映射查表命中          */
} w7b_log_category;

/* ------------------------------------------------------------------ */
/* 日志条目                                                            */
/* ------------------------------------------------------------------ */
#define W7B_LOG_MSG_MAX  256   /* 消息文本最大字节数（含 NUL）        */

typedef struct {
    uint32_t          timestamp_ms;  /* GetTickCount()，0 表示未知    */
    w7b_log_level     level;
    w7b_log_category  category;
    const char*       module;        /* 模块名（静态字符串字面量）     */
    char              message[W7B_LOG_MSG_MAX];  /* 消息文本          */
} w7b_log_entry;

/* ------------------------------------------------------------------ */
/* 环形缓冲区容量                                                      */
/* ------------------------------------------------------------------ */
#define W7B_LOG_CAPACITY  512

/* ------------------------------------------------------------------ */
/* 公共 API                                                            */
/* ------------------------------------------------------------------ */

/*
 * w7b_log_init - 初始化全局日志缓冲区
 *   必须在使用其他日志 API 之前调用一次。重复调用是安全的（重置状态）。
 * 返回：0 成功；-1 出错（锁初始化失败等）。
 */
int w7b_log_init(void);

/*
 * w7b_log_shutdown - 关闭日志缓冲区，释放锁资源
 *   调用后日志缓冲区不可用，需重新 w7b_log_init 才能用。
 */
void w7b_log_shutdown(void);

/*
 * w7b_log_set_level - 设置最低记录级别
 *   低于该级别的日志被丢弃。默认 W7B_LOG_INFO。
 */
void w7b_log_set_level(w7b_log_level level);

/*
 * w7b_log_write - 写一条日志
 *   level   ：日志级别
 *   cat     ：日志类别
 *   module  ：模块名（应为静态字符串字面量；不复制，调用方保活）
 *   fmt/... ：printf 风格格式串与可变参数；最终消息截断到 W7B_LOG_MSG_MAX-1
 *   线程安全。
 */
void w7b_log_write(w7b_log_level level, w7b_log_category cat,
                   const char* module, const char* fmt, ...)
#if defined(__GNUC__) || defined(__clang__)
    __attribute__((format(printf, 4, 5)))
#endif
    ;

/*
 * w7b_log_foreach - 遍历日志条目（按时间顺序，最旧到最新）
 *   callback ：对每条调用；返回非 0 立即停止遍历
 *   ctx      ：透传给 callback 的上下文
 * 返回：实际遍历的条数。
 */
size_t w7b_log_foreach(int (*callback)(const w7b_log_entry* e, void* ctx),
                       void* ctx);

/*
 * w7b_log_dump_to_file - 把全部日志写到文件
 *   path：UTF-8 / ASCII 路径
 *   格式：[timestamp] LEVEL CATEGORY module: message
 * 返回：0 成功；-1 文件打开失败。
 */
int w7b_log_dump_to_file(const char* path);

/*
 * w7b_log_count - 取当前已记录条数
 *   上限为 W7B_LOG_CAPACITY。
 */
size_t w7b_log_count(void);

/* ------------------------------------------------------------------ */
/* 便捷宏                                                              */
/* ------------------------------------------------------------------ */
#define W7B_LOG_INFO(cat, mod, ...)  \
    w7b_log_write(W7B_LOG_INFO,  (cat), (mod), __VA_ARGS__)
#define W7B_LOG_WARN(cat, mod, ...)  \
    w7b_log_write(W7B_LOG_WARN,  (cat), (mod), __VA_ARGS__)
#define W7B_LOG_ERROR(cat, mod, ...) \
    w7b_log_write(W7B_LOG_ERROR, (cat), (mod), __VA_ARGS__)
#define W7B_LOG_DEBUG(cat, mod, ...) \
    w7b_log_write(W7B_LOG_DEBUG, (cat), (mod), __VA_ARGS__)

#ifdef __cplusplus
}
#endif

#endif /* WIN7BRIDGE_W7B_LOG_H */
