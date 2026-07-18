/*
 * w7b_diag.c - Win7Bridge 一键诊断报告实现
 *
 * 设计目标见 docs/diag-report.md：聚合 engine / apiset / ucrt_check /
 * inline_hook / w7b_log 状态，输出单一 Markdown 文本。
 *
 * 实现要点：
 *   - 仅依赖 <stdio.h>/<string.h>/<time.h>，跨平台一致
 *   - 日志聚合通过 w7b_log_foreach 单次遍历得到计数 + 去重表，
 *     再做第二次遍历输出每条日志原文
 *   - 去重表上限 32 条；超出后仅置 overflow 标记，不再追加
 */
#include "win7bridge/w7b_diag.h"
#include "win7bridge/w7b_log.h"

#include <stdio.h>
#include <string.h>
#include <time.h>

/* ------------------------------------------------------------------ */
/* 日志聚合上下文                                                      */
/* ------------------------------------------------------------------ */
#define W7B_DIAG_DEDUP_MAX  32

typedef struct {
    const char* module;
    char        message[W7B_LOG_MSG_MAX];
} W7bDiagDedupEntry;

typedef struct {
    /* 各类别计数 */
    size_t cnt_general;
    size_t cnt_api_intercept;
    size_t cnt_missing_export;
    size_t cnt_anti_debug;
    size_t cnt_version_spoof;
    size_t cnt_apiset;
    size_t cnt_total;

    /* API_INTERCEPT 去重列表 */
    W7bDiagDedupEntry intercept[W7B_DIAG_DEDUP_MAX];
    size_t            intercept_count;
    int               intercept_overflow;

    /* MISSING_EXPORT 去重列表 */
    W7bDiagDedupEntry missing[W7B_DIAG_DEDUP_MAX];
    size_t            missing_count;
    int               missing_overflow;
} W7bDiagAgg;

/* 把一条 (module, message) 加入去重表；已存在则跳过，未满则追加 */
static void diag_dedup_add(W7bDiagDedupEntry* tbl, size_t cap,
                           size_t* count, int* overflow,
                           const char* module, const char* message)
{
    size_t i;
    if (*count >= cap) {
        *overflow = 1;
        return;
    }
    for (i = 0; i < *count; ++i) {
        if (((tbl[i].module == module) ||
             (tbl[i].module != NULL && module != NULL &&
              strcmp(tbl[i].module, module) == 0)) &&
            strcmp(tbl[i].message, message) == 0) {
            return;  /* 已存在 */
        }
    }
    tbl[*count].module = module;  /* module 为静态字面量，可直接保存指针 */
    strncpy(tbl[*count].message, message, W7B_LOG_MSG_MAX - 1);
    tbl[*count].message[W7B_LOG_MSG_MAX - 1] = 0;
    (*count)++;
}

/* w7b_log_foreach 回调：累加类别计数，维护去重表 */
static int agg_callback(const w7b_log_entry* e, void* ctx_)
{
    W7bDiagAgg* a = (W7bDiagAgg*)ctx_;
    ++a->cnt_total;
    switch (e->category) {
        case W7B_LOGCAT_GENERAL:
            ++a->cnt_general;
            break;
        case W7B_LOGCAT_API_INTERCEPT:
            ++a->cnt_api_intercept;
            diag_dedup_add(a->intercept, W7B_DIAG_DEDUP_MAX,
                           &a->intercept_count, &a->intercept_overflow,
                           e->module ? e->module : "",
                           e->message);
            break;
        case W7B_LOGCAT_MISSING_EXPORT:
            ++a->cnt_missing_export;
            diag_dedup_add(a->missing, W7B_DIAG_DEDUP_MAX,
                           &a->missing_count, &a->missing_overflow,
                           e->module ? e->module : "",
                           e->message);
            break;
        case W7B_LOGCAT_ANTI_DEBUG:
            ++a->cnt_anti_debug;
            break;
        case W7B_LOGCAT_VERSION_SPOOF:
            ++a->cnt_version_spoof;
            break;
        case W7B_LOGCAT_APISET:
            ++a->cnt_apiset;
            break;
        default:
            break;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* 完整日志遍历上下文（section 7）                                     */
/* ------------------------------------------------------------------ */
typedef struct {
    FILE* fp;
    int   error;
} DumpCtx;

static const char* diag_level_name(w7b_log_level l)
{
    switch (l) {
        case W7B_LOG_DEBUG: return "DEBUG";
        case W7B_LOG_INFO:  return "INFO";
        case W7B_LOG_WARN:  return "WARN";
        case W7B_LOG_ERROR: return "ERROR";
        default:            return "????";
    }
}

static const char* diag_category_name(w7b_log_category c)
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

static int dump_callback(const w7b_log_entry* e, void* ctx_)
{
    DumpCtx* d = (DumpCtx*)ctx_;
    if (fprintf(d->fp, "  [%u] %-5s %-15s %s: %s\n",
                (unsigned)e->timestamp_ms,
                diag_level_name(e->level),
                diag_category_name(e->category),
                e->module ? e->module : "",
                e->message) < 0) {
        d->error = 1;
        return 1;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* UCRT 状态名                                                        */
/* ------------------------------------------------------------------ */
static const char* ucrt_status_name(UcrtStatus s)
{
    switch (s) {
        case UCRT_OK:                return "UCRT_OK";
        case UCRT_MISSING_UCRTBASE:  return "UCRT_MISSING_UCRTBASE";
        case UCRT_MISSING_VCRUNTIME: return "UCRT_MISSING_VCRUNTIME";
        case UCRT_MISSING_MSVCPP:    return "UCRT_MISSING_MSVCPP";
        default:                     return "UNKNOWN";
    }
}

/* ------------------------------------------------------------------ */
/* 引擎规则类型名                                                     */
/* ------------------------------------------------------------------ */
static const char* rewrite_kind_name(RewriteKind k)
{
    switch (k) {
        case REWRITE_FORWARD_DLL:  return "FORWARD_DLL";
        case REWRITE_REPLACE_FUNC: return "REPLACE_FUNC";
        case REWRITE_STUB:         return "STUB";
        default:                   return "NONE";
    }
}

/* ------------------------------------------------------------------ */
/* 公共 API                                                            */
/* ------------------------------------------------------------------ */
int w7b_diag_export_report(const char* path, const W7bDiagInput* input)
{
    FILE*       fp;
    W7bDiagAgg  agg;
    DumpCtx     dump_ctx;
    time_t      now;
    struct tm   tm_now;
    char        time_buf[32];
    int         write_error = 0;
    size_t      i;

    if (path == NULL || input == NULL) {
        return -2;
    }

    fp = fopen(path, "wb");
    if (fp == NULL) {
        return -1;
    }

    /* 时间戳（UTC） */
    now = time(NULL);
    if (gmtime_r(&now, &tm_now) != NULL) {
        strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S UTC",
                 &tm_now);
    } else {
        strncpy(time_buf, "(unknown)", sizeof(time_buf) - 1);
        time_buf[sizeof(time_buf) - 1] = 0;
    }

    /* ---- 头部 ---- */
    if (fprintf(fp,
                "# Win7Bridge Diagnostic Report\n"
                "generated_at: %s    version: %s\n\n",
                time_buf, WIN7BRIDGE_VERSION_STRING) < 0) {
        write_error = 1;
    }

    /* ---- 1. Process ---- */
    if (!write_error) {
        if (fprintf(fp,
                    "## 1. Process\n"
                    "  target: %s\n"
                    "  arch:   %s\n\n",
                    input->target_exe ? input->target_exe : "(unset)",
                    input->target_arch ? input->target_arch : "(unset)") < 0) {
            write_error = 1;
        }
    }

    /* ---- 2. UCRT Status ---- */
    if (!write_error) {
        if (fprintf(fp,
                    "## 2. UCRT Status\n"
                    "  status: %s  message: %s\n\n",
                    ucrt_status_name(input->ucrt_status),
                    ucrt_status_message(input->ucrt_status)) < 0) {
            write_error = 1;
        }
    }

    /* ---- 3. API Set Map ---- */
    if (!write_error) {
        size_t to_real = 0, to_local = 0, unsolvable = 0;
        if (input->apiset != NULL) {
            for (i = 0; i < input->apiset->count; ++i) {
                const ApiSetEntry* e = &input->apiset->entries[i];
                switch (e->kind) {
                    case APISET_TO_REAL_DLL: ++to_real; break;
                    case APISET_TO_LOCAL:    ++to_local; break;
                    case APISET_UNSOLVABLE:  ++unsolvable; break;
                    default: break;
                }
            }
        }
        if (fprintf(fp,
                    "## 3. API Set Map\n"
                    "  entries: %zu\n"
                    "  - to_real_dll: %zu\n"
                    "  - to_local:    %zu\n"
                    "  - unsolvable:  %zu\n\n",
                    input->apiset ? input->apiset->count : 0,
                    to_real, to_local, unsolvable) < 0) {
            write_error = 1;
        }

        /* ---- 3.1 Unsolvable Entries (Dependency Missing Tree) ---- */
        if (!write_error) {
            if (fprintf(fp,
                        "### 3.1 Unsolvable Entries (Dependency Missing Tree)\n") < 0) {
                write_error = 1;
            }
            if (!write_error && unsolvable == 0) {
                if (fprintf(fp, "  (none)\n\n") < 0) write_error = 1;
            }
            if (!write_error && unsolvable > 0 && input->apiset != NULL) {
                for (i = 0; i < input->apiset->count && !write_error; ++i) {
                    const ApiSetEntry* e = &input->apiset->entries[i];
                    if (e->kind != APISET_UNSOLVABLE) continue;
                    if (fprintf(fp, "  - %s  host=%s  note=%s\n",
                                e->virtual_name ? e->virtual_name : "(null)",
                                e->host_dll ? e->host_dll : "",
                                e->note ? e->note : "") < 0) {
                        write_error = 1;
                    }
                }
                if (!write_error) {
                    if (fprintf(fp, "\n") < 0) write_error = 1;
                }
            }
        }
    }

    /* ---- 4. Engine Rules ---- */
    if (!write_error) {
        if (fprintf(fp,
                    "## 4. Engine Rules\n"
                    "  dll_redirects:  %zu\n"
                    "  func_redirects: %zu\n\n",
                    input->engine ? input->engine->dll_count : 0,
                    input->engine ? input->engine->func_count : 0) < 0) {
            write_error = 1;
        }

        /* 4.1 DLL Redirects */
        if (!write_error) {
            if (fprintf(fp, "### 4.1 DLL Redirects\n") < 0) write_error = 1;
            if (!write_error && input->engine != NULL) {
                for (i = 0; i < input->engine->dll_count && !write_error; ++i) {
                    const DllRedirect* r = &input->engine->dll_rules[i];
                    if (fprintf(fp, "  - %s -> %s\n",
                                r->orig_dll ? r->orig_dll : "(null)",
                                r->forward_dll ? r->forward_dll : "(null)") < 0) {
                        write_error = 1;
                    }
                }
            }
            if (!write_error && (input->engine == NULL ||
                                 input->engine->dll_count == 0)) {
                if (fprintf(fp, "  (none)\n") < 0) write_error = 1;
            }
            if (!write_error) {
                if (fprintf(fp, "\n") < 0) write_error = 1;
            }
        }

        /* 4.2 Function Redirects */
        if (!write_error) {
            if (fprintf(fp, "### 4.2 Function Redirects\n") < 0) write_error = 1;
            if (!write_error && input->engine != NULL) {
                for (i = 0; i < input->engine->func_count && !write_error; ++i) {
                    const ExportRedirect* r = &input->engine->func_rules[i];
                    if (fprintf(fp, "  - %s!%s  kind=%s  replacement=%p\n",
                                r->dll_name ? r->dll_name : "(null)",
                                r->func_name ? r->func_name : "(null)",
                                rewrite_kind_name(r->kind),
                                r->replacement) < 0) {
                        write_error = 1;
                    }
                }
            }
            if (!write_error && (input->engine == NULL ||
                                 input->engine->func_count == 0)) {
                if (fprintf(fp, "  (none)\n") < 0) write_error = 1;
            }
            if (!write_error) {
                if (fprintf(fp, "\n") < 0) write_error = 1;
            }
        }
    }

    /* ---- 5. Inline Hooks ---- */
    if (!write_error) {
        if (fprintf(fp,
                    "## 5. Inline Hooks\n"
                    "  installed: %zu\n",
                    input->hooks_count) < 0) {
            write_error = 1;
        }
        if (!write_error && input->hooks != NULL) {
            for (i = 0; i < input->hooks_count && !write_error; ++i) {
                const InlineHook* h = &input->hooks[i];
                if (fprintf(fp, "  - target=%p  detour=%p  patch_size=%zu\n",
                            h->target, h->detour, h->patch_size) < 0) {
                    write_error = 1;
                }
            }
        }
        if (!write_error && (input->hooks == NULL || input->hooks_count == 0)) {
            if (fprintf(fp, "  (none)\n") < 0) write_error = 1;
        }
        if (!write_error) {
            if (fprintf(fp, "\n") < 0) write_error = 1;
        }
    }

    /* ---- 6. Call Flow Summary（先聚合日志） ---- */
    if (!write_error) {
        memset(&agg, 0, sizeof(agg));
        w7b_log_foreach(agg_callback, &agg);

        if (fprintf(fp,
                    "## 6. Call Flow Summary (from log buffer)\n"
                    "  total log entries: %zu\n"
                    "  - API_INTERCEPT:   %zu   distinct APIs: %zu%s\n"
                    "  - MISSING_EXPORT:  %zu   distinct queries: %zu%s\n"
                    "  - ANTI_DEBUG:      %zu\n"
                    "  - VERSION_SPOOF:   %zu\n"
                    "  - APISET:          %zu\n"
                    "  - GENERAL:         %zu\n\n",
                    agg.cnt_total,
                    agg.cnt_api_intercept, agg.intercept_count,
                    agg.intercept_overflow ? " (overflow)" : "",
                    agg.cnt_missing_export, agg.missing_count,
                    agg.missing_overflow ? " (overflow)" : "",
                    agg.cnt_anti_debug,
                    agg.cnt_version_spoof,
                    agg.cnt_apiset,
                    agg.cnt_general) < 0) {
            write_error = 1;
        }

        /* 6.1 Intercepted APIs (distinct) */
        if (!write_error) {
            if (fprintf(fp, "### 6.1 Intercepted APIs (distinct)\n") < 0) {
                write_error = 1;
            }
            for (i = 0; i < agg.intercept_count && !write_error; ++i) {
                if (fprintf(fp, "  - %s: %s\n",
                            agg.intercept[i].module ? agg.intercept[i].module : "",
                            agg.intercept[i].message) < 0) {
                    write_error = 1;
                }
            }
            if (!write_error && agg.intercept_count == 0) {
                if (fprintf(fp, "  (none)\n") < 0) write_error = 1;
            }
            if (!write_error) {
                if (fprintf(fp, "\n") < 0) write_error = 1;
            }
        }

        /* 6.2 Missing Export Queries (distinct) */
        if (!write_error) {
            if (fprintf(fp, "### 6.2 Missing Export Queries (distinct)\n") < 0) {
                write_error = 1;
            }
            for (i = 0; i < agg.missing_count && !write_error; ++i) {
                if (fprintf(fp, "  - %s: %s\n",
                            agg.missing[i].module ? agg.missing[i].module : "",
                            agg.missing[i].message) < 0) {
                    write_error = 1;
                }
            }
            if (!write_error && agg.missing_count == 0) {
                if (fprintf(fp, "  (none)\n") < 0) write_error = 1;
            }
            if (!write_error) {
                if (fprintf(fp, "\n") < 0) write_error = 1;
            }
        }
    }

    /* ---- 7. Full Log Dump ---- */
    if (!write_error) {
        if (fprintf(fp, "## 7. Full Log Dump\n") < 0) {
            write_error = 1;
        }
        if (!write_error) {
            dump_ctx.fp    = fp;
            dump_ctx.error = 0;
            w7b_log_foreach(dump_callback, &dump_ctx);
            if (dump_ctx.error) write_error = 1;
        }
        if (!write_error) {
            if (fprintf(fp, "\n# end of report\n") < 0) write_error = 1;
        }
    }

    fclose(fp);
    return write_error ? -1 : 0;
}
