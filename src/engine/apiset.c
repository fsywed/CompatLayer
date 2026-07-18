/*
 * apiset.c - Win7Bridge L2 API Set 虚拟解析层实现
 *
 * 维护"虚拟名 → 实现源"映射表，对 PE 导入表中出现的 api-ms-win-* /
 * ext-ms-win-* 虚拟名查表，决定转发目标：
 *   - TO_REAL_DLL：转发到 Win7 真实 DLL（kernel32.dll / ole32.dll /
 *     ucrtbase.dll 等），由 L1 engine 改写导入表 DLL 名
 *   - TO_LOCAL：转发到本兼容层模拟实现（如 WaitOnAddress 体系）
 *   - UNSOLVABLE：不可解（WinRT / AVX xstate / 未知 ext-ms-win-*），
 *     上层需报告并放弃加载
 *
 * 设计要点：
 *   - 映射表用动态数组（realloc 扩容），字符串由调用方保活
 *   - apiset_load_default 用静态字符串字面量，永久保活
 *   - 大小写不敏感比较：自实现，避免依赖非标准 strings.h
 *   - 边界检查：所有 RVA 解析复用 pe.c 同样的检查风格
 *
 * JSON 配置加载（apiset_load_from_json/file）：
 *   - 极简递归下降解析器，纯 C，零外部依赖
 *   - 解析后的字符串统一存入 malloc 的 arena，由 apiset_free_arena 释放
 *   - 格式见 docs/apiset-json-config.md
 */
#include "win7bridge/apiset.h"

#include <stdio.h>   /* fopen/fread/fclose for apiset_load_from_file */
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------ */
/* 内部辅助                                                            */
/* ------------------------------------------------------------------ */

/* 大小写不敏感字符串相等比较（与 engine_ieq 风格一致）                */
static int apiset_ieq(const char* a, const char* b)
{
    if (a == b) return 1;
    if (a == NULL || b == NULL) return 0;
    while (*a && *b) {
        char ca = *a, cb = *b;
        if (ca >= 'a' && ca <= 'z') ca = (char)(ca - 32);
        if (cb >= 'a' && cb <= 'z') cb = (char)(cb - 32);
        if (ca != cb) return 0;
        ++a; ++b;
    }
    return (*a == 0) && (*b == 0);
}

/* [off, off+need) 是否完全落在 PE 缓冲区内 */
static int apiset_in_bounds(const PeInfo* pe, size_t off, size_t need)
{
    return (pe != NULL) && (off <= pe->size) && (need <= pe->size - off);
}

/* ------------------------------------------------------------------ */
/* apiset_init                                                         */
/* ------------------------------------------------------------------ */
int apiset_init(ApiSetMap* m)
{
    if (m == NULL) {
        return APISET_ERR_INVALID_ARG;
    }
    m->entries  = NULL;
    m->count    = 0;
    m->capacity = 0;
    return APISET_OK;
}

/* ------------------------------------------------------------------ */
/* apiset_add                                                          */
/* ------------------------------------------------------------------ */
int apiset_add(ApiSetMap* m, const char* vname, ApiSetTargetKind kind,
               const char* host, const char* note)
{
    ApiSetEntry* p;
    size_t new_cap;

    if (m == NULL || vname == NULL) {
        return APISET_ERR_INVALID_ARG;
    }
    /* TO_REAL_DLL / TO_LOCAL 需要 host；UNSOLVABLE 允许 NULL */
    if ((kind == APISET_TO_REAL_DLL || kind == APISET_TO_LOCAL) && host == NULL) {
        return APISET_ERR_INVALID_ARG;
    }

    if (m->count == m->capacity) {
        new_cap = m->capacity ? m->capacity * 2 : 16;
        p = (ApiSetEntry*)realloc(m->entries, new_cap * sizeof(*p));
        if (p == NULL) {
            return APISET_ERR_NOMEM;
        }
        m->entries  = p;
        m->capacity = new_cap;
    }

    m->entries[m->count].virtual_name = vname;
    m->entries[m->count].kind         = kind;
    m->entries[m->count].host_dll     = host;   /* UNSOLVABLE 时可为 NULL */
    m->entries[m->count].note         = note;
    m->count++;
    return APISET_OK;
}

/* ------------------------------------------------------------------ */
/* apiset_load_default - 加载硬编码预置映射表                          */
/*   覆盖 Win10 常见 api-ms-win-* / ext-ms-win-* 虚拟名：              */
/*     - TO_REAL_DLL：转发到 Win7 已有 DLL（kernel32/advapi32/ole32/  */
/*       user32/gdi32/shlwapi/psapi/ucrtbase 等）                      */
/*     - TO_LOCAL：转发到 win7bridge 本地模拟（VirtualAlloc2 等）       */
/*     - UNSOLVABLE：WinRT / AVX xstate / 扩展未评估项                 */
/*   覆盖策略参考 docs/api-diff.md §2.3。用户可通过 JSON 配置叠加或   */
/*   覆盖（见 docs/apiset-json-config.md）。                          */
/* ------------------------------------------------------------------ */
int apiset_load_default(ApiSetMap* m)
{
    int rc;

    if (m == NULL) {
        return APISET_ERR_INVALID_ARG;
    }

    /* ============================================================ */
    /* 1. kernel32 系列：Win7 kernel32 已含                          */
    /* ============================================================ */

    /* ---- 同步原语 ---- */
    rc = apiset_add(m, "api-ms-win-core-synch-l1-1-0",
                    APISET_TO_REAL_DLL, "kernel32.dll",
                    "Win7 kernel32 基础同步 API（CRITICAL_SECTION 等）");
    if (rc != APISET_OK) return rc;
    rc = apiset_add(m, "api-ms-win-core-synch-l1-2-0",
                    APISET_TO_LOCAL, "win7bridge_local",
                    "WaitOnAddress 体系，本地事件对象模拟");
    if (rc != APISET_OK) return rc;

    /* ---- 文件 ---- */
    rc = apiset_add(m, "api-ms-win-core-file-l1-1-0",
                    APISET_TO_REAL_DLL, "kernel32.dll",
                    "Win7 kernel32 基础文件 API");
    if (rc != APISET_OK) return rc;
    rc = apiset_add(m, "api-ms-win-core-file-l1-2-0",
                    APISET_TO_REAL_DLL, "kernel32.dll",
                    "Win7 kernel32 文件 API（含 GetFileInformationByHandleEx）");
    if (rc != APISET_OK) return rc;
    rc = apiset_add(m, "api-ms-win-core-file-l2-1-0",
                    APISET_TO_REAL_DLL, "kernel32.dll",
                    "Win7 kernel32 扩展文件 API");
    if (rc != APISET_OK) return rc;

    /* ---- 进程/线程 ---- */
    rc = apiset_add(m, "api-ms-win-core-processthreads-l1-1-0",
                    APISET_TO_REAL_DLL, "kernel32.dll",
                    "Win7 kernel32 进程线程基础 API");
    if (rc != APISET_OK) return rc;
    rc = apiset_add(m, "api-ms-win-core-processthreads-l1-1-1",
                    APISET_TO_REAL_DLL, "kernel32.dll",
                    "Win7 kernel32 进程线程 API");
    if (rc != APISET_OK) return rc;
    rc = apiset_add(m, "api-ms-win-core-processthreads-l1-1-2",
                    APISET_TO_REAL_DLL, "kernel32.dll",
                    "Win7 kernel32 进程线程 API（含部分新导出由 sim 补）");
    if (rc != APISET_OK) return rc;
    rc = apiset_add(m, "api-ms-win-core-processthreads-l1-1-3",
                    APISET_TO_LOCAL, "win7bridge_local",
                    "QueryUnbiasedInterruptTime 等新 API，本地模拟");
    if (rc != APISET_OK) return rc;

    /* ---- 进程环境 ---- */
    rc = apiset_add(m, "api-ms-win-core-processenvironment-l1-1-0",
                    APISET_TO_REAL_DLL, "kernel32.dll",
                    "Win7 kernel32 进程环境 API");
    if (rc != APISET_OK) return rc;
    rc = apiset_add(m, "api-ms-win-core-processenvironment-l1-2-0",
                    APISET_TO_REAL_DLL, "kernel32.dll",
                    "Win7 kernel32 进程环境 API");
    if (rc != APISET_OK) return rc;

    /* ---- 内存 ---- */
    rc = apiset_add(m, "api-ms-win-core-memory-l1-1-0",
                    APISET_TO_REAL_DLL, "kernel32.dll",
                    "Win7 kernel32 内存 API");
    if (rc != APISET_OK) return rc;
    rc = apiset_add(m, "api-ms-win-core-memory-l1-1-1",
                    APISET_TO_REAL_DLL, "kernel32.dll",
                    "Win7 kernel32 内存 API");
    if (rc != APISET_OK) return rc;
    rc = apiset_add(m, "api-ms-win-core-memory-l1-1-2",
                    APISET_TO_REAL_DLL, "kernel32.dll",
                    "Win7 kernel32 内存 API");
    if (rc != APISET_OK) return rc;
    rc = apiset_add(m, "api-ms-win-core-memory-l1-1-3",
                    APISET_TO_LOCAL, "win7bridge_local",
                    "VirtualAlloc2 退化为 VirtualAlloc");
    if (rc != APISET_OK) return rc;
    rc = apiset_add(m, "api-ms-win-core-memory-l1-1-4",
                    APISET_TO_LOCAL, "win7bridge_local",
                    "VirtualAlloc2 退化为 VirtualAlloc");
    if (rc != APISET_OK) return rc;
    rc = apiset_add(m, "api-ms-win-core-memory-l1-1-5",
                    APISET_TO_LOCAL, "win7bridge_local",
                    "VirtualAlloc2 退化为 VirtualAlloc");
    if (rc != APISET_OK) return rc;
    rc = apiset_add(m, "api-ms-win-core-memory-l1-1-6",
                    APISET_TO_LOCAL, "win7bridge_local",
                    "VirtualAlloc2 退化为 VirtualAlloc");
    if (rc != APISET_OK) return rc;

    /* ---- 堆 ---- */
    rc = apiset_add(m, "api-ms-win-core-heap-l1-1-0",
                    APISET_TO_REAL_DLL, "kernel32.dll",
                    "Win7 kernel32 堆 API");
    if (rc != APISET_OK) return rc;
    rc = apiset_add(m, "api-ms-win-core-heap-obsolete-l1-1-0",
                    APISET_TO_REAL_DLL, "kernel32.dll",
                    "Win7 kernel32 堆旧 API");
    if (rc != APISET_OK) return rc;

    /* ---- 控制台 ---- */
    rc = apiset_add(m, "api-ms-win-core-console-l1-1-0",
                    APISET_TO_REAL_DLL, "kernel32.dll",
                    "Win7 kernel32 控制台 API");
    if (rc != APISET_OK) return rc;
    rc = apiset_add(m, "api-ms-win-core-console-l1-2-0",
                    APISET_TO_REAL_DLL, "kernel32.dll",
                    "Win7 kernel32 控制台 API");
    if (rc != APISET_OK) return rc;
    rc = apiset_add(m, "api-ms-win-core-console-l2-1-0",
                    APISET_TO_LOCAL, "win7bridge_local",
                    "含 CreatePseudoConsole，本地模拟");
    if (rc != APISET_OK) return rc;
    rc = apiset_add(m, "api-ms-win-core-console-l3-1-0",
                    APISET_TO_REAL_DLL, "kernel32.dll",
                    "Win7 kernel32 控制台低级 API");
    if (rc != APISET_OK) return rc;
    rc = apiset_add(m, "api-ms-win-core-console-l3-2-0",
                    APISET_TO_REAL_DLL, "kernel32.dll",
                    "Win7 kernel32 控制台低级 API");
    if (rc != APISET_OK) return rc;

    /* ---- 日期时间 ---- */
    rc = apiset_add(m, "api-ms-win-core-datetime-l1-1-0",
                    APISET_TO_REAL_DLL, "kernel32.dll",
                    "Win7 kernel32 日期时间 API");
    if (rc != APISET_OK) return rc;
    rc = apiset_add(m, "api-ms-win-core-datetime-l1-1-1",
                    APISET_TO_REAL_DLL, "kernel32.dll",
                    "Win7 kernel32 日期时间 API");
    if (rc != APISET_OK) return rc;
    rc = apiset_add(m, "api-ms-win-core-realtime-l1-1-0",
                    APISET_TO_LOCAL, "win7bridge_local",
                    "GetSystemTimePreciseAsFileTime 回退 GetSystemTimeAsFileTime");
    if (rc != APISET_OK) return rc;

    /* ---- 调试 ---- */
    rc = apiset_add(m, "api-ms-win-core-debug-l1-1-0",
                    APISET_TO_REAL_DLL, "kernel32.dll",
                    "Win7 kernel32 调试 API");
    if (rc != APISET_OK) return rc;
    rc = apiset_add(m, "api-ms-win-core-debug-l1-1-1",
                    APISET_TO_REAL_DLL, "kernel32.dll",
                    "Win7 kernel32 调试 API");
    if (rc != APISET_OK) return rc;

    /* ---- 错误处理 ---- */
    rc = apiset_add(m, "api-ms-win-core-errorhandling-l1-1-0",
                    APISET_TO_REAL_DLL, "kernel32.dll",
                    "Win7 kernel32 错误处理 API");
    if (rc != APISET_OK) return rc;
    rc = apiset_add(m, "api-ms-win-core-errorhandling-l1-1-1",
                    APISET_TO_REAL_DLL, "kernel32.dll",
                    "Win7 kernel32 错误处理 API");
    if (rc != APISET_OK) return rc;
    rc = apiset_add(m, "api-ms-win-core-errorhandling-l1-1-2",
                    APISET_TO_REAL_DLL, "kernel32.dll",
                    "Win7 kernel32 错误处理 API");
    if (rc != APISET_OK) return rc;

    /* ---- 纤程 ---- */
    rc = apiset_add(m, "api-ms-win-core-fibers-l1-1-0",
                    APISET_TO_REAL_DLL, "kernel32.dll",
                    "Win7 kernel32 纤程 API");
    if (rc != APISET_OK) return rc;
    rc = apiset_add(m, "api-ms-win-core-fibers-l1-1-1",
                    APISET_TO_REAL_DLL, "kernel32.dll",
                    "Win7 kernel32 纤程 API");
    if (rc != APISET_OK) return rc;

    /* ---- 句柄 ---- */
    rc = apiset_add(m, "api-ms-win-core-handle-l1-1-0",
                    APISET_TO_REAL_DLL, "kernel32.dll",
                    "Win7 kernel32 句柄 API");
    if (rc != APISET_OK) return rc;

    /* ---- 互锁 ---- */
    rc = apiset_add(m, "api-ms-win-core-interlocked-l1-1-0",
                    APISET_TO_REAL_DLL, "kernel32.dll",
                    "Win7 kernel32 互锁 API");
    if (rc != APISET_OK) return rc;

    /* ---- IO ---- */
    rc = apiset_add(m, "api-ms-win-core-io-l1-1-0",
                    APISET_TO_REAL_DLL, "kernel32.dll",
                    "Win7 kernel32 IO API");
    if (rc != APISET_OK) return rc;
    rc = apiset_add(m, "api-ms-win-core-io-l1-1-1",
                    APISET_TO_REAL_DLL, "kernel32.dll",
                    "Win7 kernel32 IO API");
    if (rc != APISET_OK) return rc;

    /* ---- kernel32 legacy ---- */
    rc = apiset_add(m, "api-ms-win-core-kernel32-legacy-l1-1-0",
                    APISET_TO_REAL_DLL, "kernel32.dll",
                    "Win7 kernel32 旧 API");
    if (rc != APISET_OK) return rc;
    rc = apiset_add(m, "api-ms-win-core-kernel32-legacy-l1-1-1",
                    APISET_TO_REAL_DLL, "kernel32.dll",
                    "Win7 kernel32 旧 API");
    if (rc != APISET_OK) return rc;

    /* ---- 库加载器 ---- */
    rc = apiset_add(m, "api-ms-win-core-libraryloader-l1-1-0",
                    APISET_TO_REAL_DLL, "kernel32.dll",
                    "Win7 kernel32 库加载 API");
    if (rc != APISET_OK) return rc;
    rc = apiset_add(m, "api-ms-win-core-libraryloader-l1-1-1",
                    APISET_TO_REAL_DLL, "kernel32.dll",
                    "Win7 kernel32 库加载 API");
    if (rc != APISET_OK) return rc;

    /* ---- 本地化 ---- */
    rc = apiset_add(m, "api-ms-win-core-localization-l1-2-0",
                    APISET_TO_REAL_DLL, "kernel32.dll",
                    "Win7 kernel32 本地化 API");
    if (rc != APISET_OK) return rc;
    rc = apiset_add(m, "api-ms-win-core-localization-l1-2-1",
                    APISET_TO_REAL_DLL, "kernel32.dll",
                    "Win7 kernel32 本地化 API");
    if (rc != APISET_OK) return rc;
    rc = apiset_add(m, "api-ms-win-core-localization-l2-1-0",
                    APISET_TO_REAL_DLL, "kernel32.dll",
                    "Win7 kernel32 本地化扩展 API");
    if (rc != APISET_OK) return rc;

    /* ---- 命名管道 ---- */
    rc = apiset_add(m, "api-ms-win-core-namedpipe-l1-1-0",
                    APISET_TO_REAL_DLL, "kernel32.dll",
                    "Win7 kernel32 命名管道 API");
    if (rc != APISET_OK) return rc;
    rc = apiset_add(m, "api-ms-win-core-namedpipe-l1-2-1",
                    APISET_TO_REAL_DLL, "kernel32.dll",
                    "Win7 kernel32 命名管道 API");
    if (rc != APISET_OK) return rc;

    /* ---- 性能分析 ---- */
    rc = apiset_add(m, "api-ms-win-core-profile-l1-1-0",
                    APISET_TO_REAL_DLL, "kernel32.dll",
                    "Win7 kernel32 性能分析 API");
    if (rc != APISET_OK) return rc;

    /* ---- 注册表 ---- */
    rc = apiset_add(m, "api-ms-win-core-registry-l1-1-0",
                    APISET_TO_REAL_DLL, "kernel32.dll",
                    "Win7 kernel32 注册表 API");
    if (rc != APISET_OK) return rc;

    /* ---- RTL 支持 ---- */
    rc = apiset_add(m, "api-ms-win-core-rtlsupport-l1-1-0",
                    APISET_TO_REAL_DLL, "ntdll.dll",
                    "ntdll 提供 RTL 支持");
    if (rc != APISET_OK) return rc;

    /* ---- 字符串 ---- */
    rc = apiset_add(m, "api-ms-win-core-string-l1-1-0",
                    APISET_TO_REAL_DLL, "kernel32.dll",
                    "Win7 kernel32 字符串 API");
    if (rc != APISET_OK) return rc;
    rc = apiset_add(m, "api-ms-win-core-string-l2-1-0",
                    APISET_TO_REAL_DLL, "kernel32.dll",
                    "Win7 kernel32 字符串 API");
    if (rc != APISET_OK) return rc;
    rc = apiset_add(m, "api-ms-win-core-string-obsolete-l1-1-0",
                    APISET_TO_REAL_DLL, "kernel32.dll",
                    "Win7 kernel32 旧字符串 API");
    if (rc != APISET_OK) return rc;

    /* ---- 系统信息 ---- */
    rc = apiset_add(m, "api-ms-win-core-sysinfo-l1-1-0",
                    APISET_TO_REAL_DLL, "kernel32.dll",
                    "Win7 kernel32 系统信息 API");
    if (rc != APISET_OK) return rc;
    rc = apiset_add(m, "api-ms-win-core-sysinfo-l1-2-0",
                    APISET_TO_REAL_DLL, "kernel32.dll",
                    "Win7 kernel32 系统信息 API");
    if (rc != APISET_OK) return rc;
    rc = apiset_add(m, "api-ms-win-core-sysinfo-l1-2-1",
                    APISET_TO_REAL_DLL, "kernel32.dll",
                    "Win7 kernel32 系统信息 API");
    if (rc != APISET_OK) return rc;
    rc = apiset_add(m, "api-ms-win-core-largeinteger-l1-1-0",
                    APISET_TO_REAL_DLL, "kernel32.dll",
                    "Win7 kernel32 大整数 API");
    if (rc != APISET_OK) return rc;

    /* ---- 时区 ---- */
    rc = apiset_add(m, "api-ms-win-core-timezone-l1-1-0",
                    APISET_TO_REAL_DLL, "kernel32.dll",
                    "Win7 kernel32 时区 API");
    if (rc != APISET_OK) return rc;

    /* ---- 工具 ---- */
    rc = apiset_add(m, "api-ms-win-core-util-l1-1-0",
                    APISET_TO_REAL_DLL, "kernel32.dll",
                    "Win7 kernel32 工具 API");
    if (rc != APISET_OK) return rc;

    /* ---- 延迟加载 ---- */
    rc = apiset_add(m, "api-ms-win-core-delayload-l1-1-0",
                    APISET_TO_REAL_DLL, "kernel32.dll",
                    "Win7 kernel32 延迟加载 API");
    if (rc != APISET_OK) return rc;

    /* ---- Windows 错误报告 ---- */
    rc = apiset_add(m, "api-ms-win-core-windowserrorreporting-l1-1-0",
                    APISET_TO_LOCAL, "win7bridge_local",
                    "WER 新 API，no-op 回退");
    if (rc != APISET_OK) return rc;

    /* ---- 线程池（部分新 API） ---- */
    rc = apiset_add(m, "api-ms-win-core-threadpool-l1-2-0",
                    APISET_TO_REAL_DLL, "kernel32.dll",
                    "Win7 kernel32 线程池 API");
    if (rc != APISET_OK) return rc;
    rc = apiset_add(m, "api-ms-win-core-threadpool-legacy-l1-1-0",
                    APISET_TO_REAL_DLL, "kernel32.dll",
                    "Win7 kernel32 旧线程池 API");
    if (rc != APISET_OK) return rc;
    rc = apiset_add(m, "api-ms-win-core-threadpool-private-l1-1-0",
                    APISET_TO_REAL_DLL, "kernel32.dll",
                    "Win7 kernel32 私有线程池 API");
    if (rc != APISET_OK) return rc;

    /* ---- xstate：AVX 扩展上下文，Win7 无 ---- */
    rc = apiset_add(m, "api-ms-win-core-xstate-l1-1-0",
                    APISET_TO_REAL_DLL, "kernel32.dll",
                    "Win7 kernel32 基础 xstate API（仅 legacy）");
    if (rc != APISET_OK) return rc;
    rc = apiset_add(m, "api-ms-win-core-xstate-l2-1-0",
                    APISET_UNSOLVABLE, NULL,
                    "AVX 扩展上下文，Win7 无");
    if (rc != APISET_OK) return rc;

    /* ---- psapi ---- */
    rc = apiset_add(m, "api-ms-win-core-psapi-l1-1-0",
                    APISET_TO_REAL_DLL, "psapi.dll",
                    "Win7 psapi 进程信息 API");
    if (rc != APISET_OK) return rc;
    rc = apiset_add(m, "api-ms-win-core-psapi-ansi-l1-1-0",
                    APISET_TO_REAL_DLL, "psapi.dll",
                    "Win7 psapi ANSI 进程信息 API");
    if (rc != APISET_OK) return rc;

    /* ============================================================ */
    /* 2. advapi32 系列：Win7 advapi32 已含                          */
    /* ============================================================ */
    rc = apiset_add(m, "api-ms-win-security-base-l1-1-0",
                    APISET_TO_REAL_DLL, "advapi32.dll",
                    "Win7 advapi32 安全基础 API");
    if (rc != APISET_OK) return rc;
    rc = apiset_add(m, "api-ms-win-security-lsalookup-l1-1-0",
                    APISET_TO_REAL_DLL, "advapi32.dll",
                    "Win7 advapi32 LSA 查找 API");
    if (rc != APISET_OK) return rc;
    rc = apiset_add(m, "api-ms-win-security-sddl-l1-1-0",
                    APISET_TO_REAL_DLL, "advapi32.dll",
                    "Win7 advapi32 SDDL API");
    if (rc != APISET_OK) return rc;
    rc = apiset_add(m, "api-ms-win-security-provider-l1-1-0",
                    APISET_TO_REAL_DLL, "advapi32.dll",
                    "Win7 advapi32 安全提供程序 API");
    if (rc != APISET_OK) return rc;
    rc = apiset_add(m, "api-ms-win-security-cryptoapi-l1-1-0",
                    APISET_TO_REAL_DLL, "advapi32.dll",
                    "Win7 advapi32 CryptoAPI（旧 CAPI）");
    if (rc != APISET_OK) return rc;
    rc = apiset_add(m, "api-ms-win-security-cng-l1-1-0",
                    APISET_TO_LOCAL, "win7bridge_local",
                    "CNG 新算法经 win7bridge BCrypt 适配层提供");
    if (rc != APISET_OK) return rc;

    /* ---- 服务 ---- */
    rc = apiset_add(m, "api-ms-win-service-core-l1-1-0",
                    APISET_TO_REAL_DLL, "advapi32.dll",
                    "Win7 advapi32 服务核心 API");
    if (rc != APISET_OK) return rc;
    rc = apiset_add(m, "api-ms-win-service-core-l1-1-1",
                    APISET_TO_REAL_DLL, "advapi32.dll",
                    "Win7 advapi32 服务核心 API");
    if (rc != APISET_OK) return rc;
    rc = apiset_add(m, "api-ms-win-service-management-l1-1-0",
                    APISET_TO_REAL_DLL, "advapi32.dll",
                    "Win7 advapi32 服务管理 API");
    if (rc != APISET_OK) return rc;
    rc = apiset_add(m, "api-ms-win-service-management-l2-1-0",
                    APISET_TO_REAL_DLL, "advapi32.dll",
                    "Win7 advapi32 服务管理 API");
    if (rc != APISET_OK) return rc;

    /* ---- eventlog ---- */
    rc = apiset_add(m, "api-ms-win-eventing-controller-l1-1-0",
                    APISET_TO_REAL_DLL, "advapi32.dll",
                    "Win7 advapi32 ETW 控制器 API");
    if (rc != APISET_OK) return rc;
    rc = apiset_add(m, "api-ms-win-eventing-consumer-l1-1-0",
                    APISET_TO_REAL_DLL, "advapi32.dll",
                    "Win7 advapi32 ETW 消费者 API");
    if (rc != APISET_OK) return rc;
    rc = apiset_add(m, "api-ms-win-eventing-provider-l1-1-0",
                    APISET_TO_REAL_DLL, "advapi32.dll",
                    "Win7 advapi32 ETW 提供程序 API");
    if (rc != APISET_OK) return rc;
    rc = apiset_add(m, "api-ms-win-eventing-legacy-l1-1-0",
                    APISET_TO_REAL_DLL, "advapi32.dll",
                    "Win7 advapi32 旧 ETW API");
    if (rc != APISET_OK) return rc;

    /* ============================================================ */
    /* 3. user32 / gdi32 系列：Win7 已含                             */
    /* ============================================================ */
    rc = apiset_add(m, "api-ms-win-user32-registry-l1-1-0",
                    APISET_TO_REAL_DLL, "user32.dll",
                    "Win7 user32 侧注册表 API");
    if (rc != APISET_OK) return rc;
    rc = apiset_add(m, "api-ms-win-core-windowtracer-l1-1-0",
                    APISET_TO_REAL_DLL, "user32.dll",
                    "Win7 user32 window tracer API");
    if (rc != APISET_OK) return rc;
    rc = apiset_add(m, "api-ms-win-core-win32-registry-l1-1-0",
                    APISET_TO_REAL_DLL, "advapi32.dll",
                    "Win7 advapi32 注册表 API");
    if (rc != APISET_OK) return rc;
    rc = apiset_add(m, "api-ms-win-core-win32-string-l1-1-0",
                    APISET_TO_REAL_DLL, "kernel32.dll",
                    "Win7 kernel32 字符串 API");
    if (rc != APISET_OK) return rc;
    rc = apiset_add(m, "api-ms-win-core-win32-string-ansi-l1-1-0",
                    APISET_TO_REAL_DLL, "kernel32.dll",
                    "Win7 kernel32 ANSI 字符串 API");
    if (rc != APISET_OK) return rc;

    /* ============================================================ */
    /* 4. ole32 / COM 系列：Win7 ole32 已含                          */
    /* ============================================================ */
    rc = apiset_add(m, "api-ms-win-core-com-l1-1-0",
                    APISET_TO_REAL_DLL, "ole32.dll",
                    "Win7 ole32 COM 基础 API");
    if (rc != APISET_OK) return rc;
    rc = apiset_add(m, "api-ms-win-core-com-l1-1-1",
                    APISET_TO_REAL_DLL, "ole32.dll",
                    "Win7 ole32 COM 基础 API");
    if (rc != APISET_OK) return rc;
    rc = apiset_add(m, "api-ms-win-core-com-private-l1-1-0",
                    APISET_TO_REAL_DLL, "ole32.dll",
                    "Win7 ole32 私有 COM API");
    if (rc != APISET_OK) return rc;
    rc = apiset_add(m, "api-ms-win-core-com-midlproxystub-l1-1-0",
                    APISET_TO_REAL_DLL, "ole32.dll",
                    "Win7 ole32 MIDL proxy/stub API");
    if (rc != APISET_OK) return rc;

    /* ============================================================ */
    /* 5. shell / shcore / shlwapi 系列                              */
    /* ============================================================ */
    rc = apiset_add(m, "api-ms-win-shcore-scaling-l1-1-0",
                    APISET_TO_LOCAL, "win7bridge_local",
                    "DPI awareness，回退 SetProcessDPIAware");
    if (rc != APISET_OK) return rc;
    rc = apiset_add(m, "api-ms-win-shcore-registry-l1-1-0",
                    APISET_TO_REAL_DLL, "shcore.dll",
                    "Win7 shcore 注册表 API");
    if (rc != APISET_OK) return rc;
    rc = apiset_add(m, "api-ms-win-shcore-stream-l1-1-0",
                    APISET_TO_REAL_DLL, "shcore.dll",
                    "Win7 shcore 流 API");
    if (rc != APISET_OK) return rc;
    rc = apiset_add(m, "api-ms-win-shcore-thread-l1-1-0",
                    APISET_TO_REAL_DLL, "shcore.dll",
                    "Win7 shcore 线程 API");
    if (rc != APISET_OK) return rc;
    rc = apiset_add(m, "api-ms-win-shcore-winrt-l1-1-0",
                    APISET_UNSOLVABLE, NULL,
                    "shcore WinRT 路径，不可解");
    if (rc != APISET_OK) return rc;
    rc = apiset_add(m, "api-ms-win-shlwapi-winrt-storage-l1-1-0",
                    APISET_UNSOLVABLE, NULL,
                    "shlwapi WinRT 存储路径，不可解");
    if (rc != APISET_OK) return rc;
    rc = apiset_add(m, "api-ms-win-shlwapi-winrt-timer-l1-1-0",
                    APISET_UNSOLVABLE, NULL,
                    "shlwapi WinRT 定时器路径，不可解");
    if (rc != APISET_OK) return rc;

    /* ============================================================ */
    /* 6. UCRT：靠 KB2999226 提供 ucrtbase.dll                       */
    /*    若用户无 KB2999226，需安装 VCRedist（ucrt_check 模块提示）   */
    /* ============================================================ */
    rc = apiset_add(m, "api-ms-win-crt-runtime-l1-1-0",
                    APISET_TO_REAL_DLL, "ucrtbase.dll",
                    "UCRT，靠 KB2999226 或 VCRedist");
    if (rc != APISET_OK) return rc;
    rc = apiset_add(m, "api-ms-win-crt-runtime-l1-1-1",
                    APISET_TO_REAL_DLL, "ucrtbase.dll",
                    "UCRT，靠 KB2999226 或 VCRedist");
    if (rc != APISET_OK) return rc;
    rc = apiset_add(m, "api-ms-win-crt-stdio-l1-1-0",
                    APISET_TO_REAL_DLL, "ucrtbase.dll",
                    "UCRT stdio，靠 KB2999226 或 VCRedist");
    if (rc != APISET_OK) return rc;
    rc = apiset_add(m, "api-ms-win-crt-heap-l1-1-0",
                    APISET_TO_REAL_DLL, "ucrtbase.dll",
                    "UCRT heap，靠 KB2999226 或 VCRedist");
    if (rc != APISET_OK) return rc;
    rc = apiset_add(m, "api-ms-win-crt-string-l1-1-0",
                    APISET_TO_REAL_DLL, "ucrtbase.dll",
                    "UCRT string，靠 KB2999226 或 VCRedist");
    if (rc != APISET_OK) return rc;
    rc = apiset_add(m, "api-ms-win-crt-math-l1-1-0",
                    APISET_TO_REAL_DLL, "ucrtbase.dll",
                    "UCRT math，靠 KB2999226 或 VCRedist");
    if (rc != APISET_OK) return rc;
    rc = apiset_add(m, "api-ms-win-crt-locale-l1-1-0",
                    APISET_TO_REAL_DLL, "ucrtbase.dll",
                    "UCRT locale，靠 KB2999226 或 VCRedist");
    if (rc != APISET_OK) return rc;
    rc = apiset_add(m, "api-ms-win-crt-time-l1-1-0",
                    APISET_TO_REAL_DLL, "ucrtbase.dll",
                    "UCRT time，靠 KB2999226 或 VCRedist");
    if (rc != APISET_OK) return rc;
    rc = apiset_add(m, "api-ms-win-crt-filesystem-l1-1-0",
                    APISET_TO_REAL_DLL, "ucrtbase.dll",
                    "UCRT filesystem，靠 KB2999226 或 VCRedist");
    if (rc != APISET_OK) return rc;
    rc = apiset_add(m, "api-ms-win-crt-multibyte-l1-1-0",
                    APISET_TO_REAL_DLL, "ucrtbase.dll",
                    "UCRT multibyte，靠 KB2999226 或 VCRedist");
    if (rc != APISET_OK) return rc;
    rc = apiset_add(m, "api-ms-win-crt-private-l1-1-0",
                    APISET_TO_REAL_DLL, "ucrtbase.dll",
                    "UCRT private，靠 KB2999226 或 VCRedist");
    if (rc != APISET_OK) return rc;
    rc = apiset_add(m, "api-ms-win-crt-conio-l1-1-0",
                    APISET_TO_REAL_DLL, "ucrtbase.dll",
                    "UCRT conio，靠 KB2999226 或 VCRedist");
    if (rc != APISET_OK) return rc;
    rc = apiset_add(m, "api-ms-win-crt-convert-l1-1-0",
                    APISET_TO_REAL_DLL, "ucrtbase.dll",
                    "UCRT convert，靠 KB2999226 或 VCRedist");
    if (rc != APISET_OK) return rc;
    rc = apiset_add(m, "api-ms-win-crt-process-l1-1-0",
                    APISET_TO_REAL_DLL, "ucrtbase.dll",
                    "UCRT process，靠 KB2999226 或 VCRedist");
    if (rc != APISET_OK) return rc;
    rc = apiset_add(m, "api-ms-win-crt-environment-l1-1-0",
                    APISET_TO_REAL_DLL, "ucrtbase.dll",
                    "UCRT environment，靠 KB2999226 或 VCRedist");
    if (rc != APISET_OK) return rc;
    rc = apiset_add(m, "api-ms-win-crt-utility-l1-1-0",
                    APISET_TO_REAL_DLL, "ucrtbase.dll",
                    "UCRT utility，靠 KB2999226 或 VCRedist");
    if (rc != APISET_OK) return rc;

    /* ============================================================ */
    /* 7. WinRT：完全不可解                                          */
    /* ============================================================ */
    rc = apiset_add(m, "api-ms-win-core-winrt-l1-1-0",
                    APISET_UNSOLVABLE, NULL,
                    "WinRT，不可解");
    if (rc != APISET_OK) return rc;
    rc = apiset_add(m, "api-ms-win-core-winrt-l1-1-1",
                    APISET_UNSOLVABLE, NULL,
                    "WinRT，不可解");
    if (rc != APISET_OK) return rc;
    rc = apiset_add(m, "api-ms-win-core-winrt-string-l1-1-0",
                    APISET_UNSOLVABLE, NULL,
                    "WinRT HSTRING，不可解");
    if (rc != APISET_OK) return rc;
    rc = apiset_add(m, "api-ms-win-core-winrt-error-l1-1-0",
                    APISET_UNSOLVABLE, NULL,
                    "WinRT error，不可解");
    if (rc != APISET_OK) return rc;
    rc = apiset_add(m, "api-ms-win-core-winrt-registration-l1-1-0",
                    APISET_UNSOLVABLE, NULL,
                    "WinRT registration，不可解");
    if (rc != APISET_OK) return rc;
    rc = apiset_add(m, "api-ms-win-core-winrt-roparameterizediid-l1-1-0",
                    APISET_UNSOLVABLE, NULL,
                    "WinRT IID，不可解");
    if (rc != APISET_OK) return rc;
    rc = apiset_add(m, "api-ms-win-core-winrt-robuffer-l1-1-0",
                    APISET_UNSOLVABLE, NULL,
                    "WinRT buffer，不可解");
    if (rc != APISET_OK) return rc;

    /* ============================================================ */
    /* 8. 扩展 API set（ext-ms-win-*）：逐项评估，默认不可解         */
    /* ============================================================ */
    rc = apiset_add(m, "ext-ms-win-core-winrt-l1-1-0",
                    APISET_UNSOLVABLE, NULL,
                    "扩展 API set，逐项评估");
    if (rc != APISET_OK) return rc;
    rc = apiset_add(m, "ext-ms-win-core-winrt-string-l1-1-0",
                    APISET_UNSOLVABLE, NULL,
                    "扩展 API set，逐项评估");
    if (rc != APISET_OK) return rc;
    rc = apiset_add(m, "ext-ms-win-rtcore-ntuser-sysparams-l1-1-0",
                    APISET_TO_REAL_DLL, "user32.dll",
                    "Win7 user32 系统参数 API");
    if (rc != APISET_OK) return rc;
    rc = apiset_add(m, "ext-ms-win-rtcore-ntuser-windowclass-l1-1-0",
                    APISET_TO_REAL_DLL, "user32.dll",
                    "Win7 user32 窗口类 API");
    if (rc != APISET_OK) return rc;
    rc = apiset_add(m, "ext-ms-win-ntuser-window-l1-1-0",
                    APISET_TO_REAL_DLL, "user32.dll",
                    "Win7 user32 窗口 API");
    if (rc != APISET_OK) return rc;
    rc = apiset_add(m, "ext-ms-win-ntuser-uicontext-ext-l1-1-0",
                    APISET_TO_REAL_DLL, "user32.dll",
                    "Win7 user32 UI 上下文 API");
    if (rc != APISET_OK) return rc;
    rc = apiset_add(m, "ext-ms-win-ntuser-gui-l1-1-0",
                    APISET_TO_REAL_DLL, "user32.dll",
                    "Win7 user32 GUI API");
    if (rc != APISET_OK) return rc;
    rc = apiset_add(m, "ext-ms-win-ntuser-misc-l1-1-0",
                    APISET_TO_REAL_DLL, "user32.dll",
                    "Win7 user32 杂项 API");
    if (rc != APISET_OK) return rc;
    rc = apiset_add(m, "ext-ms-win-ntuser-rectangle-ext-l1-1-0",
                    APISET_TO_REAL_DLL, "user32.dll",
                    "Win7 user32 矩形 API");
    if (rc != APISET_OK) return rc;
    rc = apiset_add(m, "ext-ms-win-ntuser-powermanagement-l1-1-0",
                    APISET_TO_REAL_DLL, "user32.dll",
                    "Win7 user32 电源管理 API");
    if (rc != APISET_OK) return rc;
    rc = apiset_add(m, "ext-ms-win-gdi-dc-create-l1-1-0",
                    APISET_TO_REAL_DLL, "gdi32.dll",
                    "Win7 gdi32 DC 创建 API");
    if (rc != APISET_OK) return rc;
    rc = apiset_add(m, "ext-ms-win-gdi-dc-l1-1-0",
                    APISET_TO_REAL_DLL, "gdi32.dll",
                    "Win7 gdi32 DC API");
    if (rc != APISET_OK) return rc;
    rc = apiset_add(m, "ext-ms-win-gdi-draw-l1-1-0",
                    APISET_TO_REAL_DLL, "gdi32.dll",
                    "Win7 gdi32 绘图 API");
    if (rc != APISET_OK) return rc;
    rc = apiset_add(m, "ext-ms-win-gdi-font-l1-1-0",
                    APISET_TO_REAL_DLL, "gdi32.dll",
                    "Win7 gdi32 字体 API");
    if (rc != APISET_OK) return rc;
    rc = apiset_add(m, "ext-ms-win-gdi-metafile-l1-1-0",
                    APISET_TO_REAL_DLL, "gdi32.dll",
                    "Win7 gdi32 metafile API");
    if (rc != APISET_OK) return rc;
    rc = apiset_add(m, "ext-ms-win-gdi-misc-l1-1-0",
                    APISET_TO_REAL_DLL, "gdi32.dll",
                    "Win7 gdi32 杂项 API");
    if (rc != APISET_OK) return rc;
    rc = apiset_add(m, "ext-ms-win-gdi-paint-l1-1-0",
                    APISET_TO_REAL_DLL, "gdi32.dll",
                    "Win7 gdi32 paint API");
    if (rc != APISET_OK) return rc;
    rc = apiset_add(m, "ext-ms-win-gdi-path-l1-1-0",
                    APISET_TO_REAL_DLL, "gdi32.dll",
                    "Win7 gdi32 path API");
    if (rc != APISET_OK) return rc;
    rc = apiset_add(m, "ext-ms-win-gdi-region-l1-1-0",
                    APISET_TO_REAL_DLL, "gdi32.dll",
                    "Win7 gdi32 region API");
    if (rc != APISET_OK) return rc;
    rc = apiset_add(m, "ext-ms-win-gdi-transform-l1-1-0",
                    APISET_TO_REAL_DLL, "gdi32.dll",
                    "Win7 gdi32 transform API");
    if (rc != APISET_OK) return rc;

    /* ---- kernel32 legacy 扩展 ---- */
    rc = apiset_add(m, "ext-ms-win-core-kernel32-legacy-l1-1-0",
                    APISET_TO_REAL_DLL, "kernel32.dll",
                    "Win7 kernel32 旧 API 扩展");
    if (rc != APISET_OK) return rc;
    rc = apiset_add(m, "ext-ms-win-core-psynch-l1-1-0",
                    APISET_TO_REAL_DLL, "kernel32.dll",
                    "Win7 kernel32 同步 API 扩展");
    if (rc != APISET_OK) return rc;
    rc = apiset_add(m, "ext-ms-win-core-heap-l1-1-0",
                    APISET_TO_REAL_DLL, "kernel32.dll",
                    "Win7 kernel32 堆 API 扩展");
    if (rc != APISET_OK) return rc;

    /* ============================================================ */
    /* 9. AppX / UWP / Shell — 不可解                                */
    /* ============================================================ */
    rc = apiset_add(m, "api-ms-win-appmodel-runtime-l1-1-0",
                    APISET_UNSOLVABLE, NULL,
                    "AppModel runtime，UWP 不可解");
    if (rc != APISET_OK) return rc;
    rc = apiset_add(m, "api-ms-win-appmodel-runtime-l1-1-1",
                    APISET_UNSOLVABLE, NULL,
                    "AppModel runtime，UWP 不可解");
    if (rc != APISET_OK) return rc;
    rc = apiset_add(m, "api-ms-win-appmodel-state-l1-1-0",
                    APISET_UNSOLVABLE, NULL,
                    "AppModel state，UWP 不可解");
    if (rc != APISET_OK) return rc;
    rc = apiset_add(m, "api-ms-win-appmodel-identity-l1-1-0",
                    APISET_UNSOLVABLE, NULL,
                    "AppModel identity，UWP 不可解");
    if (rc != APISET_OK) return rc;

    /* ============================================================ */
    /* 10. state separation / nucleus — 不可解                      */
    /* ============================================================ */
    rc = apiset_add(m, "api-ms-win-shcore-state-l1-1-0",
                    APISET_UNSOLVABLE, NULL,
                    "shcore state separation，不可解");
    if (rc != APISET_OK) return rc;
    rc = apiset_add(m, "api-ms-win-shcore-comhelpers-l1-1-0",
                    APISET_UNSOLVABLE, NULL,
                    "shcore COM helpers，不可解");
    if (rc != APISET_OK) return rc;
    rc = apiset_add(m, "api-ms-win-shcore-obsolete-l1-1-0",
                    APISET_TO_REAL_DLL, "shcore.dll",
                    "shcore 旧 API，Win7 shcore 已含");
    if (rc != APISET_OK) return rc;

    return APISET_OK;
}

/* ------------------------------------------------------------------ */
/* apiset_lookup - 大小写不敏感查找                                    */
/* ------------------------------------------------------------------ */
int apiset_lookup(const ApiSetMap* m, const char* virtual_name,
                  ApiSetEntry* out)
{
    size_t i;

    if (m == NULL || virtual_name == NULL) {
        return APISET_ERR_INVALID_ARG;
    }

    for (i = 0; i < m->count; ++i) {
        if (apiset_ieq(m->entries[i].virtual_name, virtual_name)) {
            if (out != NULL) {
                *out = m->entries[i];
            }
            return 1;
        }
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* 内部：大小写不敏感前缀匹配                                            */
/*   s     ：待测字符串（可为 NULL，返回 0）                            */
/*   prefix ：前缀（任意大小写）                                        */
/* 返回：1 s 以 prefix 开头；0 否则。                                    */
/* ------------------------------------------------------------------ */
static int apiset_starts_with_ci(const char* s, const char* prefix)
{
    size_t i;
    if (s == NULL || prefix == NULL) {
        return 0;
    }
    for (i = 0; prefix[i] != 0; ++i) {
        char c = s[i];
        char pc = prefix[i];
        if (c == 0) return 0;
        if (c >= 'a' && c <= 'z') c = (char)(c - 32);
        if (pc >= 'a' && pc <= 'z') pc = (char)(pc - 32);
        if (c != pc) return 0;
    }
    return 1;
}

/* ------------------------------------------------------------------ */
/* apiset_is_virtual_name - 判断虚拟名前缀                             */
/* ------------------------------------------------------------------ */
int apiset_is_virtual_name(const char* dll_name)
{
    if (dll_name == NULL) {
        return 0;
    }
    if (apiset_starts_with_ci(dll_name, "api-ms-win-")) {
        return 1;
    }
    if (apiset_starts_with_ci(dll_name, "ext-ms-win-")) {
        return 1;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* 内部：剥离 ".dll" 后缀（大小写不敏感），写入临时缓冲区              */
/*   src       ：原始 DLL 名（NUL 结尾）                               */
/*   dst       ：输出缓冲区（至少 strlen(src)+1 字节）                  */
/*   dst_cap   ：缓冲区容量                                            */
/* 返回：dst（始终 NUL 结尾）。后缀不存在时返回原串副本。              */
/* ------------------------------------------------------------------ */
static void apiset_strip_dll_suffix(const char* src, char* dst, size_t dst_cap)
{
    size_t len;
    if (src == NULL || dst == NULL || dst_cap == 0) {
        if (dst != NULL && dst_cap > 0) dst[0] = 0;
        return;
    }
    len = 0;
    while (src[len] != 0 && len + 1 < dst_cap) {
        dst[len] = src[len];
        ++len;
    }
    dst[len] = 0;

    /* 剥离 ".dll" 后缀（大小写不敏感） */
    if (len >= 4) {
        char c0 = dst[len - 4];
        char c1 = dst[len - 3];
        char c2 = dst[len - 2];
        char c3 = dst[len - 1];
        if (c0 >= 'a' && c0 <= 'z') c0 = (char)(c0 - 32);
        if (c1 >= 'a' && c1 <= 'z') c1 = (char)(c1 - 32);
        if (c2 >= 'a' && c2 <= 'z') c2 = (char)(c2 - 32);
        if (c3 >= 'a' && c3 <= 'z') c3 = (char)(c3 - 32);
        if (c0 == '.' && c1 == 'D' && c2 == 'L' && c3 == 'L') {
            dst[len - 4] = 0;
        }
    }
}

/* ------------------------------------------------------------------ */
/* apiset_resolve_imports - 遍历 PE 导入表，对虚拟名查表               */
/* 返回：命中映射表的虚拟名导入项个数                                  */
/* ------------------------------------------------------------------ */
int apiset_resolve_imports(const ApiSetMap* m, PeInfo* pe)
{
    IMAGE_DATA_DIRECTORY* dir;
    DWORD dir_va, dir_sz;
    size_t off;
    int need_handle = 0;

    if (m == NULL || pe == NULL || pe->data_dir == NULL) {
        return APISET_ERR_INVALID_ARG;
    }

    dir = &pe->data_dir[IMAGE_DIRECTORY_ENTRY_IMPORT];
    dir_va = dir->VirtualAddress;
    dir_sz = dir->Size;
    if (dir_va == 0 || dir_sz == 0) {
        return 0;  /* 无导入表，无需处理 */
    }

    off = 0;
    while (off + sizeof(IMAGE_IMPORT_DESCRIPTOR) <= dir_sz) {
        const IMAGE_IMPORT_DESCRIPTOR* d;
        const char* dll_name;
        size_t abs_off = dir_va + off;
        ApiSetEntry entry;
        int rc;

        if (!apiset_in_bounds(pe, abs_off, sizeof(IMAGE_IMPORT_DESCRIPTOR))) {
            break;
        }
        d = (const IMAGE_IMPORT_DESCRIPTOR*)
            ((const unsigned char*)pe->data + abs_off);

        /* 终止项 */
        if (d->Name == 0 && d->OriginalFirstThunk == 0 && d->FirstThunk == 0) {
            break;
        }

        /* 取 DLL 名（RVA -> 指针） */
        dll_name = NULL;
        if (d->Name != 0 && apiset_in_bounds(pe, d->Name, 1)) {
            dll_name = (const char*)pe->data + d->Name;
        }

        if (dll_name != NULL && apiset_is_virtual_name(dll_name)) {
            /* 命中虚拟名前缀：剥离 .dll 后缀后查映射表 */
            char norm[128];
            apiset_strip_dll_suffix(dll_name, norm, sizeof(norm));
            rc = apiset_lookup(m, norm, &entry);
            if (rc == 1) {
                /* 命中映射表，计入"需要处理"的条目数 */
                ++need_handle;
            }
            /* 未命中映射表的虚拟名暂不计入；上层可单独报告 */
        }

        off += sizeof(IMAGE_IMPORT_DESCRIPTOR);
    }

    return need_handle;
}

/* ================================================================== */
/* JSON 配置加载器                                                     */
/*   极简递归下降解析器，纯 C，零外部依赖。仅支持本格式所需的 JSON    */
/*   子集：对象、数组、字符串、键值对、字面 null/true/false（被忽略）。*/
/*   支持 // 行注释和 块注释（非标准但便于人工编辑）。字符串转义支持  */
/*   " \ / \n \t \r \b \f。                                           */
/* ================================================================== */

/* arena 头部：放在 arena 起始处，记录容量与已用偏移 */
typedef struct {
    size_t capacity;   /* arena 总容量（含头部）   */
    size_t used;       /* 已用偏移（含头部）       */
} ArenaHeader;

#define ARENA_INITIAL_CAP  4096   /* arena 初始容量           */
#define ARENA_ALIGN        8      /* 字符串 8 字节对齐        */

/*
 * arena_alloc - 在 arena 中分配 size 字节，必要时扩容
 *   arena_p  ：指向 arena 指针的指针（可能 *arena_p == NULL）
 *   size     ：需分配的字节数（不含 NUL）
 *   返回：分配区起始指针；失败返回 NULL（arena 已释放并置 NULL）
 */
static char* arena_alloc(void** arena_p, size_t size)
{
    ArenaHeader* hdr;
    char*        body;
    size_t       need;
    size_t       new_cap;

    if (arena_p == NULL) return NULL;

    /* 首次分配：建立 arena */
    if (*arena_p == NULL) {
        size_t cap = ARENA_INITIAL_CAP;
        if (cap < sizeof(ArenaHeader) + size + 1) {
            cap = sizeof(ArenaHeader) + size + 1 + ARENA_ALIGN;
        }
        hdr = (ArenaHeader*)malloc(cap);
        if (hdr == NULL) return NULL;
        hdr->capacity = cap;
        hdr->used     = sizeof(ArenaHeader);
        *arena_p = (void*)hdr;
    }

    hdr = (ArenaHeader*)(*arena_p);

    /* 8 字节对齐 */
    need = (hdr->used + (ARENA_ALIGN - 1)) & ~((size_t)(ARENA_ALIGN - 1));
    need += size + 1;  /* +1 for NUL */

    if (need > hdr->capacity) {
        new_cap = hdr->capacity;
        while (new_cap < need) new_cap *= 2;
        hdr = (ArenaHeader*)realloc(hdr, new_cap);
        if (hdr == NULL) {
            *arena_p = NULL;
            return NULL;
        }
        hdr->capacity = new_cap;
        *arena_p = (void*)hdr;
    }

    body = (char*)(*arena_p) + hdr->used;
    /* 对齐：先把 hdr->used 提到对齐边界 */
    {
        size_t aligned = (hdr->used + (ARENA_ALIGN - 1)) & ~((size_t)(ARENA_ALIGN - 1));
        if (aligned != hdr->used) {
            /* 填充字节置 0 */
            memset((char*)(*arena_p) + hdr->used, 0, aligned - hdr->used);
            hdr->used = aligned;
        }
        body = (char*)(*arena_p) + hdr->used;
    }
    hdr->used += size + 1;
    body[size] = 0;
    return body;
}

/*
 * arena_dup - 把字符串复制到 arena，返回 arena 内副本指针
 */
static char* arena_dup(void** arena_p, const char* s, size_t len)
{
    char* dst = arena_alloc(arena_p, len);
    if (dst == NULL) return NULL;
    memcpy(dst, s, len);
    dst[len] = 0;
    return dst;
}

/* ------------------------------------------------------------------ */
/* JSON 解析器状态                                                     */
/* ------------------------------------------------------------------ */
typedef struct {
    const char* buf;   /* 输入 JSON 文本                */
    size_t      pos;   /* 当前偏移                      */
    size_t      len;   /* 文本总长                      */
    void*       arena; /* 字符串 arena（与 arena_out 共享） */
    int         error; /* 0=OK；APISET_ERR_PARSE 等错误码 */
} JsonParser;

/* 跳过空白与注释 */
static void json_skip_ws(JsonParser* p)
{
    while (p->pos < p->len) {
        char c = p->buf[p->pos];
        if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
            ++p->pos;
            continue;
        }
        if (c == '/' && p->pos + 1 < p->len) {
            char next = p->buf[p->pos + 1];
            if (next == '/') {
                /* 行注释：直到 \n 或 EOF */
                p->pos += 2;
                while (p->pos < p->len && p->buf[p->pos] != '\n')
                    ++p->pos;
                continue;
            }
            if (next == '*') {
                /* 块注释：直到 *\/ */
                p->pos += 2;
                while (p->pos + 1 < p->len) {
                    if (p->buf[p->pos] == '*' && p->buf[p->pos + 1] == '/') {
                        p->pos += 2;
                        break;
                    }
                    ++p->pos;
                }
                /* 未闭合的块注释视为语法错误 */
                if (p->pos + 1 >= p->len &&
                    !(p->pos >= 2 && p->buf[p->pos - 2] == '*' &&
                      p->buf[p->pos - 1] == '/')) {
                    p->error = APISET_ERR_PARSE;
                    return;
                }
                continue;
            }
        }
        break;
    }
}

/* 解析 JSON 字符串：返回 arena 内副本指针；失败置 p->error */
static char* json_parse_string(JsonParser* p)
{
    /* 临时缓冲区：字符串值不可能超过输入长度 */
    char*  tmp;
    size_t tmp_len = 0;
    char*  result;

    if (p->pos >= p->len || p->buf[p->pos] != '"') {
        p->error = APISET_ERR_PARSE;
        return NULL;
    }
    ++p->pos;  /* 跳过起始 " */

    tmp = (char*)malloc(p->len - p->pos + 1);
    if (tmp == NULL) {
        p->error = APISET_ERR_NOMEM;
        return NULL;
    }

    while (p->pos < p->len) {
        char c = p->buf[p->pos++];
        if (c == '"') {
            /* 字符串结束 */
            tmp[tmp_len] = 0;
            result = arena_dup(&p->arena, tmp, tmp_len);
            free(tmp);
            if (result == NULL) p->error = APISET_ERR_NOMEM;
            return result;
        }
        if (c == '\\') {
            if (p->pos >= p->len) { p->error = APISET_ERR_PARSE; free(tmp); return NULL; }
            switch (p->buf[p->pos++]) {
                case '"':  tmp[tmp_len++] = '"';  break;
                case '\\': tmp[tmp_len++] = '\\'; break;
                case '/':  tmp[tmp_len++] = '/';  break;
                case 'n':  tmp[tmp_len++] = '\n'; break;
                case 't':  tmp[tmp_len++] = '\t'; break;
                case 'r':  tmp[tmp_len++] = '\r'; break;
                case 'b':  tmp[tmp_len++] = '\b'; break;
                case 'f':  tmp[tmp_len++] = '\f'; break;
                default:
                    /* 未知转义：原样保留反斜杠 + 字符 */
                    tmp[tmp_len++] = '\\';
                    tmp[tmp_len++] = p->buf[p->pos - 1];
                    break;
            }
        } else {
            /* 控制字符（< 0x20）非法 */
            if ((unsigned char)c < 0x20) {
                p->error = APISET_ERR_PARSE;
                free(tmp);
                return NULL;
            }
            tmp[tmp_len++] = c;
        }
    }
    /* 未闭合字符串 */
    p->error = APISET_ERR_PARSE;
    free(tmp);
    return NULL;
}

/* 跳过 JSON 值（对象/数组/字符串/字面 null/true/false），不解析内容
 *   用于忽略 schema 之外的字段或 entries 之外的顶层键
 *   返回 0=成功；-1=语法错误
 */
static int json_skip_value(JsonParser* p)
{
    json_skip_ws(p);
    if (p->error) return -1;
    if (p->pos >= p->len) { p->error = APISET_ERR_PARSE; return -1; }

    switch (p->buf[p->pos]) {
        case '{': {
            int rc;
            ++p->pos;
            json_skip_ws(p);
            if (p->error) return -1;
            if (p->pos < p->len && p->buf[p->pos] == '}') {
                ++p->pos;
                return 0;
            }
            for (;;) {
                char* key;
                json_skip_ws(p);
                if (p->error) return -1;
                key = json_parse_string(p);
                if (p->error) { if (key) {} return -1; }
                json_skip_ws(p);
                if (p->error) return -1;
                if (p->pos >= p->len || p->buf[p->pos] != ':') {
                    p->error = APISET_ERR_PARSE;
                    return -1;
                }
                ++p->pos;  /* 跳过 : */
                rc = json_skip_value(p);
                if (rc != 0) return rc;
                json_skip_ws(p);
                if (p->error) return -1;
                if (p->pos < p->len && p->buf[p->pos] == ',') {
                    ++p->pos;
                    continue;
                }
                if (p->pos < p->len && p->buf[p->pos] == '}') {
                    ++p->pos;
                    return 0;
                }
                p->error = APISET_ERR_PARSE;
                return -1;
            }
        }
        case '[': {
            ++p->pos;
            json_skip_ws(p);
            if (p->error) return -1;
            if (p->pos < p->len && p->buf[p->pos] == ']') {
                ++p->pos;
                return 0;
            }
            for (;;) {
                int rc = json_skip_value(p);
                if (rc != 0) return rc;
                json_skip_ws(p);
                if (p->error) return -1;
                if (p->pos < p->len && p->buf[p->pos] == ',') {
                    ++p->pos;
                    continue;
                }
                if (p->pos < p->len && p->buf[p->pos] == ']') {
                    ++p->pos;
                    return 0;
                }
                p->error = APISET_ERR_PARSE;
                return -1;
            }
        }
        case '"': {
            char* s = json_parse_string(p);
            if (p->error) { if (s) {} return -1; }
            return 0;
        }
        default: {
            /* 字面 null/true/false 或数字（跳过标识符/数字字符） */
            while (p->pos < p->len) {
                char c = p->buf[p->pos];
                if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                    (c >= '0' && c <= '9') || c == '-' || c == '+' ||
                    c == '.' || c == 'e' || c == 'E') {
                    ++p->pos;
                } else {
                    break;
                }
            }
            return 0;
        }
    }
}

/*
 * parse_kind_string - kind 字符串 -> ApiSetTargetKind 枚举
 *   返回 1=识别；0=未知
 */
static int parse_kind_string(const char* s, ApiSetTargetKind* out)
{
    if (s == NULL) return 0;
    if (strcmp(s, "to_real_dll") == 0) { *out = APISET_TO_REAL_DLL; return 1; }
    if (strcmp(s, "to_local")    == 0) { *out = APISET_TO_LOCAL;    return 1; }
    if (strcmp(s, "unsolvable")  == 0) { *out = APISET_UNSOLVABLE;  return 1; }
    return 0;
}

/*
 * parse_entry_object - 解析单个 entry 对象，调用 apiset_add 加入映射表
 *   p     ：解析器
 *   m     ：目标映射表
 *   返回 0=成功；-1=错误（p->error 已置位）
 */
static int parse_entry_object(JsonParser* p, ApiSetMap* m)
{
    char*              vname = NULL;
    char*              kind_str = NULL;
    char*              host  = NULL;
    char*              note  = NULL;
    ApiSetTargetKind   kind;
    int                seen_virtual_name = 0;
    int                seen_kind = 0;
    int                rc_add;

    json_skip_ws(p);
    if (p->error) return -1;
    if (p->pos >= p->len || p->buf[p->pos] != '{') {
        p->error = APISET_ERR_PARSE;
        return -1;
    }
    ++p->pos;
    json_skip_ws(p);
    if (p->error) return -1;
    if (p->pos < p->len && p->buf[p->pos] == '}') {
        ++p->pos;
        /* 空对象：跳过 */
        return 0;
    }
    for (;;) {
        char* key;
        json_skip_ws(p);
        if (p->error) return -1;
        key = json_parse_string(p);
        if (p->error) return -1;
        json_skip_ws(p);
        if (p->error) return -1;
        if (p->pos >= p->len || p->buf[p->pos] != ':') {
            p->error = APISET_ERR_PARSE;
            return -1;
        }
        ++p->pos;  /* 跳过 : */
        json_skip_ws(p);
        if (p->error) return -1;

        if (strcmp(key, "virtual_name") == 0) {
            vname = json_parse_string(p);
            if (p->error) return -1;
            seen_virtual_name = 1;
        } else if (strcmp(key, "kind") == 0) {
            kind_str = json_parse_string(p);
            if (p->error) return -1;
            seen_kind = 1;
        } else if (strcmp(key, "host_dll") == 0) {
            host = json_parse_string(p);
            if (p->error) return -1;
        } else if (strcmp(key, "note") == 0) {
            note = json_parse_string(p);
            if (p->error) return -1;
        } else {
            /* 未知字段：跳过其值 */
            if (json_skip_value(p) != 0) return -1;
        }

        json_skip_ws(p);
        if (p->error) return -1;
        if (p->pos < p->len && p->buf[p->pos] == ',') {
            ++p->pos;
            continue;
        }
        if (p->pos < p->len && p->buf[p->pos] == '}') {
            ++p->pos;
            break;
        }
        p->error = APISET_ERR_PARSE;
        return -1;
    }

    /* 校验必填字段 */
    if (!seen_virtual_name || vname == NULL || vname[0] == 0) {
        p->error = APISET_ERR_PARSE;
        return -1;
    }
    if (!seen_kind || kind_str == NULL) {
        p->error = APISET_ERR_PARSE;
        return -1;
    }
    if (!parse_kind_string(kind_str, &kind)) {
        p->error = APISET_ERR_PARSE;
        return -1;
    }
    if ((kind == APISET_TO_REAL_DLL || kind == APISET_TO_LOCAL) &&
        (host == NULL || host[0] == 0)) {
        p->error = APISET_ERR_PARSE;
        return -1;
    }

    rc_add = apiset_add(m, vname, kind,
                        (kind == APISET_UNSOLVABLE) ? NULL : host,
                        note);
    if (rc_add != APISET_OK) {
        p->error = rc_add;
        return -1;
    }
    return 0;
}

/*
 * apiset_load_from_json - 实现
 *   失败时不修改 m 的状态，arena 已释放并置 NULL
 */
int apiset_load_from_json(ApiSetMap* m, const char* json_text,
                          void** arena_out)
{
    JsonParser   p;
    ApiSetEntry* snap_entries;
    size_t       snap_count;
    size_t       snap_cap;
    int          saw_schema = 0;
    int          saw_entries = 0;

    if (arena_out) *arena_out = NULL;
    if (m == NULL || json_text == NULL) {
        return APISET_ERR_INVALID_ARG;
    }

    /* 失败回滚：保存原状态 */
    snap_entries = m->entries;
    snap_count   = m->count;
    snap_cap     = m->capacity;

    p.buf   = json_text;
    p.pos   = 0;
    p.len   = strlen(json_text);
    p.arena = NULL;
    p.error = 0;

    json_skip_ws(&p);
    if (p.error) goto fail;
    if (p.pos >= p.len || p.buf[p.pos] != '{') {
        p.error = APISET_ERR_PARSE;
        goto fail;
    }
    ++p.pos;
    json_skip_ws(&p);
    if (p.error) goto fail;
    if (p.pos < p.len && p.buf[p.pos] == '}') {
        ++p.pos;
        /* 空对象：合法但无 entries */
        goto done;
    }

    for (;;) {
        char* key;
        json_skip_ws(&p);
        if (p.error) goto fail;
        key = json_parse_string(&p);
        if (p.error) goto fail;
        json_skip_ws(&p);
        if (p.error) goto fail;
        if (p.pos >= p.len || p.buf[p.pos] != ':') {
            p.error = APISET_ERR_PARSE;
            goto fail;
        }
        ++p.pos;
        json_skip_ws(&p);
        if (p.error) goto fail;

        if (strcmp(key, "schema") == 0) {
            char* schema_val = json_parse_string(&p);
            if (p.error) goto fail;
            if (schema_val == NULL ||
                strcmp(schema_val, "win7bridge.apiset/v1") != 0) {
                p.error = APISET_ERR_SCHEMA;
                goto fail;
            }
            saw_schema = 1;
        } else if (strcmp(key, "entries") == 0) {
            /* 解析 entries 数组 */
            if (p.pos >= p.len || p.buf[p.pos] != '[') {
                p.error = APISET_ERR_PARSE;
                goto fail;
            }
            ++p.pos;
            json_skip_ws(&p);
            if (p.error) goto fail;
            if (p.pos < p.len && p.buf[p.pos] == ']') {
                ++p.pos;
                saw_entries = 1;
            } else {
                for (;;) {
                    if (parse_entry_object(&p, m) != 0) goto fail;
                    json_skip_ws(&p);
                    if (p.error) goto fail;
                    if (p.pos < p.len && p.buf[p.pos] == ',') {
                        ++p.pos;
                        continue;
                    }
                    if (p.pos < p.len && p.buf[p.pos] == ']') {
                        ++p.pos;
                        break;
                    }
                    p.error = APISET_ERR_PARSE;
                    goto fail;
                }
                saw_entries = 1;
            }
        } else {
            /* 未知顶层字段：跳过其值 */
            if (json_skip_value(&p) != 0) goto fail;
        }

        json_skip_ws(&p);
        if (p.error) goto fail;
        if (p.pos < p.len && p.buf[p.pos] == ',') {
            ++p.pos;
            continue;
        }
        if (p.pos < p.len && p.buf[p.pos] == '}') {
            ++p.pos;
            break;
        }
        p.error = APISET_ERR_PARSE;
        goto fail;
    }

    if (!saw_schema) {
        p.error = APISET_ERR_SCHEMA;
        goto fail;
    }
    (void)saw_entries;  /* entries 可省略 */

done:
    json_skip_ws(&p);
    if (p.pos != p.len) {
        /* 末尾应只有空白 */
        p.error = APISET_ERR_PARSE;
        goto fail;
    }
    if (arena_out) *arena_out = p.arena;
    return APISET_OK;

fail:
    /* 回滚：恢复 m 原状态 */
    m->entries  = snap_entries;
    m->count    = snap_count;
    m->capacity = snap_cap;
    /* 注意：snap 之后新加入的条目，其字符串都指向 p.arena；
       直接丢弃 entries 数组中由 snapshot 之后 realloc 得到的指针
       （与 snap_entries 可能相同也可能不同）。
       若 realloc 已扩展数组，原 snap_entries 仍可用；我们这里
       只是把指针还原，避免内存泄漏由调用方负责。 */
    if (p.arena) {
        free(p.arena);
        p.arena = NULL;
    }
    if (arena_out) *arena_out = NULL;
    return p.error ? p.error : APISET_ERR_PARSE;
}

/*
 * apiset_load_from_file - 实现
 *   用 fopen/fread/fclose 读取整个文件到内存，再调 apiset_load_from_json
 */
int apiset_load_from_file(ApiSetMap* m, const char* path,
                          void** arena_out)
{
    FILE*       fp;
    long        fsize;
    size_t      nread;
    char*       buf;
    int         rc;

    if (arena_out) *arena_out = NULL;
    if (m == NULL || path == NULL) {
        return APISET_ERR_INVALID_ARG;
    }

    fp = fopen(path, "rb");
    if (fp == NULL) {
        return APISET_ERR_IO;
    }
    if (fseek(fp, 0, SEEK_END) != 0) {
        fclose(fp);
        return APISET_ERR_IO;
    }
    fsize = ftell(fp);
    if (fsize < 0) {
        fclose(fp);
        return APISET_ERR_IO;
    }
    if (fseek(fp, 0, SEEK_SET) != 0) {
        fclose(fp);
        return APISET_ERR_IO;
    }

    buf = (char*)malloc((size_t)fsize + 1);
    if (buf == NULL) {
        fclose(fp);
        return APISET_ERR_NOMEM;
    }
    nread = fread(buf, 1, (size_t)fsize, fp);
    fclose(fp);
    if (nread != (size_t)fsize) {
        free(buf);
        return APISET_ERR_IO;
    }
    buf[nread] = 0;

    rc = apiset_load_from_json(m, buf, arena_out);
    free(buf);
    return rc;
}

/*
 * apiset_free_arena - 释放 JSON arena
 */
void apiset_free_arena(void* arena)
{
    if (arena == NULL) return;
    free(arena);
}

/*
 * apiset_free - 释放映射表本身
 */
void apiset_free(ApiSetMap* m)
{
    if (m == NULL) return;
    if (m->entries != NULL) {
        free(m->entries);
        m->entries = NULL;
    }
    m->count    = 0;
    m->capacity = 0;
}
