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
 */
#include "win7bridge/apiset.h"

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
/* ------------------------------------------------------------------ */
int apiset_load_default(ApiSetMap* m)
{
    int rc;

    if (m == NULL) {
        return APISET_ERR_INVALID_ARG;
    }

    /* ---- 同步原语：本地模拟（WaitOnAddress 体系） ---- */
    rc = apiset_add(m, "api-ms-win-core-synch-l1-2-0",
                    APISET_TO_LOCAL, "win7bridge_local",
                    "WaitOnAddress 体系，本地事件对象模拟");
    if (rc != APISET_OK) return rc;

    /* ---- timezone / file / localization / processthreads：转发 kernel32 ---- */
    rc = apiset_add(m, "api-ms-win-core-timezone-l1-1-0",
                    APISET_TO_REAL_DLL, "kernel32.dll",
                    "Win7 kernel32 含时区 API");
    if (rc != APISET_OK) return rc;

    rc = apiset_add(m, "api-ms-win-core-file-l1-2-0",
                    APISET_TO_REAL_DLL, "kernel32.dll",
                    "Win7 kernel32 含基础文件 API");
    if (rc != APISET_OK) return rc;

    rc = apiset_add(m, "api-ms-win-core-file-l2-1-0",
                    APISET_TO_REAL_DLL, "kernel32.dll",
                    "Win7 kernel32 含扩展文件 API");
    if (rc != APISET_OK) return rc;

    rc = apiset_add(m, "api-ms-win-core-localization-l1-2-0",
                    APISET_TO_REAL_DLL, "kernel32.dll",
                    "Win7 kernel32 含本地化 API");
    if (rc != APISET_OK) return rc;

    rc = apiset_add(m, "api-ms-win-core-processthreads-l1-1-1",
                    APISET_TO_REAL_DLL, "kernel32.dll",
                    "Win7 kernel32 含进程线程 API");
    if (rc != APISET_OK) return rc;

    /* ---- memory l1-1-3+ ：VirtualAlloc2 退化到本地模拟 ---- */
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

    /* ---- xstate：AVX 扩展上下文，Win7 无 ---- */
    rc = apiset_add(m, "api-ms-win-core-xstate-l2-1-0",
                    APISET_UNSOLVABLE, NULL,
                    "AVX 扩展上下文，Win7 无");
    if (rc != APISET_OK) return rc;

    /* ---- WinRT：完全不可解 ---- */
    rc = apiset_add(m, "api-ms-win-core-winrt-l1-1-0",
                    APISET_UNSOLVABLE, NULL,
                    "WinRT，不可解");
    if (rc != APISET_OK) return rc;

    rc = apiset_add(m, "api-ms-win-core-winrt-string-l1-1-0",
                    APISET_UNSOLVABLE, NULL,
                    "WinRT，不可解");
    if (rc != APISET_OK) return rc;

    rc = apiset_add(m, "api-ms-win-core-winrt-error-l1-1-0",
                    APISET_UNSOLVABLE, NULL,
                    "WinRT，不可解");
    if (rc != APISET_OK) return rc;

    /* ---- COM：转发 ole32 ---- */
    rc = apiset_add(m, "api-ms-win-core-com-l1-1-1",
                    APISET_TO_REAL_DLL, "ole32.dll",
                    "Win7 ole32 含 COM 基础 API");
    if (rc != APISET_OK) return rc;

    /* ---- DPI / Shell scaling：本地模拟 ---- */
    rc = apiset_add(m, "api-ms-win-shcore-scaling-l1-1-0",
                    APISET_TO_LOCAL, "win7bridge_local",
                    "DPI awareness，回退 SetProcessDPIAware");
    if (rc != APISET_OK) return rc;

    /* ---- UCRT：靠 KB2999226 提供 ucrtbase.dll ---- */
    rc = apiset_add(m, "api-ms-win-crt-runtime-l1-1-0",
                    APISET_TO_REAL_DLL, "ucrtbase.dll",
                    "UCRT，靠 KB2999226");
    if (rc != APISET_OK) return rc;

    rc = apiset_add(m, "api-ms-win-crt-stdio-l1-1-0",
                    APISET_TO_REAL_DLL, "ucrtbase.dll",
                    "UCRT，靠 KB2999226");
    if (rc != APISET_OK) return rc;

    rc = apiset_add(m, "api-ms-win-crt-heap-l1-1-0",
                    APISET_TO_REAL_DLL, "ucrtbase.dll",
                    "UCRT，靠 KB2999226");
    if (rc != APISET_OK) return rc;

    /* ---- 扩展 API set：逐项评估，默认不可解 ---- */
    rc = apiset_add(m, "ext-ms-win-core-winrt-l1-1-0",
                    APISET_UNSOLVABLE, NULL,
                    "扩展 API set，逐项评估");
    if (rc != APISET_OK) return rc;

    rc = apiset_add(m, "ext-ms-win-core-winrt-string-l1-1-0",
                    APISET_UNSOLVABLE, NULL,
                    "扩展 API set，逐项评估");
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
