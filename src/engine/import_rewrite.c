/*
 * import_rewrite.c - Win7Bridge L1 符号级重写引擎实现
 *
 * 实现 engine.h 中的接口：引擎规则表管理、导入表改写、规则查询。
 *
 * 设计要点：
 *   - 规则表用动态数组（realloc 扩容），字符串由调用方保活
 *   - engine_rewrite_imports 遍历导入描述符数组：
 *       * 匹配 DllRedirect：覆盖 DLL 名字符串（带边界检查）
 *       * 匹配 ExportRedirect：遍历 ILT 找到按名导入项，改写对应 IAT thunk
 *   - 内存可写性：Windows 下用 VirtualProtect（extern 声明，不 include
 *     windows.h）；host/syntax-check 下缓冲区本身可写，空操作
 *   - 大小写不敏感比较：Windows DLL/导出名不区分大小写
 */
#include "win7bridge/engine.h"

#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* ------------------------------------------------------------------ */
/* 内部辅助                                                            */
/* ------------------------------------------------------------------ */

/* 大小写不敏感字符串相等比较（避免依赖非标准 strings.h）              */
static int engine_ieq(const char* a, const char* b)
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
static int engine_in_bounds(const PeInfo* pe, size_t off, size_t need)
{
    return (pe != NULL) && (off <= pe->size) && (need <= pe->size - off);
}

/*
 * Windows 下用 VirtualProtect 把 [addr, addr+size) 改为可写；
 * host/syntax-check 下缓冲区本身可写，空操作。
 * 不 #include <windows.h>：用 extern 声明 VirtualProtect。
 */
#if defined(_WIN32) && !defined(WIN7BRIDGE_HOST_TEST) && !defined(WIN7BRIDGE_SYNTAX_CHECK)
extern __declspec(dllimport) int __stdcall
VirtualProtect(void* lpAddress, size_t dwSize,
               unsigned long flNewProtect, unsigned long* lpflOldProtect);
#define ENGINE_PAGE_READWRITE 0x04U
static int engine_protect_rw(void* addr, size_t size, unsigned long* old_prot)
{
    return VirtualProtect(addr, size, ENGINE_PAGE_READWRITE, old_prot) ? 0 : -1;
}
#else
static int engine_protect_rw(void* addr, size_t size, unsigned long* old_prot)
{
    (void)addr; (void)size; (void)old_prot;
    return 0;  /* host：缓冲区已可写 */
}
#endif

/* ------------------------------------------------------------------ */
/* engine_init                                                         */
/* ------------------------------------------------------------------ */
int engine_init(RewriteEngine* e)
{
    if (e == NULL) {
        return ENGINE_ERR_INVALID_ARG;
    }
    e->dll_rules  = NULL;
    e->dll_count  = 0;
    e->dll_cap    = 0;
    e->func_rules = NULL;
    e->func_count = 0;
    e->func_cap   = 0;
    return ENGINE_OK;
}

/* ------------------------------------------------------------------ */
/* engine_add_dll_redirect                                             */
/* ------------------------------------------------------------------ */
int engine_add_dll_redirect(RewriteEngine* e, const char* orig, const char* forward)
{
    DllRedirect* p;
    size_t new_cap;

    if (e == NULL || orig == NULL || forward == NULL) {
        return ENGINE_ERR_INVALID_ARG;
    }
    if (e->dll_count == e->dll_cap) {
        new_cap = e->dll_cap ? e->dll_cap * 2 : 8;
        p = (DllRedirect*)realloc(e->dll_rules, new_cap * sizeof(*p));
        if (p == NULL) {
            return ENGINE_ERR_NOMEM;
        }
        e->dll_rules = p;
        e->dll_cap   = new_cap;
    }
    e->dll_rules[e->dll_count].orig_dll    = orig;
    e->dll_rules[e->dll_count].forward_dll = forward;
    e->dll_count++;
    return ENGINE_OK;
}

/* ------------------------------------------------------------------ */
/* engine_add_func_redirect                                            */
/* ------------------------------------------------------------------ */
int engine_add_func_redirect(RewriteEngine* e, const char* dll, const char* func,
                             RewriteKind kind, void* replacement)
{
    ExportRedirect* p;
    size_t new_cap;

    if (e == NULL || dll == NULL || func == NULL) {
        return ENGINE_ERR_INVALID_ARG;
    }
    if (kind != REWRITE_REPLACE_FUNC && kind != REWRITE_STUB) {
        return ENGINE_ERR_INVALID_ARG;
    }
    if (e->func_count == e->func_cap) {
        new_cap = e->func_cap ? e->func_cap * 2 : 8;
        p = (ExportRedirect*)realloc(e->func_rules, new_cap * sizeof(*p));
        if (p == NULL) {
            return ENGINE_ERR_NOMEM;
        }
        e->func_rules = p;
        e->func_cap   = new_cap;
    }
    e->func_rules[e->func_count].dll_name    = dll;
    e->func_rules[e->func_count].func_name   = func;
    e->func_rules[e->func_count].kind        = kind;
    e->func_rules[e->func_count].replacement = replacement;
    e->func_count++;
    return ENGINE_OK;
}

/* ------------------------------------------------------------------ */
/* engine_find_func_redirect                                           */
/* ------------------------------------------------------------------ */
int engine_find_func_redirect(RewriteEngine* e, const char* dll, const char* func,
                              ExportRedirect* out)
{
    size_t i;

    if (e == NULL || dll == NULL || func == NULL || out == NULL) {
        return ENGINE_ERR_INVALID_ARG;
    }
    for (i = 0; i < e->func_count; ++i) {
        if (engine_ieq(e->func_rules[i].dll_name, dll) &&
            engine_ieq(e->func_rules[i].func_name, func)) {
            *out = e->func_rules[i];
            return 1;
        }
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* 内部：把 IAT 中位于 thunk_rva 的一个 thunk 改写为 replacement        */
/* ------------------------------------------------------------------ */
static int engine_patch_iat_thunk(PeInfo* pe, DWORD thunk_rva, size_t thunk_size,
                                  void* replacement, unsigned long* old_prot)
{
    unsigned char* base;
    if (!engine_in_bounds(pe, thunk_rva, thunk_size)) {
        return ENGINE_ERR_BAD_PE;
    }
    base = (unsigned char*)pe->data + thunk_rva;
    if (engine_protect_rw(base, thunk_size, old_prot) != 0) {
        return ENGINE_ERR_BAD_PE;
    }
    if (thunk_size == sizeof(QWORD)) {
        *(QWORD*)base = (QWORD)(uintptr_t)replacement;
    } else {
        *(DWORD*)base = (DWORD)(uintptr_t)replacement;
    }
    return ENGINE_OK;
}

/* ------------------------------------------------------------------ */
/* engine_rewrite_imports                                              */
/* ------------------------------------------------------------------ */
int engine_rewrite_imports(RewriteEngine* e, PeInfo* pe)
{
    IMAGE_DATA_DIRECTORY* dir;
    DWORD dir_va, dir_sz;
    size_t off;
    size_t thunk_size;
    int changed = 0;
    unsigned long old_prot = 0;

    if (e == NULL || pe == NULL || pe->data_dir == NULL) {
        return ENGINE_ERR_INVALID_ARG;
    }

    dir = &pe->data_dir[IMAGE_DIRECTORY_ENTRY_IMPORT];
    dir_va = dir->VirtualAddress;
    dir_sz = dir->Size;
    if (dir_va == 0 || dir_sz == 0) {
        return 0;  /* 无导入表，无需改写 */
    }
    thunk_size = pe->is64 ? sizeof(QWORD) : sizeof(DWORD);

    off = 0;
    while (off + sizeof(IMAGE_IMPORT_DESCRIPTOR) <= dir_sz) {
        IMAGE_IMPORT_DESCRIPTOR* d;
        const char* dll_name;
        size_t abs_off = dir_va + off;
        DllRedirect* dr = NULL;
        size_t k;

        if (!engine_in_bounds(pe, abs_off, sizeof(IMAGE_IMPORT_DESCRIPTOR))) {
            break;
        }
        d = (IMAGE_IMPORT_DESCRIPTOR*)((unsigned char*)pe->data + abs_off);

        /* 终止项 */
        if (d->Name == 0 && d->OriginalFirstThunk == 0 && d->FirstThunk == 0) {
            break;
        }

        /* 取 DLL 名（RVA -> 指针） */
        dll_name = NULL;
        if (d->Name != 0 && engine_in_bounds(pe, d->Name, 1)) {
            dll_name = (const char*)pe->data + d->Name;
        }

        /* 查找匹配的整 DLL 转发规则 */
        for (k = 0; k < e->dll_count; ++k) {
            if (dll_name != NULL &&
                engine_ieq(e->dll_rules[k].orig_dll, dll_name)) {
                dr = &e->dll_rules[k];
                break;
            }
        }

        /* ① 应用整 DLL 转发：覆盖 DLL 名字符串为 forward_dll */
        if (dr != NULL && dll_name != NULL) {
            const char* fwd = dr->forward_dll;
            size_t name_off = d->Name;
            size_t fwd_len  = strlen(fwd) + 1;   /* 含 NUL */
            size_t avail    = pe->size - name_off;
            if (avail < fwd_len) {
                return ENGINE_ERR_NO_ROOM;
            }
            if (engine_protect_rw((unsigned char*)pe->data + name_off,
                                  fwd_len, &old_prot) != 0) {
                return ENGINE_ERR_BAD_PE;
            }
            memcpy((unsigned char*)pe->data + name_off, fwd, fwd_len);
            ++changed;
            /* 名字已变，更新本地指针以便后续 func_rules 匹配使用新名 */
            dll_name = (const char*)pe->data + name_off;
        }

        /* ② 应用单导出替换：遍历 ILT 找按名导入，改写对应 IAT thunk */
        if (dll_name != NULL && e->func_count > 0) {
            DWORD ilt_rva = d->OriginalFirstThunk ? d->OriginalFirstThunk
                                                  : d->FirstThunk;
            DWORD iat_rva = d->FirstThunk;
            size_t thunk_off = 0;

            if (ilt_rva != 0 && iat_rva != 0) {
                for (;;) {
                    size_t ilt_abs = (size_t)ilt_rva + thunk_off;
                    size_t iat_abs = (size_t)iat_rva + thunk_off;
                    const void* tp;
                    QWORD tv = 0;

                    if (!engine_in_bounds(pe, ilt_abs, thunk_size) ||
                        !engine_in_bounds(pe, iat_abs, thunk_size)) {
                        break;
                    }
                    tp = (const unsigned char*)pe->data + ilt_abs;
                    if (pe->is64) {
                        tv = *(const QWORD*)tp;
                    } else {
                        tv = *(const DWORD*)tp;
                    }
                    if (tv == 0) {
                        break;  /* thunks 终止 */
                    }

                    /* 仅处理按名导入（低位置 0）；按序号暂不支持替换 */
                    if ((pe->is64 && !(tv & 0x8000000000000000ULL)) ||
                        (!pe->is64 && !(tv & 0x80000000UL))) {
                        DWORD name_rva = (DWORD)(tv & (pe->is64
                                ? 0x7FFFFFFFFFFFFFFFULL
                                : 0x7FFFFFFFUL));
                        /* 至少需读 Hint(2) + 1 字节名 */
                        if (engine_in_bounds(pe, name_rva,
                                             sizeof(WORD) + 1)) {
                            const IMAGE_IMPORT_BY_NAME* ibn =
                                (const IMAGE_IMPORT_BY_NAME*)
                                ((const unsigned char*)pe->data + name_rva);
                            for (k = 0; k < e->func_count; ++k) {
                                if (engine_ieq(e->func_rules[k].dll_name,
                                               dll_name) &&
                                    engine_ieq(e->func_rules[k].func_name,
                                               (const char*)ibn->Name)) {
                                    int rc = engine_patch_iat_thunk(
                                        pe, (DWORD)iat_abs, thunk_size,
                                        e->func_rules[k].replacement,
                                        &old_prot);
                                    if (rc < 0) {
                                        return rc;
                                    }
                                    ++changed;
                                    break;
                                }
                            }
                        }
                    }
                    thunk_off += thunk_size;
                }
            }
        }

        off += sizeof(IMAGE_IMPORT_DESCRIPTOR);
    }

    return changed;
}
