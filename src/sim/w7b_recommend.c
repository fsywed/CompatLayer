/*
 * w7b_recommend.c - Win7Bridge 自动推荐引擎实现（SubTask 3.4.3）
 *
 * 实现：
 *   - w7b_recommend_from_pe：扫描 PE 导入表 + manifest XML，分类依赖、
 *     识别可模拟 API、记录不可解项。
 *   - w7b_recommend_apply：把推荐结果应用到 W7bProgramConfig。
 *
 * 设计要点见 docs/recommend-engine.md：
 *   - 纯函数：不分配堆内存，结果存调用方传入的固定数组；超出上限截断。
 *   - 复用 apiset_is_virtual_name 判定 api-ms-* / ext-ms-* 前缀。
 *   - manifest 扫描用简单字符串匹配（与 manifest.c 风格一致），
 *     不依赖完整 XML 解析器。
 *   - 去重：emulated_apis 与 unresolvable 列表内同名条目只入一次。
 *
 * 不依赖 <windows.h>。PE 类型来自 pe_types.h。
 */
#include "win7bridge/w7b_recommend.h"
#include "win7bridge/apiset.h"      /* apiset_is_virtual_name            */
#include "win7bridge/manifest.h"    /* WIN7/10_SUPPORTEDOS_GUID 常量     */

#include <string.h>

/* ------------------------------------------------------------------ */
/* 内部：大小写不敏感字符串比较                                         */
/* ------------------------------------------------------------------ */
static int rec_ieq(const char* a, const char* b)
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

/* 大小写不敏感前缀匹配 */
static int rec_starts_with_ci(const char* s, const char* prefix)
{
    if (s == NULL || prefix == NULL) return 0;
    while (*prefix) {
        char cs = *s, cp = *prefix;
        if (cs == 0) return 0;
        if (cs >= 'a' && cs <= 'z') cs = (char)(cs - 32);
        if (cp >= 'a' && cp <= 'z') cp = (char)(cp - 32);
        if (cs != cp) return 0;
        ++s; ++prefix;
    }
    return 1;
}

/* ------------------------------------------------------------------ */
/* 可模拟 API 表（与 scripts/config_gen.py EMULATABLE_APIS 对齐）       */
/* ------------------------------------------------------------------ */
static const char* const kEmulatableApis[] = {
    "GetSystemTimePreciseAsFileTime",
    "WaitOnAddress",
    "WakeByAddressSingle",
    "WakeByAddressAll",
    "VirtualAlloc2",
    "VirtualAlloc2FromApp",
    "MapViewOfFileNuma2",
    "UnmapViewOfFileEx",
    "SetThreadDescription",
    "GetThreadDescription",
    "CreatePseudoConsole",
    "ClosePseudoConsole",
    "ResizePseudoConsole",
    "SetProcessDpiAwarenessContext",
    "EnableMouseInPointer",
    NULL
};

/* ------------------------------------------------------------------ */
/* 内部：[off, off+need) 是否完全落在 PE 缓冲区内                       */
/* ------------------------------------------------------------------ */
static int rec_in_bounds(const PeInfo* pe, size_t off, size_t need)
{
    return (pe != NULL) && (off <= pe->size) && (need <= pe->size - off);
}

/* ------------------------------------------------------------------ */
/* 内部：把 (dll_name + 原因) 追加到 unresolvable 列表                  */
/*   去重：相同 dll_name（大小写不敏感）已存在则不重复加入。            */
/*   超出上限：截断（不报错）。                                          */
/* ------------------------------------------------------------------ */
static void rec_add_unresolvable(W7bRecommendResult* rec,
                                 const char* dll_name,
                                 const char* reason)
{
    size_t i;
    char* dst;
    size_t dll_len, reason_len, total;

    if (rec == NULL || dll_name == NULL) return;
    if (rec->unresolvable_count >= W7B_REC_UNSOLV_MAX) return;

    /* 去重：仅按 dll_name 比较 */
    for (i = 0; i < rec->unresolvable_count; ++i) {
        /* unresolvable[i] 形如 "dllname: reason"，取首段比较 */
        const char* entry = rec->unresolvable[i];
        size_t j = 0;
        while (entry[j] != 0 && entry[j] != ':') ++j;
        if (entry[j] == ':') {
            size_t k = j;
            /* 取 [0, k) 与 dll_name 比较 */
            char tmp[W7B_REC_UNSOLV_TEXT];
            if (k >= sizeof(tmp)) k = sizeof(tmp) - 1;
            memcpy(tmp, entry, k);
            tmp[k] = 0;
            if (rec_ieq(tmp, dll_name)) {
                return;  /* 已存在 */
            }
        }
    }

    dst = rec->unresolvable[rec->unresolvable_count];
    dll_len = strlen(dll_name);
    reason_len = (reason != NULL) ? strlen(reason) : 0;
    total = dll_len + 2 + reason_len;  /* "dll: reason" */
    if (total >= W7B_REC_UNSOLV_TEXT) {
        /* 截断 reason 以适应缓冲区 */
        size_t avail = W7B_REC_UNSOLV_TEXT - 1;
        size_t reason_avail;
        if (avail <= dll_len + 2) {
            /* 仅装得下 dll_name */
            memcpy(dst, dll_name, avail);
            dst[avail] = 0;
        } else {
            reason_avail = avail - dll_len - 2;
            memcpy(dst, dll_name, dll_len);
            dst[dll_len] = ':';
            dst[dll_len + 1] = ' ';
            memcpy(dst + dll_len + 2, reason, reason_avail);
            dst[dll_len + 2 + reason_avail] = 0;
        }
    } else {
        memcpy(dst, dll_name, dll_len);
        dst[dll_len] = ':';
        dst[dll_len + 1] = ' ';
        if (reason_len > 0) {
            memcpy(dst + dll_len + 2, reason, reason_len);
        }
        dst[dll_len + 2 + reason_len] = 0;
    }
    rec->unresolvable_count++;
}

/* ------------------------------------------------------------------ */
/* 内部：把函数名追加到 emulated_apis 列表                              */
/*   去重：相同函数名已存在则不重复加入。                                */
/*   超出上限：截断。                                                    */
/* ------------------------------------------------------------------ */
static void rec_add_emulated(W7bRecommendResult* rec, const char* func_name)
{
    size_t i, len;
    if (rec == NULL || func_name == NULL) return;
    if (rec->emulated_apis_count >= W7B_REC_EMULATED_MAX) return;

    /* 去重 */
    for (i = 0; i < rec->emulated_apis_count; ++i) {
        if (rec_ieq(rec->emulated_apis[i], func_name)) {
            return;
        }
    }

    len = strlen(func_name);
    if (len >= W7B_REC_EMULATED_NAME) {
        len = W7B_REC_EMULATED_NAME - 1;
    }
    memcpy(rec->emulated_apis[rec->emulated_apis_count], func_name, len);
    rec->emulated_apis[rec->emulated_apis_count][len] = 0;
    rec->emulated_apis_count++;
}

/* ------------------------------------------------------------------ */
/* 内部：遍历单个导入描述符的 ILT，对每个按名导入的函数查可模拟 API 表  */
/*   pe ：PE 信息                                                       */
/*   ilt_rva ：ILT 的 RVA（OriginalFirstThunk；可为 0 退化为 FirstThunk）*/
/*   iat_rva ：IAT 的 RVA（FirstThunk，ILT 缺失时用）                   */
/* ------------------------------------------------------------------ */
static void rec_scan_import_thunks(const PeInfo* pe,
                                   DWORD ilt_rva,
                                   DWORD iat_rva,
                                   W7bRecommendResult* rec)
{
    DWORD thunk_rva;
    size_t off;

    if (pe == NULL || rec == NULL) return;
    thunk_rva = ilt_rva;
    if (thunk_rva == 0) thunk_rva = iat_rva;
    if (thunk_rva == 0) return;

    off = thunk_rva;
    while (1) {
        const void* thunk_p;
        int is_ordinal;
        const char* func_name = NULL;
        const IMAGE_IMPORT_BY_NAME* ibn;
        const char* const* p;

        /* PE32+ 每项 8 字节，PE32 每项 4 字节 */
        size_t thunk_size = pe->is64 ? 8 : 4;
        if (!rec_in_bounds(pe, off, thunk_size)) break;

        thunk_p = (const unsigned char*)pe->data + off;

        if (pe->is64) {
            /* 读 64 位 thunk；高位置 1 = ordinal，否则为 RVA */
            unsigned long long v = 0;
            const unsigned char* b = (const unsigned char*)thunk_p;
            v = ((unsigned long long)b[0]) |
                ((unsigned long long)b[1] << 8) |
                ((unsigned long long)b[2] << 16) |
                ((unsigned long long)b[3] << 24) |
                ((unsigned long long)b[4] << 32) |
                ((unsigned long long)b[5] << 40) |
                ((unsigned long long)b[6] << 48) |
                ((unsigned long long)b[7] << 56);
            if (v == 0) break;  /* 终止项 */
            is_ordinal = (v & 0x8000000000000000ULL) ? 1 : 0;
            if (!is_ordinal) {
                DWORD rva = (DWORD)(v & 0x7FFFFFFFu);
                if (rec_in_bounds(pe, rva, sizeof(IMAGE_IMPORT_BY_NAME))) {
                    ibn = (const IMAGE_IMPORT_BY_NAME*)
                          ((const unsigned char*)pe->data + rva);
                    func_name = (const char*)ibn->Name;
                }
            }
        } else {
            /* PE32：4 字节 thunk */
            DWORD v = *(const DWORD*)thunk_p;
            if (v == 0) break;  /* 终止项 */
            is_ordinal = (v & 0x80000000u) ? 1 : 0;
            if (!is_ordinal) {
                DWORD rva = v & 0x7FFFFFFFu;
                if (rec_in_bounds(pe, rva, sizeof(IMAGE_IMPORT_BY_NAME))) {
                    ibn = (const IMAGE_IMPORT_BY_NAME*)
                          ((const unsigned char*)pe->data + rva);
                    func_name = (const char*)ibn->Name;
                }
            }
        }

        if (func_name != NULL) {
            /* 与可模拟 API 表逐项比较 */
            for (p = kEmulatableApis; *p != NULL; ++p) {
                if (rec_ieq(func_name, *p)) {
                    rec_add_emulated(rec, *p);
                    break;
                }
            }
        }

        off += thunk_size;
    }
}

/* ------------------------------------------------------------------ */
/* 内部：对单个导入 DLL 名做分类                                        */
/*   - api-ms-win-crt-* / ucrtbase.dll         -> has_ucrt_dependency   */
/*   - api-ms-win-core-winrt-* / combase.dll   -> has_winrt + unsupport */
/*     winrtbase.dll                                                   */
/*   - d3d12.dll                               -> has_d3d12 + unsupport  */
/*   - api-ms-win-core-winrt-*                 -> 不可解 WinRT          */
/*   - 其他 api-ms-* / ext-ms-* 未识别的虚拟名 -> 不可解未知扩展        */
/* ------------------------------------------------------------------ */
static void rec_classify_dll(const char* dll_name,
                             W7bRecommendResult* rec)
{
    if (dll_name == NULL || rec == NULL) return;

    /* UCRT 依赖 */
    if (rec_starts_with_ci(dll_name, "api-ms-win-crt-")) {
        rec->has_ucrt_dependency = 1;
        return;
    }
    if (rec_ieq(dll_name, "ucrtbase.dll") ||
        rec_ieq(dll_name, "ucrtbase")) {
        rec->has_ucrt_dependency = 1;
        return;
    }

    /* WinRT 依赖 */
    if (rec_starts_with_ci(dll_name, "api-ms-win-core-winrt-") ||
        rec_starts_with_ci(dll_name, "api-ms-win-core-winrt-l1-1-0") ||
        rec_ieq(dll_name, "combase.dll") ||
        rec_ieq(dll_name, "winrtbase.dll") ||
        rec_ieq(dll_name, "api-ms-win-core-winrt-error-l1-1-0") ||
        rec_ieq(dll_name, "api-ms-win-core-winrt-string-l1-1-0") ||
        rec_ieq(dll_name, "api-ms-win-core-winrt-robuffer-l1-1-0")) {
        rec->has_winrt_dependency = 1;
        rec->unsupported_overall = 1;
        rec_add_unresolvable(rec, dll_name, "WinRT not supported on Win7");
        return;
    }

    /* D3D12 依赖 */
    if (rec_ieq(dll_name, "d3d12.dll") || rec_ieq(dll_name, "d3d12")) {
        rec->has_d3d12_dependency = 1;
        rec->unsupported_overall = 1;
        rec_add_unresolvable(rec, dll_name, "D3D12 requires WDDM 2.0");
        return;
    }

    /* VBS 依赖（虚拟化安全）：vgauth.dll / vmcompute.dll            */
    if (rec_ieq(dll_name, "vgauth.dll") ||
        rec_ieq(dll_name, "vmcompute.dll")) {
        rec->has_vbs_dependency = 1;
        rec->unsupported_overall = 1;
        rec_add_unresolvable(rec, dll_name, "VBS requires Win10 HVCI");
        return;
    }

    /* TPM2.0 依赖：tbs.dll（TPM Base Services）                     */
    if (rec_ieq(dll_name, "tbs.dll")) {
        rec->has_tpm_dependency = 1;
        rec->unsupported_overall = 1;
        rec_add_unresolvable(rec, dll_name, "TPM2.0 TBS requires Win8+");
        return;
    }

    /* 其他虚拟名（api-ms-* / ext-ms-*）：未知扩展，标注不可解 */
    if (apiset_is_virtual_name(dll_name)) {
        /* 与已知 WinRT/D3D12/UCRT 已分类的之外，标为未知虚拟名 */
        rec_add_unresolvable(rec, dll_name, "unknown virtual api set");
        return;
    }

    /* 普通真实 DLL，忽略 */
}

/* ------------------------------------------------------------------ */
/* 内部：扫描 manifest XML                                              */
/*   - 找 <supportedOS Id="...">，提取 GUID 与 Win7/Win10 常量比较      */
/*   - 子串扫描 <maxversiontested / <msix / <catalog，计 Win10-only 数 */
/* ------------------------------------------------------------------ */
static void rec_scan_manifest(const char* xml, W7bRecommendResult* rec)
{
    const char* p;
    int found_win7 = 0;
    int found_win10 = 0;
    int win10_only_count = 0;
    const char* const kWin10OnlyTags[] = {
        "<maxversiontested",
        "<msix",
        "<catalog",
        NULL
    };
    const char* const* pt;

    if (xml == NULL || rec == NULL) return;
    if (*xml == 0) return;

    rec->manifest_present = 1;

    /* 1. supportedOS Id 扫描 */
    p = xml;
    while ((p = strstr(p, "supportedOS")) != NULL) {
        /* 从 p 开始往后找 Id= */
        const char* id_p = strstr(p, "Id");
        const char* close_p;
        const char* guid_start = NULL;
        size_t i;

        /* 限制在当前 supportedOS 节点范围内：找最近的 '>' */
        close_p = strchr(p, '>');
        if (close_p == NULL) break;

        if (id_p != NULL && id_p < close_p) {
            /* 找 Id 之后的引号 */
            const char* q = id_p + 2;
            while (*q == ' ' || *q == '\t' || *q == '=' ||
                   *q == '"' || *q == '\'') {
                ++q;
            }
            if (*q == '{') {
                guid_start = q;
                /* GUID 长度约 38 字符（带花括号） */
                for (i = 0; i < 64 && guid_start[i] != 0 &&
                             guid_start[i] != '}'; ++i) {
                    /* 累计到 } */
                }
                if (guid_start[i] == '}') {
                    /* 取 [guid_start, guid_start+i+1] 与 Win7/Win10 常量比较 */
                    char tmp[64];
                    size_t guid_len = i + 1;
                    if (guid_len >= sizeof(tmp)) guid_len = sizeof(tmp) - 1;
                    memcpy(tmp, guid_start, guid_len);
                    tmp[guid_len] = 0;
                    if (rec_ieq(tmp, WIN7_SUPPORTEDOS_GUID)) {
                        found_win7 = 1;
                    } else if (rec_ieq(tmp, WIN10_SUPPORTEDOS_GUID)) {
                        found_win10 = 1;
                    }
                }
            }
        }
        p = close_p + 1;
    }

    rec->manifest_has_win7_guid = found_win7;
    rec->manifest_has_win10_guid = found_win10;
    /* 需要注入 Win7 GUID 的条件：manifest 存在但不含 Win7 GUID */
    rec->manifest_needs_inject_win7 = found_win7 ? 0 : 1;

    /* 2. Win10-only 元素计数 */
    for (pt = kWin10OnlyTags; *pt != NULL; ++pt) {
        p = xml;
        while ((p = strstr(p, *pt)) != NULL) {
            ++win10_only_count;
            p += strlen(*pt);
        }
    }
    rec->manifest_win10_only_count = win10_only_count;
}

/* ------------------------------------------------------------------ */
/* 公共：w7b_recommend_from_pe                                          */
/* ------------------------------------------------------------------ */
int w7b_recommend_from_pe(const PeInfo* pe,
                          const char* manifest_xml,
                          W7bRecommendResult* rec)
{
    IMAGE_DATA_DIRECTORY* dir;
    DWORD dir_va, dir_sz;
    size_t off;
    WORD major = 0, minor = 0;

    if (pe == NULL || rec == NULL) {
        return -1;
    }

    memset(rec, 0, sizeof(*rec));

    /* 1. 子系统版本检查 */
    if (pe_get_subsystem_version(pe, &major, &minor) == PE_OK) {
        rec->current_major_subsystem = major;
        rec->current_minor_subsystem = minor;
        /* > 6.1 需降级 */
        if (major > 6 || (major == 6 && minor > 1)) {
            rec->needs_subsystem_fix = 1;
        }
    }

    /* 2. 遍历导入表 */
    if (pe->data_dir != NULL) {
        dir = &pe->data_dir[IMAGE_DIRECTORY_ENTRY_IMPORT];
        dir_va = dir->VirtualAddress;
        dir_sz = dir->Size;
        if (dir_va != 0 && dir_sz != 0) {
            off = 0;
            while (off + sizeof(IMAGE_IMPORT_DESCRIPTOR) <= dir_sz) {
                const IMAGE_IMPORT_DESCRIPTOR* d;
                const char* dll_name = NULL;
                size_t abs_off = dir_va + off;

                if (!rec_in_bounds(pe, abs_off,
                                   sizeof(IMAGE_IMPORT_DESCRIPTOR))) {
                    break;
                }
                d = (const IMAGE_IMPORT_DESCRIPTOR*)
                    ((const unsigned char*)pe->data + abs_off);

                /* 终止项 */
                if (d->Name == 0 && d->OriginalFirstThunk == 0 &&
                    d->FirstThunk == 0) {
                    break;
                }

                /* 取 DLL 名 */
                if (d->Name != 0 && rec_in_bounds(pe, d->Name, 1)) {
                    dll_name = (const char*)pe->data + d->Name;
                }

                if (dll_name != NULL) {
                    rec_classify_dll(dll_name, rec);
                }

                /* 遍历该 DLL 的导入函数，识别可模拟 API */
                rec_scan_import_thunks(pe, d->OriginalFirstThunk,
                                       d->FirstThunk, rec);

                off += sizeof(IMAGE_IMPORT_DESCRIPTOR);
            }
        }
    }

    /* 3. manifest 扫描 */
    if (manifest_xml != NULL && *manifest_xml != 0) {
        rec_scan_manifest(manifest_xml, rec);
    }

    /* 4. unsupported_overall 已在 rec_classify_dll 中按 WinRT/D3D12 设置 */
    return 0;
}

/* ------------------------------------------------------------------ */
/* 公共：w7b_recommend_apply                                            */
/* ------------------------------------------------------------------ */
void w7b_recommend_apply(W7bProgramConfig* cfg,
                         const W7bRecommendResult* rec)
{
    if (cfg == NULL || rec == NULL) return;

    /* 整体不可支持：禁用 */
    cfg->enabled = rec->unsupported_overall ? 0 : 1;

    /* 子系统修复 */
    cfg->fix_subsystem_version = rec->needs_subsystem_fix;
    /* bound import 剥离：始终启用（兼容性最稳妥） */
    cfg->strip_bound_imports = 1;

    /* 版本伪装：除非不可支持，否则默认启用 */
    cfg->version_spoof_enabled = rec->unsupported_overall ? 0 : 1;

    /* 不动 injection_path / log_level / overlays / diag_report_*：
       这些是用户偏好，自动推荐不覆盖。 */
}
