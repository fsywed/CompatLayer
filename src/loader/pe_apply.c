/*
 * pe_apply.c - Win7Bridge SubTask 3.1.3：在 DLL_PROCESS_ATTACH 阶段
 *              对当前 EXE 应用 L0 PE 修正 + L1/L2 IAT 改写
 *
 * 【开发文档】
 *
 * 目的：win7bridge.dll 被 loader 注入后，在 DllMain 中先调用本模块，
 *   对"当前 EXE"（即 GetModuleHandleW(NULL) 返回的 image base）应用：
 *     1) L0 PE 修正：子系统版本 > 6.1 降级到 6.1；剥离 bound import
 *     2) L2 API Set 解析：遍历导入表，识别 api-ms-* / ext-ms-* 虚拟名
 *     3) L1 IAT 改写：按 apiset 映射表把虚拟名 DLL 改写为真实 DLL
 *        或本地实现 DLL（win7bridge_local.dll）
 *
 * 分点展开：
 *
 *   1. 平台隔离
 *      本文件 #include <windows.h>，仅在 Windows 真实环境编译。
 *      host / syntax-check 模式下提供桩实现，返回 0。
 *
 *   2. 入口函数 win7bridge_apply_pe_and_iat_fixes
 *      不接收参数；内部用 GetModuleHandleW(NULL) 取 EXE image base。
 *      从 DOS/NT 头解析 SizeOfImage 后调用 pe_parse。
 *
 *   3. 改写流程
 *      - pe_fix_subsystem：版本 > 6.1 降级
 *      - pe_strip_bound_imports：TimeDateStamp 置 0
 *      - apiset_load_default：加载预置虚拟名映射表
 *      - 遍历导入表，对每个虚拟名查 apiset_lookup：
 *        * TO_REAL_DLL: engine_add_dll_redirect(virtual, host_dll)
 *        * TO_LOCAL:    engine_add_dll_redirect(virtual, "win7bridge_local.dll")
 *        * UNSOLVABLE:  跳过（不可解项由上层报告）
 *      - engine_rewrite_imports：实际改写 IAT 中的 DLL 名
 *
 *   4. 写权限
 *      改写 PE 内存前需要 VirtualProtect 改 PAGE_READWRITE。
 *      pe_fix_subsystem / pe_strip_bound_imports / engine_rewrite_imports
 *      内部不调 VirtualProtect；由本模块在调用前对整个 image 加可写权限。
 *
 *   5. 不分配堆
 *      RewriteEngine 内部用 realloc 管理规则表，由 engine 内部 free。
 *      ApiSetMap.entries 同理由 apiset_free 释放。本模块不直接 malloc。
 */

#include "win7bridge/pe.h"
#include "win7bridge/engine.h"
#include "win7bridge/apiset.h"

#include <string.h>

#if defined(_WIN32) && !defined(WIN7BRIDGE_HOST_TEST) && !defined(WIN7BRIDGE_SYNTAX_CHECK)

#include <windows.h>

#ifndef IMAGE_DOS_SIGNATURE
#define IMAGE_DOS_SIGNATURE 0x5A4D
#endif
#ifndef IMAGE_NT_SIGNATURE
#define IMAGE_NT_SIGNATURE 0x00004550
#endif

/* ------------------------------------------------------------------ */
/* 内部：取当前 EXE image base 与 size                                 */
/* ------------------------------------------------------------------ */
static int _get_current_image(const void** out_base, size_t* out_size)
{
    HMODULE hExe;
    const unsigned char* base;
    const IMAGE_DOS_HEADER* dos;
    const IMAGE_NT_HEADERS32* nt32;
    const IMAGE_NT_HEADERS64* nt64;

    hExe = GetModuleHandleW(NULL);
    if (hExe == NULL) return -1;
    base = (const unsigned char*)hExe;

    dos = (const IMAGE_DOS_HEADER*)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return -1;
    if (dos->e_lfanew <= 0) return -1;

    /* 判定 PE32 / PE32+ */
    {
        const DWORD* sig = (const DWORD*)(base + dos->e_lfanew);
        if (*sig != IMAGE_NT_SIGNATURE) return -1;
    }

    nt32 = (const IMAGE_NT_HEADERS32*)(base + dos->e_lfanew);
    if (nt32->OptionalHeader.Magic == 0x10b) {
        /* PE32 */
        *out_base = base;
        *out_size = nt32->OptionalHeader.SizeOfImage;
        return 0;
    }
    nt64 = (const IMAGE_NT_HEADERS64*)(base + dos->e_lfanew);
    if (nt64->OptionalHeader.Magic == 0x20b) {
        /* PE32+ */
        *out_base = base;
        *out_size = nt64->OptionalHeader.SizeOfImage;
        return 0;
    }
    return -1;
}

/* ------------------------------------------------------------------ */
/* 内部：把整个 image 改为可写                                         */
/*   改写子系统版本 / bound import / IAT DLL 名都需要写权限。          */
/* ------------------------------------------------------------------ */
static int _make_image_writable(void* base, size_t size)
{
    DWORD old_protect = 0;
    if (!VirtualProtect(base, size, PAGE_READWRITE, &old_protect)) {
        return -1;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* 内部：为虚拟名导入项添加 engine 转发规则                             */
/*   遍历 PE 导入表，对每个 api-ms-* / ext-ms-* 名查 apiset 表，        */
/*   按 kind 添加 engine_add_dll_redirect 规则。                        */
/* ------------------------------------------------------------------ */
static int _add_apiset_redirect_rules(RewriteEngine* e,
                                       const ApiSetMap* m,
                                       const PeInfo* pe)
{
    IMAGE_DATA_DIRECTORY* dir;
    DWORD dir_va, dir_sz;
    size_t off;
    int added = 0;

    if (pe->data_dir == NULL) return 0;
    dir = &pe->data_dir[IMAGE_DIRECTORY_ENTRY_IMPORT];
    dir_va = dir->VirtualAddress;
    dir_sz = dir->Size;
    if (dir_va == 0 || dir_sz == 0) return 0;

    off = 0;
    while (off + sizeof(IMAGE_IMPORT_DESCRIPTOR) <= dir_sz) {
        const IMAGE_IMPORT_DESCRIPTOR* d;
        const char* dll_name = NULL;
        size_t abs_off = dir_va + off;
        ApiSetEntry entry;
        const char* forward_to = NULL;

        if (abs_off + sizeof(IMAGE_IMPORT_DESCRIPTOR) > pe->size) break;
        d = (const IMAGE_IMPORT_DESCRIPTOR*)
            ((const unsigned char*)pe->data + abs_off);

        /* 终止项 */
        if (d->Name == 0 && d->OriginalFirstThunk == 0 &&
            d->FirstThunk == 0) {
            break;
        }

        if (d->Name != 0 && d->Name < pe->size) {
            dll_name = (const char*)pe->data + d->Name;
        }

        if (dll_name != NULL && apiset_is_virtual_name(dll_name)) {
            /* 取虚拟名（不含 .dll 后缀）查表 */
            char vname[128];
            size_t len = strlen(dll_name);
            size_t copy_len = len;
            if (copy_len >= sizeof(vname)) copy_len = sizeof(vname) - 1;
            memcpy(vname, dll_name, copy_len);
            vname[copy_len] = '\0';
            /* 去掉 .dll 后缀（apiset 表里键不带后缀） */
            if (copy_len >= 4 &&
                (vname[copy_len - 4] == '.') &&
                (vname[copy_len - 3] == 'd' || vname[copy_len - 3] == 'D') &&
                (vname[copy_len - 2] == 'l' || vname[copy_len - 2] == 'L') &&
                (vname[copy_len - 1] == 'l' || vname[copy_len - 1] == 'L')) {
                vname[copy_len - 4] = '\0';
            }

            if (apiset_lookup(m, vname, &entry) == 1) {
                if (entry.kind == APISET_TO_REAL_DLL) {
                    forward_to = entry.host_dll;
                } else if (entry.kind == APISET_TO_LOCAL) {
                    forward_to = "win7bridge_local.dll";
                }
                /* UNSOLVABLE 不转发 */
            }

            if (forward_to != NULL) {
                /* 仅当新名长度 <= 旧名长度时才添加规则，
                 * 避免 engine_rewrite_imports 越界写 */
                if (strlen(forward_to) <= strlen(dll_name)) {
                    if (engine_add_dll_redirect(e, dll_name, forward_to)
                        == ENGINE_OK) {
                        ++added;
                    }
                }
            }
        }

        off += sizeof(IMAGE_IMPORT_DESCRIPTOR);
    }
    return added;
}

/* ------------------------------------------------------------------ */
/* 公共：win7bridge_apply_pe_and_iat_fixes                              */
/*   返回：0 成功（即使无改动也返回 0）；<0 出错。                      */
/* ------------------------------------------------------------------ */
int win7bridge_apply_pe_and_iat_fixes(void)
{
    const void* image_base = NULL;
    size_t      image_size = 0;
    PeInfo      pe;
    ApiSetMap   apiset_map;
    RewriteEngine engine;
    int         rc;
    int         redirected = 0;

    /* 1. 取当前 EXE image base 与 size */
    if (_get_current_image(&image_base, &image_size) != 0) {
        return -1;
    }

    /* 2. 改为可写 */
    if (_make_image_writable((void*)image_base, image_size) != 0) {
        return -2;
    }

    /* 3. 解析 PE */
    rc = pe_parse(image_base, image_size, &pe);
    if (rc != PE_OK) {
        return -3;
    }

    /* 4. L0 PE 修正：子系统版本 + bound import */
    pe_fix_subsystem(&pe);
    pe_strip_bound_imports(&pe);

    /* 5. L2 API Set 解析 */
    if (apiset_init(&apiset_map) != APISET_OK) {
        return -4;
    }
    if (apiset_load_default(&apiset_map) != APISET_OK) {
        apiset_free(&apiset_map);
        return -5;
    }
    /* apiset_resolve_imports 只是遍历识别，不修改；用于诊断计数 */
    apiset_resolve_imports(&apiset_map, &pe);

    /* 6. L1 IAT 改写 */
    if (engine_init(&engine) != ENGINE_OK) {
        apiset_free(&apiset_map);
        return -6;
    }
    redirected = _add_apiset_redirect_rules(&engine, &apiset_map, &pe);
    if (redirected > 0) {
        engine_rewrite_imports(&engine, &pe);
    }

    /* 7. 释放规则表与映射表（字符串由调用方保活，这里都是静态字面量） */
    free(engine.dll_rules);
    free(engine.func_rules);
    apiset_free(&apiset_map);

    (void)redirected;  /* 调试用，避免 -Wunused */
    return 0;
}

/* ================================================================== */
/* host / syntax-check 桩                                              */
/* ================================================================== */
#else  /* !(_WIN32 && !HOST_TEST && !SYNTAX_CHECK) */

int win7bridge_apply_pe_and_iat_fixes(void)
{
    /* host 模式：无 Windows API，返回 0 表示"无需处理" */
    return 0;
}

#endif
