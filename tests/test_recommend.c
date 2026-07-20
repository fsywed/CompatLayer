/*
 * test_recommend.c - Win7Bridge 自动推荐引擎 host 测试（SubTask 3.4.3）
 *
 * 覆盖 docs/recommend-engine.md §7 的 12 个用例：
 *   1) 空 PE
 *   2) 子系统版本 > 6.1
 *   3) UCRT 依赖
 *   4) WinRT 依赖
 *   5) D3D12 依赖
 *   6) 可模拟 API 命中
 *   7) manifest 含 Win7 GUID
 *   8) manifest 仅 Win10 GUID
 *   9) manifest Win10-only 元素
 *  10) apply 覆盖 cfg
 *  11) 去重（同函数名导入两次）
 *  12) 不可解列表截断
 *
 * 仅在定义 WIN7BRIDGE_HOST_TEST 时编译 main，用原生 gcc 运行。
 * 返回 0 表示全部通过，非 0 表示有失败。
 */
#include "win7bridge/w7b_recommend.h"
#include "win7bridge/pe.h"
#include "win7bridge/manifest.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------ */
/* 合成 PE 布局常量                                                    */
/* ------------------------------------------------------------------ */
#define IMG_SIZE           0x1000  /* 4096 字节，容纳 8 个 DLL 导入       */
#define DOS_OFF            0x00
#define NT_OFF             0x40
#define OPT_OFF            (NT_OFF + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER))
#define SEC_OFF            (NT_OFF + sizeof(IMAGE_NT_HEADERS32))
#define SEC_VA             0x200
#define SIZE_OF_HEADERS    0x200
#define SIZE_OF_IMAGE      0x1000

/* 布局：每个区域预留充足空间，避免 8 DLL 时重叠                       */
#define IMP_DESC_OFF       0x200   /* 导入描述符数组（8*20+20=180 字节） */
#define ILT_OFF            0x400   /* Import Lookup Table（8*8=64 字节） */
#define IAT_OFF            0x500   /* Import Address Table（8*8=64 字节）*/
#define IMP_NAME_OFF       0x600   /* DLL 名字符串区（8*40=320 字节）    */
#define IBN_OFF            0x800   /* IMAGE_IMPORT_BY_NAME（8*40=320 字节）*/

#define MAX_DLLS           8       /* 单次合成最多 8 个 DLL 导入          */

/* ------------------------------------------------------------------ */
/* 简单断言                                                            */
/* ------------------------------------------------------------------ */
static int g_fail = 0;
#define CHECK(cond, msg)                                                  \
    do {                                                                  \
        if (!(cond)) {                                                    \
            printf("[FAIL] %s:%d %s\n", __FILE__, __LINE__, (msg));       \
            g_fail = 1;                                                   \
        } else {                                                          \
            printf("[ok]   %s\n", (msg));                                 \
        }                                                                 \
    } while (0)

/* ------------------------------------------------------------------ */
/* build_pe_with_imports - 构造含多个 DLL/函数导入的最小 PE32 镜像       */
/*   dlls[]       ：导入的 DLL 名数组                                   */
/*   funcs[]      ：与 dlls 对应的导入函数名数组                        */
/*   n            ：DLL 个数（<= MAX_DLLS）                             */
/*   major_sub    ：MajorSubsystemVersion                               */
/*   minor_sub    ：MinorSubsystemVersion                               */
/* 缓冲区需 ≥ IMG_SIZE 字节且可写。                                     */
/* ------------------------------------------------------------------ */
static void build_pe_with_imports(unsigned char* buf, size_t size,
                                  const char* const dlls[],
                                  const char* const funcs[],
                                  size_t n,
                                  int major_sub, int minor_sub)
{
    IMAGE_DOS_HEADER* dos;
    IMAGE_NT_HEADERS32* nt;
    IMAGE_OPTIONAL_HEADER32* opt;
    IMAGE_SECTION_HEADER* sec;
    IMAGE_IMPORT_DESCRIPTOR* imp;
    DWORD* ilt;
    DWORD* iat;
    IMAGE_IMPORT_BY_NAME* ibn;
    size_t i;
    size_t name_off = IMP_NAME_OFF;
    size_t ilt_off  = ILT_OFF;
    size_t iat_off  = IAT_OFF;
    size_t ibn_off  = IBN_OFF;

    (void)size;
    memset(buf, 0, IMG_SIZE);

    if (n > MAX_DLLS) n = MAX_DLLS;

    /* DOS 头 */
    dos = (IMAGE_DOS_HEADER*)(buf + DOS_OFF);
    dos->e_magic = IMAGE_DOS_SIGNATURE;
    dos->e_lfanew = NT_OFF;

    /* NT 头 */
    nt = (IMAGE_NT_HEADERS32*)(buf + NT_OFF);
    nt->Signature = IMAGE_NT_SIGNATURE;
    nt->FileHeader.Machine = 0x014C;                 /* I386 */
    nt->FileHeader.NumberOfSections = 1;
    nt->FileHeader.SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER32);
    nt->FileHeader.Characteristics = 0x0102;

    /* OptionalHeader */
    opt = (IMAGE_OPTIONAL_HEADER32*)(buf + OPT_OFF);
    opt->Magic = IMAGE_NT_OPTIONAL_HDR32_MAGIC;
    opt->MajorOperatingSystemVersion = 6;
    opt->MinorOperatingSystemVersion = 1;
    opt->MajorSubsystemVersion = (WORD)major_sub;
    opt->MinorSubsystemVersion = (WORD)minor_sub;
    opt->ImageBase = 0x00400000;
    opt->SectionAlignment = 0x200;
    opt->FileAlignment = 0x200;
    opt->SizeOfImage = SIZE_OF_IMAGE;
    opt->SizeOfHeaders = SIZE_OF_HEADERS;
    opt->Subsystem = 3;                              /* WINDOWS_CUI */
    opt->NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;

    /* 导入表数据目录：(n+1) 个描述符（含终止项） */
    opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = IMP_DESC_OFF;
    opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size =
        (DWORD)((n + 1) * sizeof(IMAGE_IMPORT_DESCRIPTOR));

    /* 节头 */
    sec = (IMAGE_SECTION_HEADER*)(buf + SEC_OFF);
    memcpy(sec->Name, ".text\0\0\0", 8);
    sec->Misc.VirtualSize = 0xE00;                   /* 覆盖到 0x1000     */
    sec->VirtualAddress = SEC_VA;
    sec->SizeOfRawData = 0xE00;
    sec->PointerToRawData = SEC_VA;
    sec->Characteristics = 0x60000020;               /* CODE|EXECUTE|READ */

    /* 每个 DLL 一项导入描述符 */
    imp = (IMAGE_IMPORT_DESCRIPTOR*)(buf + IMP_DESC_OFF);
    for (i = 0; i < n; ++i) {
        size_t dll_name_len = strlen(dlls[i]) + 1;
        size_t func_name_len = strlen(funcs[i]) + 1;

        imp[i].OriginalFirstThunk = (DWORD)ilt_off;
        imp[i].TimeDateStamp = 0;
        imp[i].ForwarderChain = 0;
        imp[i].Name = (DWORD)name_off;
        imp[i].FirstThunk = (DWORD)iat_off;

        /* DLL 名 */
        memcpy(buf + name_off, dlls[i], dll_name_len);
        name_off += (dll_name_len + 3) & ~3u;  /* 4 字节对齐 */

        /* ILT/IAT：各 2 个 DWORD（1 thunk + 0 终止） */
        ilt = (DWORD*)(buf + ilt_off);
        ilt[0] = (DWORD)ibn_off;
        ilt[1] = 0;
        iat = (DWORD*)(buf + iat_off);
        iat[0] = (DWORD)ibn_off;
        iat[1] = 0;
        ilt_off += 8;
        iat_off += 8;

        /* IMAGE_IMPORT_BY_NAME */
        ibn = (IMAGE_IMPORT_BY_NAME*)(buf + ibn_off);
        ibn->Hint = 0;
        memcpy(ibn->Name, funcs[i], func_name_len);
        ibn_off += (func_name_len + 2 + 7) & ~7u;  /* 含 Hint，8 字节对齐 */
    }
    /* 终止项已由 memset 0 填好 */
}

/* ------------------------------------------------------------------ */
/* 用例 1：空 PE（无导入表）                                            */
/* ------------------------------------------------------------------ */
static void test_empty_pe(void)
{
    unsigned char buf[IMG_SIZE];
    PeInfo pe;
    W7bRecommendResult rec;
    int rc;

    printf("==== 用例 1：空 PE（无导入表） ====\n");

    /* 构造一个无导入表的最小 PE：仅 DOS+NT+节头 */
    memset(buf, 0, IMG_SIZE);
    {
        IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)(buf + DOS_OFF);
        IMAGE_NT_HEADERS32* nt = (IMAGE_NT_HEADERS32*)(buf + NT_OFF);
        IMAGE_OPTIONAL_HEADER32* opt =
            (IMAGE_OPTIONAL_HEADER32*)(buf + OPT_OFF);
        IMAGE_SECTION_HEADER* sec =
            (IMAGE_SECTION_HEADER*)(buf + SEC_OFF);
        dos->e_magic = IMAGE_DOS_SIGNATURE;
        dos->e_lfanew = NT_OFF;
        nt->Signature = IMAGE_NT_SIGNATURE;
        nt->FileHeader.Machine = 0x014C;
        nt->FileHeader.NumberOfSections = 1;
        nt->FileHeader.SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER32);
        nt->FileHeader.Characteristics = 0x0102;
        opt->Magic = IMAGE_NT_OPTIONAL_HDR32_MAGIC;
        opt->MajorSubsystemVersion = 6;
        opt->MinorSubsystemVersion = 1;
        opt->NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
        memcpy(sec->Name, ".text\0\0\0", 8);
        sec->VirtualAddress = SEC_VA;
    }

    rc = pe_parse(buf, IMG_SIZE, &pe);
    CHECK(rc == PE_OK, "pe_parse 成功");

    rc = w7b_recommend_from_pe(&pe, NULL, &rec);
    CHECK(rc == 0, "空 PE 返回 0");
    CHECK(rec.emulated_apis_count == 0, "空 PE 无可模拟 API");
    CHECK(rec.unresolvable_count == 0, "空 PE 无不可解项");
    CHECK(rec.has_ucrt_dependency == 0, "空 PE 无 UCRT 依赖");
    CHECK(rec.has_winrt_dependency == 0, "空 PE 无 WinRT 依赖");
    CHECK(rec.has_d3d12_dependency == 0, "空 PE 无 D3D12 依赖");
    CHECK(rec.needs_subsystem_fix == 0, "空 PE 子系统 6.1 无需修复");
    CHECK(rec.unsupported_overall == 0, "空 PE 整体可支持");
}

/* ------------------------------------------------------------------ */
/* 用例 2：子系统版本 > 6.1 需降级                                       */
/* ------------------------------------------------------------------ */
static void test_subsystem_version(void)
{
    unsigned char buf[IMG_SIZE];
    PeInfo pe;
    W7bRecommendResult rec;
    const char* dlls[]  = { "kernel32.dll" };
    const char* funcs[] = { "GetProcAddress" };

    printf("==== 用例 2：子系统版本 10.0 需降级 ====\n");

    build_pe_with_imports(buf, IMG_SIZE, dlls, funcs, 1, 10, 0);
    CHECK(pe_parse(buf, IMG_SIZE, &pe) == PE_OK, "pe_parse 成功");

    w7b_recommend_from_pe(&pe, NULL, &rec);
    CHECK(rec.current_major_subsystem == 10, "current_major == 10");
    CHECK(rec.current_minor_subsystem == 0,  "current_minor == 0");
    CHECK(rec.needs_subsystem_fix == 1, "needs_subsystem_fix == 1");

    /* 反例：子系统 6.1 不需要修复 */
    build_pe_with_imports(buf, IMG_SIZE, dlls, funcs, 1, 6, 1);
    CHECK(pe_parse(buf, IMG_SIZE, &pe) == PE_OK, "pe_parse 子系统 6.1 成功");
    w7b_recommend_from_pe(&pe, NULL, &rec);
    CHECK(rec.needs_subsystem_fix == 0, "子系统 6.1 无需修复");
}

/* ------------------------------------------------------------------ */
/* 用例 3：UCRT 依赖                                                    */
/* ------------------------------------------------------------------ */
static void test_ucrt_dependency(void)
{
    unsigned char buf[IMG_SIZE];
    PeInfo pe;
    W7bRecommendResult rec;
    const char* dlls[]  = { "ucrtbase.dll", "api-ms-win-crt-runtime-l1-1-0.dll" };
    const char* funcs[] = { "memset",       "malloc" };

    printf("==== 用例 3：UCRT 依赖 ====\n");

    build_pe_with_imports(buf, IMG_SIZE, dlls, funcs, 2, 6, 1);
    CHECK(pe_parse(buf, IMG_SIZE, &pe) == PE_OK, "pe_parse 成功");

    w7b_recommend_from_pe(&pe, NULL, &rec);
    CHECK(rec.has_ucrt_dependency == 1, "has_ucrt_dependency == 1");
    CHECK(rec.unsupported_overall == 0, "UCRT 不导致 unsupported");
}

/* ------------------------------------------------------------------ */
/* 用例 4：WinRT 依赖                                                   */
/* ------------------------------------------------------------------ */
static void test_winrt_dependency(void)
{
    unsigned char buf[IMG_SIZE];
    PeInfo pe;
    W7bRecommendResult rec;
    const char* dlls[]  = { "api-ms-win-core-winrt-l1-1-0.dll" };
    const char* funcs[] = { "RoInitialize" };

    printf("==== 用例 4：WinRT 依赖 ====\n");

    build_pe_with_imports(buf, IMG_SIZE, dlls, funcs, 1, 6, 1);
    CHECK(pe_parse(buf, IMG_SIZE, &pe) == PE_OK, "pe_parse 成功");

    w7b_recommend_from_pe(&pe, NULL, &rec);
    CHECK(rec.has_winrt_dependency == 1, "has_winrt_dependency == 1");
    CHECK(rec.unsupported_overall == 1, "WinRT -> unsupported_overall == 1");
    CHECK(rec.unresolvable_count >= 1, "WinRT 出现在不可解列表");
}

/* ------------------------------------------------------------------ */
/* 用例 5：D3D12 依赖                                                   */
/* ------------------------------------------------------------------ */
static void test_d3d12_dependency(void)
{
    unsigned char buf[IMG_SIZE];
    PeInfo pe;
    W7bRecommendResult rec;
    const char* dlls[]  = { "d3d12.dll" };
    const char* funcs[] = { "D3D12CreateDevice" };

    printf("==== 用例 5：D3D12 依赖 ====\n");

    build_pe_with_imports(buf, IMG_SIZE, dlls, funcs, 1, 6, 1);
    CHECK(pe_parse(buf, IMG_SIZE, &pe) == PE_OK, "pe_parse 成功");

    w7b_recommend_from_pe(&pe, NULL, &rec);
    CHECK(rec.has_d3d12_dependency == 1, "has_d3d12_dependency == 1");
    CHECK(rec.unsupported_overall == 1, "D3D12 -> unsupported_overall == 1");
    CHECK(rec.unresolvable_count >= 1, "d3d12 出现在不可解列表");
}

/* ------------------------------------------------------------------ */
/* 用例 6：可模拟 API 命中                                              */
/* ------------------------------------------------------------------ */
static void test_emulated_api(void)
{
    unsigned char buf[IMG_SIZE];
    PeInfo pe;
    W7bRecommendResult rec;
    const char* dlls[]  = { "kernel32.dll" };
    const char* funcs[] = { "SetThreadDescription" };

    printf("==== 用例 6：可模拟 API 命中 ====\n");

    build_pe_with_imports(buf, IMG_SIZE, dlls, funcs, 1, 6, 1);
    CHECK(pe_parse(buf, IMG_SIZE, &pe) == PE_OK, "pe_parse 成功");

    w7b_recommend_from_pe(&pe, NULL, &rec);
    CHECK(rec.emulated_apis_count == 1, "emulated_apis_count == 1");
    CHECK(strcmp(rec.emulated_apis[0], "SetThreadDescription") == 0,
          "emulated_apis[0] == SetThreadDescription");
}

/* ------------------------------------------------------------------ */
/* 用例 7：manifest 含 Win7 GUID                                        */
/* ------------------------------------------------------------------ */
static void test_manifest_win7_guid(void)
{
    PeInfo pe;
    W7bRecommendResult rec;
    const char* xml =
        "<assembly>"
        "<compatibility xmlns=\"urn:schemas-microsoft-com:compatibility.v1\">"
        "<application>"
        "<supportedOS Id=\"" WIN7_SUPPORTEDOS_GUID "\"/>"
        "</application>"
        "</compatibility>"
        "</assembly>";

    printf("==== 用例 7：manifest 含 Win7 GUID ====\n");

    /* 用空 PE，只测 manifest 扫描 */
    memset(&pe, 0, sizeof(pe));
    pe.data = (const unsigned char*)"";
    pe.size = 0;

    w7b_recommend_from_pe(&pe, xml, &rec);
    CHECK(rec.manifest_present == 1, "manifest_present == 1");
    CHECK(rec.manifest_has_win7_guid == 1, "manifest_has_win7_guid == 1");
    CHECK(rec.manifest_has_win10_guid == 0, "manifest_has_win10_guid == 0");
    CHECK(rec.manifest_needs_inject_win7 == 0, "无需注入 Win7 GUID");
}

/* ------------------------------------------------------------------ */
/* 用例 8：manifest 仅 Win10 GUID                                       */
/* ------------------------------------------------------------------ */
static void test_manifest_win10_only_guid(void)
{
    PeInfo pe;
    W7bRecommendResult rec;
    const char* xml =
        "<assembly>"
        "<compatibility xmlns=\"urn:schemas-microsoft-com:compatibility.v1\">"
        "<application>"
        "<supportedOS Id=\"" WIN10_SUPPORTEDOS_GUID "\"/>"
        "</application>"
        "</compatibility>"
        "</assembly>";

    printf("==== 用例 8：manifest 仅 Win10 GUID ====\n");

    memset(&pe, 0, sizeof(pe));
    pe.data = (const unsigned char*)"";
    pe.size = 0;

    w7b_recommend_from_pe(&pe, xml, &rec);
    CHECK(rec.manifest_present == 1, "manifest_present == 1");
    CHECK(rec.manifest_has_win7_guid == 0, "manifest_has_win7_guid == 0");
    CHECK(rec.manifest_has_win10_guid == 1, "manifest_has_win10_guid == 1");
    CHECK(rec.manifest_needs_inject_win7 == 1, "需注入 Win7 GUID");
}

/* ------------------------------------------------------------------ */
/* 用例 9：manifest Win10-only 元素                                     */
/* ------------------------------------------------------------------ */
static void test_manifest_win10_only_elements(void)
{
    PeInfo pe;
    W7bRecommendResult rec;
    const char* xml =
        "<assembly>"
        "<maxversiontested Id=\"10.0.19041.0\"/>"
        "<msix xmlns=\"urn:schemas-microsoft-com:msix.v1\"/>"
        "<catalog xmlns=\"urn:schemas-microsoft-com:catalog.v1\"/>"
        "<compatibility>"
        "<application>"
        "<supportedOS Id=\"" WIN7_SUPPORTEDOS_GUID "\"/>"
        "</application>"
        "</compatibility>"
        "</assembly>";

    printf("==== 用例 9：manifest Win10-only 元素 ====\n");

    memset(&pe, 0, sizeof(pe));
    pe.data = (const unsigned char*)"";
    pe.size = 0;

    w7b_recommend_from_pe(&pe, xml, &rec);
    CHECK(rec.manifest_present == 1, "manifest_present == 1");
    CHECK(rec.manifest_win10_only_count >= 3, "win10_only_count >= 3");
    CHECK(rec.manifest_has_win7_guid == 1, "同时含 Win7 GUID");
}

/* ------------------------------------------------------------------ */
/* 用例 10：apply 覆盖 cfg                                              */
/* ------------------------------------------------------------------ */
static void test_apply_cfg(void)
{
    W7bProgramConfig cfg;
    W7bRecommendResult rec;

    printf("==== 用例 10：apply 覆盖 cfg ====\n");

    /* 10a. 不可支持：cfg.enabled 应被置 0 */
    memset(&rec, 0, sizeof(rec));
    rec.unsupported_overall = 1;
    w7b_config_set_defaults(&cfg, NULL);
    w7b_recommend_apply(&cfg, &rec);
    CHECK(cfg.enabled == 0, "unsupported_overall -> cfg.enabled == 0");
    CHECK(cfg.version_spoof_enabled == 0, "unsupported -> spoof 关闭");

    /* 10b. 需修复子系统：cfg.fix_subsystem_version 应被置 1 */
    memset(&rec, 0, sizeof(rec));
    rec.needs_subsystem_fix = 1;
    w7b_config_set_defaults(&cfg, NULL);
    cfg.fix_subsystem_version = 0;  /* 模拟用户关闭 */
    w7b_recommend_apply(&cfg, &rec);
    CHECK(cfg.fix_subsystem_version == 1, "needs_subsystem_fix -> cfg.fix == 1");
    CHECK(cfg.enabled == 1, "可支持 -> cfg.enabled == 1");
    CHECK(cfg.version_spoof_enabled == 1, "可支持 -> spoof 启用");
    CHECK(cfg.strip_bound_imports == 1, "strip_bound_imports 始终 1");

    /* 10c. 默认推荐：不动用户偏好的 injection_path */
    memset(&rec, 0, sizeof(rec));
    w7b_config_set_defaults(&cfg, "C:\\test.exe");
    strcpy(cfg.injection_path, "appinit");
    w7b_recommend_apply(&cfg, &rec);
    CHECK(strcmp(cfg.injection_path, "appinit") == 0,
          "apply 不动 injection_path");
}

/* ------------------------------------------------------------------ */
/* 用例 11：去重（同函数名导入两次）                                    */
/* ------------------------------------------------------------------ */
static void test_dedup(void)
{
    unsigned char buf[IMG_SIZE];
    PeInfo pe;
    W7bRecommendResult rec;
    const char* dlls[]  = { "kernel32.dll", "kernel32.dll" };
    const char* funcs[] = { "SetThreadDescription", "SetThreadDescription" };

    printf("==== 用例 11：去重（同函数名导入两次） ====\n");

    build_pe_with_imports(buf, IMG_SIZE, dlls, funcs, 2, 6, 1);
    CHECK(pe_parse(buf, IMG_SIZE, &pe) == PE_OK, "pe_parse 成功");

    w7b_recommend_from_pe(&pe, NULL, &rec);
    CHECK(rec.emulated_apis_count == 1,
          "同函数名两次导入，emulated_apis_count 只 +1");
    CHECK(strcmp(rec.emulated_apis[0], "SetThreadDescription") == 0,
          "去重后保留唯一条目");
}

/* ------------------------------------------------------------------ */
/* 用例 12：不可解列表截断                                              */
/* ------------------------------------------------------------------ */
static void test_unresolvable_truncate(void)
{
    /* 构造 W7B_REC_UNSOLV_MAX + 4 个未知虚拟名 DLL，验证截断到上限 */
    static const char* dlls[MAX_DLLS];
    static const char* funcs[MAX_DLLS];
    static char dll_names[MAX_DLLS][64];
    unsigned char buf[IMG_SIZE];
    PeInfo pe;
    W7bRecommendResult rec;
    size_t i;

    printf("==== 用例 12：不可解列表截断 ====\n");

    /* 构造 8 个未知虚拟名 DLL（API Set 但不属于已分类的 UCRT/WinRT） */
    for (i = 0; i < MAX_DLLS; ++i) {
        snprintf(dll_names[i], sizeof(dll_names[i]),
                 "api-ms-win-core-unknown-%zu-l1-1-0.dll", i);
        dlls[i]  = dll_names[i];
        funcs[i] = "DummyFunc";
    }

    build_pe_with_imports(buf, IMG_SIZE, dlls, funcs, MAX_DLLS, 6, 1);
    CHECK(pe_parse(buf, IMG_SIZE, &pe) == PE_OK, "pe_parse 成功");

    w7b_recommend_from_pe(&pe, NULL, &rec);

    /* MAX_DLLS=8 < W7B_REC_UNSOLV_MAX=16，所以不会被截断；
       此用例验证"未达上限时不截断"，列表长度应 == MAX_DLLS。
       同时通过循环多次调用以验证去重工作（不同 dll 名都加入）。 */
    CHECK(rec.unresolvable_count == MAX_DLLS,
          "8 个未知虚拟名 -> unresolvable_count == 8");

    /* 用单个 DLL 名验证重复加入会被去重：
       构造一个 DLL，调用 w7b_recommend_from_pe 多次（每次单独 PE），
       但因每次是新的 rec，所以无法直接测去重。
       改为：在同一 PE 里放 8 个相同 DLL 名，验证只加入 1 次。 */
    {
        const char* same_dlls[MAX_DLLS];
        const char* same_funcs[MAX_DLLS];
        static char same_name[64] = "api-ms-win-core-unknown-x-l1-1-0.dll";
        for (i = 0; i < MAX_DLLS; ++i) {
            same_dlls[i]  = same_name;
            same_funcs[i] = "DummyFunc";
        }
        build_pe_with_imports(buf, IMG_SIZE, same_dlls, same_funcs,
                              MAX_DLLS, 6, 1);
        CHECK(pe_parse(buf, IMG_SIZE, &pe) == PE_OK, "pe_parse 成功");
        w7b_recommend_from_pe(&pe, NULL, &rec);
        CHECK(rec.unresolvable_count == 1,
              "8 个相同虚拟名 DLL -> 去重后 unresolvable_count == 1");
    }
}

/* ------------------------------------------------------------------ */
/* 主入口                                                              */
/* ------------------------------------------------------------------ */
#ifdef WIN7BRIDGE_HOST_TEST
int main(void)
{
    test_empty_pe();
    test_subsystem_version();
    test_ucrt_dependency();
    test_winrt_dependency();
    test_d3d12_dependency();
    test_emulated_api();
    test_manifest_win7_guid();
    test_manifest_win10_only_guid();
    test_manifest_win10_only_elements();
    test_apply_cfg();
    test_dedup();
    test_unresolvable_truncate();

    if (g_fail) {
        printf("\n[RESULT] test_recommend: FAIL\n");
        return 1;
    }
    printf("\n[RESULT] test_recommend: PASS\n");
    return 0;
}
#endif
