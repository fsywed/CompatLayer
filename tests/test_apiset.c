/*
 * test_apiset.c - Win7Bridge L2 API Set 虚拟解析层 host 测试
 *
 * 覆盖：
 *   1) apiset_is_virtual_name：api-ms-win-* / ext-ms-win-* 前缀识别
 *   2) apiset_load_default + apiset_lookup：预置条目命中各类 kind
 *   3) apiset_add + apiset_lookup：动态添加后能查到
 *   4) apiset_resolve_imports：合成 PE 导入 api-ms-win-core-synch-l1-2-0.dll
 *      后调用返回需要处理的条目数 >= 1
 *
 * 仅在定义 WIN7BRIDGE_HOST_TEST 时编译 main，用原生 gcc 运行。
 * 返回 0 表示全部通过，非 0 表示有失败。
 */
#include "win7bridge/apiset.h"
#include "win7bridge/pe.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------ */
/* 合成 PE 布局常量                                                    */
/* ------------------------------------------------------------------ */
#define IMG_SIZE           0x400   /* 1024 字节                        */
#define DOS_OFF            0x00
#define NT_OFF             0x40
#define OPT_OFF            (NT_OFF + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER))
#define SEC_OFF            (NT_OFF + sizeof(IMAGE_NT_HEADERS32))
#define SEC_VA             0x200
#define SIZE_OF_HEADERS    0x200
#define SIZE_OF_IMAGE      0x400

#define IMP_DESC_OFF       0x200   /* 导入描述符数组（2 项）           */
#define IMP_NAME_OFF       0x240   /* DLL 名字符串（预留 0x30 字节）   */
#define ILT_OFF            0x280   /* Import Lookup Table              */
#define IAT_OFF            0x288   /* Import Address Table             */
#define IBN_OFF            0x2A0   /* IMAGE_IMPORT_BY_NAME             */

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

/*
 * build_pe_with_import - 构造含单个 DLL/单个函数导入的最小 PE32 镜像
 *   dll_name  ：导入的 DLL 名（写入 IMP_NAME_OFF，需不超过 0x3F 字节）
 *   func_name ：按名导入的函数名（写入 IBN_OFF）
 * 缓冲区需 >= IMG_SIZE 字节且可写。
 */
static void build_pe_with_import(unsigned char* buf, size_t size,
                                 const char* dll_name, const char* func_name)
{
    IMAGE_DOS_HEADER* dos;
    IMAGE_NT_HEADERS32* nt;
    IMAGE_OPTIONAL_HEADER32* opt;
    IMAGE_SECTION_HEADER* sec;
    IMAGE_IMPORT_DESCRIPTOR* imp;
    DWORD* ilt;
    DWORD* iat;
    IMAGE_IMPORT_BY_NAME* ibn;
    size_t name_avail = ILT_OFF - IMP_NAME_OFF;

    (void)size;
    memset(buf, 0, IMG_SIZE);

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
    opt->MajorSubsystemVersion = 6;
    opt->MinorSubsystemVersion = 1;
    opt->ImageBase = 0x00400000;
    opt->SectionAlignment = 0x200;
    opt->FileAlignment = 0x200;
    opt->SizeOfImage = SIZE_OF_IMAGE;
    opt->SizeOfHeaders = SIZE_OF_HEADERS;
    opt->Subsystem = 3;                              /* WINDOWS_CUI */
    opt->NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;

    /* 导入表数据目录 */
    opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = IMP_DESC_OFF;
    opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size = 2 * sizeof(IMAGE_IMPORT_DESCRIPTOR);

    /* 节头 */
    sec = (IMAGE_SECTION_HEADER*)(buf + SEC_OFF);
    memcpy(sec->Name, ".text\0\0\0", 8);
    sec->Misc.VirtualSize = 0x200;
    sec->VirtualAddress = SEC_VA;
    sec->SizeOfRawData = 0x200;
    sec->PointerToRawData = SEC_VA;
    sec->Characteristics = 0x60000020;               /* CODE|EXECUTE|READ */

    /* 导入描述符（1 项 + 终止项） */
    imp = (IMAGE_IMPORT_DESCRIPTOR*)(buf + IMP_DESC_OFF);
    imp[0].OriginalFirstThunk = ILT_OFF;
    imp[0].TimeDateStamp = 0;
    imp[0].ForwarderChain = 0;
    imp[0].Name = IMP_NAME_OFF;
    imp[0].FirstThunk = IAT_OFF;
    /* imp[1] 全零终止 */

    /* DLL 名（截断保护，避免溢出到 ILT） */
    {
        size_t dn = strlen(dll_name) + 1;
        if (dn > name_avail) dn = name_avail;
        memcpy(buf + IMP_NAME_OFF, dll_name, dn);
        buf[IMP_NAME_OFF + dn - 1] = 0;
    }

    /* ILT / IAT：各 2 个 DWORD（1 thunk + 0 终止） */
    ilt = (DWORD*)(buf + ILT_OFF);
    ilt[0] = IBN_OFF;                                /* 指向 IMPORT_BY_NAME */
    ilt[1] = 0;
    iat = (DWORD*)(buf + IAT_OFF);
    iat[0] = IBN_OFF;
    iat[1] = 0;

    /* IMAGE_IMPORT_BY_NAME */
    ibn = (IMAGE_IMPORT_BY_NAME*)(buf + IBN_OFF);
    ibn->Hint = 0;
    {
        size_t fn = strlen(func_name) + 1;
        /* 节内剩余空间足够，直接 memcpy；最多写 0x40 字节 */
        if (fn > 0x40) fn = 0x40;
        memcpy(ibn->Name, func_name, fn);
        ibn->Name[fn - 1] = 0;
    }
}

/* ------------------------------------------------------------------ */
/* 用例 1：apiset_is_virtual_name                                       */
/* ------------------------------------------------------------------ */
static void test_is_virtual_name(void)
{
    int rc;

    printf("==== 用例 1：apiset_is_virtual_name ====\n");

    rc = apiset_is_virtual_name("api-ms-win-core-synch-l1-2-0.dll");
    CHECK(rc == 1, "api-ms-win-core-synch-l1-2-0.dll 识别为虚拟名");

    rc = apiset_is_virtual_name("API-MS-WIN-CORE-SYNCH-L1-2-0.DLL");
    CHECK(rc == 1, "大小写不敏感识别 API-MS-WIN-*");

    rc = apiset_is_virtual_name("ext-ms-win-core-winrt-l1-1-0.dll");
    CHECK(rc == 1, "ext-ms-win-core-winrt-l1-1-0.dll 识别为虚拟名");

    rc = apiset_is_virtual_name("EXT-MS-WIN-FOO-L1-1-0.DLL");
    CHECK(rc == 1, "大小写不敏感识别 EXT-MS-WIN-*");

    rc = apiset_is_virtual_name("kernel32.dll");
    CHECK(rc == 0, "kernel32.dll 非虚拟名");

    rc = apiset_is_virtual_name("ucrtbase.dll");
    CHECK(rc == 0, "ucrtbase.dll 非虚拟名");

    rc = apiset_is_virtual_name("api-ms-win-crt-runtime-l1-1-0");
    CHECK(rc == 1, "无 .dll 后缀的 api-ms-win-crt-runtime-l1-1-0 仍识别");

    rc = apiset_is_virtual_name(NULL);
    CHECK(rc == 0, "NULL 入参返回 0");

    rc = apiset_is_virtual_name("api-ms-win-");
    CHECK(rc == 1, "仅前缀 api-ms-win- 也识别（边界）");

    rc = apiset_is_virtual_name("api-ms-winx");  /* 前缀后无 '-' */
    CHECK(rc == 0, "api-ms-winx 非 api-ms-win- 前缀");
}

/* ------------------------------------------------------------------ */
/* 用例 2：apiset_load_default + apiset_lookup                          */
/* ------------------------------------------------------------------ */
static void test_load_default_and_lookup(void)
{
    ApiSetMap m;
    ApiSetEntry e;
    int rc;

    printf("==== 用例 2：apiset_load_default + apiset_lookup ====\n");

    rc = apiset_init(&m);
    CHECK(rc == APISET_OK, "apiset_init 成功");
    CHECK(m.count == 0 && m.entries == NULL, "init 后表为空");

    rc = apiset_load_default(&m);
    CHECK(rc == APISET_OK, "apiset_load_default 成功");
    CHECK(m.count > 0, "load_default 后有条目");

    /* synch -> TO_LOCAL */
    rc = apiset_lookup(&m, "api-ms-win-core-synch-l1-2-0", &e);
    CHECK(rc == 1, "查 api-ms-win-core-synch-l1-2-0 命中");
    CHECK(e.kind == APISET_TO_LOCAL, "synch kind == TO_LOCAL");
    CHECK(e.host_dll != NULL, "synch host_dll 非空");

    /* 大小写不敏感 */
    rc = apiset_lookup(&m, "API-MS-WIN-CORE-SYNCH-L1-2-0", &e);
    CHECK(rc == 1 && e.kind == APISET_TO_LOCAL, "大小写不敏感查找 synch 命中");

    /* winrt -> UNSOLVABLE */
    rc = apiset_lookup(&m, "api-ms-win-core-winrt-l1-1-0", &e);
    CHECK(rc == 1, "查 api-ms-win-core-winrt-l1-1-0 命中");
    CHECK(e.kind == APISET_UNSOLVABLE, "winrt kind == UNSOLVABLE");
    CHECK(e.note != NULL && strstr(e.note, "WinRT") != NULL,
          "winrt note 含 WinRT");

    /* winrt-string -> UNSOLVABLE */
    rc = apiset_lookup(&m, "api-ms-win-core-winrt-string-l1-1-0", &e);
    CHECK(rc == 1 && e.kind == APISET_UNSOLVABLE,
          "winrt-string kind == UNSOLVABLE");

    /* timezone -> TO_REAL_DLL kernel32.dll */
    rc = apiset_lookup(&m, "api-ms-win-core-timezone-l1-1-0", &e);
    CHECK(rc == 1, "查 api-ms-win-core-timezone-l1-1-0 命中");
    CHECK(e.kind == APISET_TO_REAL_DLL, "timezone kind == TO_REAL_DLL");
    CHECK(e.host_dll != NULL && strcmp(e.host_dll, "kernel32.dll") == 0,
          "timezone host_dll == kernel32.dll");

    /* com -> TO_REAL_DLL ole32.dll */
    rc = apiset_lookup(&m, "api-ms-win-core-com-l1-1-1", &e);
    CHECK(rc == 1 && e.kind == APISET_TO_REAL_DLL &&
          strcmp(e.host_dll, "ole32.dll") == 0,
          "com 转发到 ole32.dll");

    /* xstate -> UNSOLVABLE (AVX) */
    rc = apiset_lookup(&m, "api-ms-win-core-xstate-l2-1-0", &e);
    CHECK(rc == 1 && e.kind == APISET_UNSOLVABLE &&
          strstr(e.note, "AVX") != NULL,
          "xstate UNSOLVABLE 且 note 含 AVX");

    /* memory l1-1-3..6 -> TO_LOCAL */
    rc = apiset_lookup(&m, "api-ms-win-core-memory-l1-1-3", &e);
    CHECK(rc == 1 && e.kind == APISET_TO_LOCAL,
          "memory-l1-1-3 TO_LOCAL");
    rc = apiset_lookup(&m, "api-ms-win-core-memory-l1-1-6", &e);
    CHECK(rc == 1 && e.kind == APISET_TO_LOCAL,
          "memory-l1-1-6 TO_LOCAL");

    /* crt-runtime -> TO_REAL_DLL ucrtbase.dll */
    rc = apiset_lookup(&m, "api-ms-win-crt-runtime-l1-1-0", &e);
    CHECK(rc == 1 && e.kind == APISET_TO_REAL_DLL &&
          strcmp(e.host_dll, "ucrtbase.dll") == 0,
          "crt-runtime 转发到 ucrtbase.dll");

    /* ext-ms-win-* -> UNSOLVABLE */
    rc = apiset_lookup(&m, "ext-ms-win-core-winrt-l1-1-0", &e);
    CHECK(rc == 1 && e.kind == APISET_UNSOLVABLE,
          "ext-ms-win-core-winrt-l1-1-0 UNSOLVABLE");

    /* 不存在的虚拟名 -> 未命中 */
    rc = apiset_lookup(&m, "api-ms-win-core-not-a-real-entry-l1-1-0", &e);
    CHECK(rc == 0, "不存在的虚拟名返回 0");

    /* 非虚拟名 -> 未命中 */
    rc = apiset_lookup(&m, "kernel32.dll", &e);
    CHECK(rc == 0, "非虚拟名查找返回 0");

    /* out=NULL 仅探测 */
    rc = apiset_lookup(&m, "api-ms-win-core-synch-l1-2-0", NULL);
    CHECK(rc == 1, "out=NULL 仅探测返回 1");

    /* 非法入参 */
    rc = apiset_lookup(NULL, "x", &e);
    CHECK(rc == APISET_ERR_INVALID_ARG, "NULL map 被拒绝");
    rc = apiset_lookup(&m, NULL, &e);
    CHECK(rc == APISET_ERR_INVALID_ARG, "NULL name 被拒绝");

    free(m.entries);
}

/* ------------------------------------------------------------------ */
/* 用例 3：apiset_add + apiset_lookup                                  */
/* ------------------------------------------------------------------ */
static void test_add_and_lookup(void)
{
    ApiSetMap m;
    ApiSetEntry e;
    int rc;

    printf("==== 用例 3：apiset_add + apiset_lookup ====\n");

    rc = apiset_init(&m);
    CHECK(rc == APISET_OK, "apiset_init 成功");
    CHECK(m.count == 0, "init 后 count==0");

    rc = apiset_add(&m, "api-ms-win-fake-l1-1-0",
                    APISET_TO_REAL_DLL, "fakehost.dll", "测试条目");
    CHECK(rc == APISET_OK, "apiset_add 成功");
    CHECK(m.count == 1, "add 后 count==1");

    rc = apiset_lookup(&m, "api-ms-win-fake-l1-1-0", &e);
    CHECK(rc == 1, "动态添加后能查到");
    CHECK(e.kind == APISET_TO_REAL_DLL, "kind 正确");
    CHECK(strcmp(e.host_dll, "fakehost.dll") == 0, "host_dll 正确");
    CHECK(strcmp(e.note, "测试条目") == 0, "note 正确");

    /* 大小写不敏感查询动态条目 */
    rc = apiset_lookup(&m, "API-MS-WIN-FAKE-L1-1-0", NULL);
    CHECK(rc == 1, "大小写不敏感查询动态条目");

    /* UNSOLVABLE 允许 host=NULL */
    rc = apiset_add(&m, "api-ms-win-fake-unsolvable-l1-1-0",
                    APISET_UNSOLVABLE, NULL, "不可解");
    CHECK(rc == APISET_OK, "UNSOLVABLE 允许 host=NULL");
    rc = apiset_lookup(&m, "api-ms-win-fake-unsolvable-l1-1-0", &e);
    CHECK(rc == 1 && e.kind == APISET_UNSOLVABLE && e.host_dll == NULL,
          "UNSOLVABLE 条目查询正确");

    /* TO_REAL_DLL 不允许 host=NULL */
    rc = apiset_add(&m, "api-ms-win-fake-bad-l1-1-0",
                    APISET_TO_REAL_DLL, NULL, "bad");
    CHECK(rc == APISET_ERR_INVALID_ARG, "TO_REAL_DLL 拒绝 host=NULL");

    /* TO_LOCAL 不允许 host=NULL */
    rc = apiset_add(&m, "api-ms-win-fake-bad2-l1-1-0",
                    APISET_TO_LOCAL, NULL, "bad");
    CHECK(rc == APISET_ERR_INVALID_ARG, "TO_LOCAL 拒绝 host=NULL");

    /* 非法入参 */
    rc = apiset_add(NULL, "x", APISET_TO_REAL_DLL, "h", "n");
    CHECK(rc == APISET_ERR_INVALID_ARG, "NULL map 被拒绝");
    rc = apiset_add(&m, NULL, APISET_TO_REAL_DLL, "h", "n");
    CHECK(rc == APISET_ERR_INVALID_ARG, "NULL vname 被拒绝");

    /* 扩容触发：连续添加超过初始容量 16 */
    {
        int i;
        char name[64];
        for (i = 0; i < 32; ++i) {
            snprintf(name, sizeof(name), "api-ms-win-fake-extra-l1-1-%d", i);
            rc = apiset_add(&m, name, APISET_TO_LOCAL, "win7bridge_local", "x");
            if (rc != APISET_OK) {
                printf("[FAIL] %s:%d 扩容添加失败 i=%d rc=%d\n",
                       __FILE__, __LINE__, i, rc);
                g_fail = 1;
                break;
            }
        }
        CHECK(m.count >= 34, "扩容后 count >= 34");
    }

    free(m.entries);
}

/* ------------------------------------------------------------------ */
/* 用例 4：apiset_resolve_imports                                      */
/* ------------------------------------------------------------------ */
static void test_resolve_imports(void)
{
    ApiSetMap m;
    unsigned char* buf;
    PeInfo pe;
    int rc;

    printf("==== 用例 4：apiset_resolve_imports ====\n");

    buf = (unsigned char*)malloc(IMG_SIZE);
    if (buf == NULL) {
        printf("[FAIL] malloc 失败\n");
        g_fail = 1;
        return;
    }

    /* 构造合成 PE：导入 api-ms-win-core-synch-l1-2-0.dll!WaitOnAddress */
    build_pe_with_import(buf, IMG_SIZE,
                         "api-ms-win-core-synch-l1-2-0.dll",
                         "WaitOnAddress");

    rc = pe_parse(buf, IMG_SIZE, &pe);
    CHECK(rc == PE_OK, "pe_parse 成功");
    CHECK(pe.import_dir != NULL, "导入表已定位");

    /* 准备映射表 */
    rc = apiset_init(&m);
    CHECK(rc == APISET_OK, "apiset_init 成功");
    rc = apiset_load_default(&m);
    CHECK(rc == APISET_OK, "apiset_load_default 成功");

    /* 调用解析：synch 在映射表中，应返回 >= 1 */
    rc = apiset_resolve_imports(&m, &pe);
    CHECK(rc >= 1, "resolve_imports 对 synch 导入返回 >= 1");

    /* 测试非虚拟名导入：应返回 0 */
    {
        unsigned char* buf2 = (unsigned char*)malloc(IMG_SIZE);
        PeInfo pe2;
        if (buf2 == NULL) {
            printf("[FAIL] malloc 失败\n");
            g_fail = 1;
            free(m.entries);
            free(buf);
            return;
        }
        build_pe_with_import(buf2, IMG_SIZE, "kernel32.dll", "ExitProcess");
        pe_parse(buf2, IMG_SIZE, &pe2);
        rc = apiset_resolve_imports(&m, &pe2);
        CHECK(rc == 0, "非虚拟名导入返回 0");
        free(buf2);
    }

    /* 测试 UNSOLVABLE 虚拟名导入：应返回 1（计入需要处理） */
    {
        unsigned char* buf3 = (unsigned char*)malloc(IMG_SIZE);
        PeInfo pe3;
        if (buf3 == NULL) {
            printf("[FAIL] malloc 失败\n");
            g_fail = 1;
            free(m.entries);
            free(buf);
            return;
        }
        build_pe_with_import(buf3, IMG_SIZE,
                             "api-ms-win-core-winrt-l1-1-0.dll",
                             "RoInitialize");
        pe_parse(buf3, IMG_SIZE, &pe3);
        rc = apiset_resolve_imports(&m, &pe3);
        CHECK(rc == 1, "winrt UNSOLVABLE 导入计入需要处理");
        free(buf3);
    }

    /* 测试未在映射表中的虚拟名：应返回 0 */
    {
        unsigned char* buf4 = (unsigned char*)malloc(IMG_SIZE);
        PeInfo pe4;
        if (buf4 == NULL) {
            printf("[FAIL] malloc 失败\n");
            g_fail = 1;
            free(m.entries);
            free(buf);
            return;
        }
        build_pe_with_import(buf4, IMG_SIZE,
                             "api-ms-win-unknown-xyz-l99-9-9.dll",
                             "SomeFunc");
        pe_parse(buf4, IMG_SIZE, &pe4);
        rc = apiset_resolve_imports(&m, &pe4);
        CHECK(rc == 0, "未知虚拟名未命中映射表返回 0");
        free(buf4);
    }

    /* 非法入参 */
    rc = apiset_resolve_imports(NULL, &pe);
    CHECK(rc == APISET_ERR_INVALID_ARG, "NULL map 被拒绝");
    rc = apiset_resolve_imports(&m, NULL);
    CHECK(rc == APISET_ERR_INVALID_ARG, "NULL pe 被拒绝");

    free(m.entries);
    free(buf);
}

/* ------------------------------------------------------------------ */
/* main                                                                */
/* ------------------------------------------------------------------ */
#ifdef WIN7BRIDGE_HOST_TEST
int main(void)
{
    test_is_virtual_name();
    test_load_default_and_lookup();
    test_add_and_lookup();
    test_resolve_imports();

    if (g_fail) {
        printf("\n==== 存在失败用例 ====\n");
        return 1;
    }
    printf("\n==== 全部通过 ====\n");
    return 0;
}
#endif /* WIN7BRIDGE_HOST_TEST */
