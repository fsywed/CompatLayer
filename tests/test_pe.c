/*
 * test_pe.c - Win7Bridge L0 PE 解析与修正器 host 测试
 *
 * 在内存中手工构造最小 PE32 镜像（DOS 头 + PE 头 + OptionalHeader +
 * 一个节 + 导入表/绑定导入表），验证 pe_parse / pe_fix_subsystem /
 * pe_strip_bound_imports / pe_dump_imports 的行为。
 *
 * 构造为"扁平镜像"：节的数据 RVA == 文件偏移，因此 RVA 可直接当作
 * 相对缓冲区起点的偏移使用，与 pe.c 的映射假设一致。
 *
 * 仅在定义 WIN7BRIDGE_HOST_TEST 时编译 main，用原生 gcc 运行。
 * 返回 0 表示全部通过，非 0 表示有失败。
 */
#include "win7bridge/pe.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* 镜像布局常量                                                          */
#define IMG_SIZE           0x400   /* 1024 字节                          */
#define DOS_OFF            0x00
#define NT_OFF             0x40    /* e_lfanew                           */
#define OPT_OFF            (NT_OFF + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER))
#define SEC_OFF            (NT_OFF + sizeof(IMAGE_NT_HEADERS32))
#define SEC_VA             0x200   /* 节的 RVA == 文件偏移（扁平）       */
#define SIZE_OF_HEADERS    0x200
#define SIZE_OF_IMAGE      0x400

/* 节数据内的子结构偏移（RVA == 文件偏移）                              */
#define IMP_DESC_OFF       0x200   /* 导入描述符数组（2 项）             */
#define IMP_NAME_OFF       0x228   /* "kernel32.dll"                     */
#define ILT_OFF            0x240   /* Import Lookup Table                */
#define IAT_OFF            0x248   /* Import Address Table               */
#define IBN_OFF            0x260   /* IMAGE_IMPORT_BY_NAME "ExitProcess" */
#define BID_OFF            0x280   /* 绑定导入描述符数组（2 项）         */
#define BID_NAME_OFF       0x290   /* 绑定导入模块名                     */

/* 简单断言：失败则打印并令 main 返回非 0                               */
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
 * build_pe - 在 buf 中构造一个最小 PE32 镜像
 *   maj_sub/min_sub：MajorSubsystemVersion / MinorSubsystemVersion
 *   maj_os/min_os   ：MajorOperatingSystemVersion / MinorOperatingSystemVersion
 *   bound_td        ：绑定导入描述符的初始 TimeDateStamp（非 0 时存在）
 */
static void build_pe(unsigned char* buf, size_t size,
                     WORD maj_sub, WORD min_sub,
                     WORD maj_os, WORD min_os,
                     DWORD bound_td)
{
    IMAGE_DOS_HEADER* dos;
    IMAGE_NT_HEADERS32* nt;
    IMAGE_OPTIONAL_HEADER32* opt;
    IMAGE_SECTION_HEADER* sec;
    IMAGE_IMPORT_DESCRIPTOR* imp;
    IMAGE_BOUND_IMPORT_DESCRIPTOR* bid;
    DWORD* ilt;
    DWORD* iat;
    IMAGE_IMPORT_BY_NAME* ibn;

    (void)size;
    memset(buf, 0, IMG_SIZE);

    /* DOS 头 */
    dos = (IMAGE_DOS_HEADER*)(buf + DOS_OFF);
    dos->e_magic = IMAGE_DOS_SIGNATURE;
    dos->e_lfanew = NT_OFF;

    /* NT 头（用偏移取指针，避免对 packed 成员取址） */
    nt = (IMAGE_NT_HEADERS32*)(buf + NT_OFF);
    nt->Signature = IMAGE_NT_SIGNATURE;
    nt->FileHeader.Machine = 0x014C;                 /* IMAGE_FILE_MACHINE_I386 */
    nt->FileHeader.NumberOfSections = 1;
    nt->FileHeader.SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER32);
    nt->FileHeader.Characteristics = 0x0102;         /* EXECUTABLE_IMAGE | 32BIT_MACHINE */

    /* OptionalHeader */
    opt = (IMAGE_OPTIONAL_HEADER32*)(buf + OPT_OFF);
    opt->Magic = IMAGE_NT_OPTIONAL_HDR32_MAGIC;
    opt->MajorOperatingSystemVersion = maj_os;
    opt->MinorOperatingSystemVersion = min_os;
    opt->MajorSubsystemVersion = maj_sub;
    opt->MinorSubsystemVersion = min_sub;
    opt->ImageBase = 0x00400000;
    opt->SectionAlignment = 0x200;
    opt->FileAlignment = 0x200;
    opt->SizeOfImage = SIZE_OF_IMAGE;
    opt->SizeOfHeaders = SIZE_OF_HEADERS;
    opt->Subsystem = 3;                              /* WINDOWS_CUI */
    opt->NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;

    /* 数据目录：导入表 + 绑定导入表 */
    opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = IMP_DESC_OFF;
    opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size = 2 * sizeof(IMAGE_IMPORT_DESCRIPTOR);
    opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].VirtualAddress = BID_OFF;
    opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].Size = 2 * sizeof(IMAGE_BOUND_IMPORT_DESCRIPTOR);

    /* 节头 */
    sec = (IMAGE_SECTION_HEADER*)(buf + SEC_OFF);
    memcpy(sec->Name, ".text\0\0\0", 8);
    sec->Misc.VirtualSize = 0x200;
    sec->VirtualAddress = SEC_VA;
    sec->SizeOfRawData = 0x200;
    sec->PointerToRawData = SEC_VA;
    sec->Characteristics = 0x60000020;               /* CODE|EXECUTE|READ */

    /* ---- 节数据：导入描述符 ---- */
    imp = (IMAGE_IMPORT_DESCRIPTOR*)(buf + IMP_DESC_OFF);
    imp[0].OriginalFirstThunk = ILT_OFF;             /* ILT RVA */
    imp[0].TimeDateStamp = 0;
    imp[0].ForwarderChain = 0;
    imp[0].Name = IMP_NAME_OFF;                      /* DLL 名 RVA */
    imp[0].FirstThunk = IAT_OFF;                     /* IAT RVA */
    /* imp[1] 全零，作为终止项（memset 已清零） */

    /* DLL 名 */
    memcpy(buf + IMP_NAME_OFF, "kernel32.dll", 13);  /* 含 NUL */

    /* ILT / IAT：各 2 个 DWORD（1 个 thunk + 0 终止） */
    ilt = (DWORD*)(buf + ILT_OFF);
    ilt[0] = IBN_OFF;                                /* 指向 IMPORT_BY_NAME */
    ilt[1] = 0;
    iat = (DWORD*)(buf + IAT_OFF);
    iat[0] = IBN_OFF;
    iat[1] = 0;

    /* IMAGE_IMPORT_BY_NAME */
    ibn = (IMAGE_IMPORT_BY_NAME*)(buf + IBN_OFF);
    ibn->Hint = 0;
    memcpy(ibn->Name, "ExitProcess", 12);            /* 含 NUL */

    /* ---- 节数据：绑定导入描述符 ---- */
    bid = (IMAGE_BOUND_IMPORT_DESCRIPTOR*)(buf + BID_OFF);
    bid[0].TimeDateStamp = bound_td;
    bid[0].OffsetModuleName = (WORD)(BID_NAME_OFF - BID_OFF); /* 相对偏移 */
    bid[0].NumberOfModuleForwarderRefs = 0;
    /* bid[1] 全零，作为终止项 */
    memcpy(buf + BID_NAME_OFF, "kernel32.dll", 13);
}

#ifdef WIN7BRIDGE_HOST_TEST
int main(void)
{
    unsigned char* buf;
    PeInfo pe;
    int rc;
    WORD maj, min;

    buf = (unsigned char*)malloc(IMG_SIZE);
    if (buf == NULL) {
        printf("[FAIL] malloc 失败\n");
        return 1;
    }

    /* -------------------------------------------------------------- */
    /* 用例 1：MajorSubsystemVersion=10.0，应被修正为 6.1              */
    /* -------------------------------------------------------------- */
    printf("==== 用例 1：子系统版本 10.0 -> 6.1 ====\n");
    build_pe(buf, IMG_SIZE, 10, 0, 10, 0, 0x12345678);

    rc = pe_parse(buf, IMG_SIZE, &pe);
    CHECK(rc == PE_OK, "pe_parse 成功");
    CHECK(pe.is64 == 0, "判定为 PE32");

    rc = pe_get_subsystem_version(&pe, &maj, &min);
    CHECK(rc == PE_OK && maj == 10 && min == 0, "修正前子系统版本为 10.0");

    rc = pe_fix_subsystem(&pe);
    CHECK(rc > 0, "pe_fix_subsystem 报告已修改");

    rc = pe_get_subsystem_version(&pe, &maj, &min);
    CHECK(rc == PE_OK && maj == WIN7_SUBSYSTEM_MAJOR && min == WIN7_SUBSYSTEM_MINOR,
          "修正后子系统版本为 6.1");

    /* OS 版本应同步被修正（直接通过字段指针验证） */
    CHECK(pe.major_os != NULL && *pe.major_os == WIN7_SUBSYSTEM_MAJOR &&
          *pe.minor_os == WIN7_SUBSYSTEM_MINOR,
          "MajorOperatingSystemVersion 同步修正为 6.1");

    /* -------------------------------------------------------------- */
    /* 用例 1 续：剥离绑定导入                                          */
    /* -------------------------------------------------------------- */
    printf("==== 用例 1 续：剥离绑定导入 ====\n");
    {
        IMAGE_BOUND_IMPORT_DESCRIPTOR* bid =
            (IMAGE_BOUND_IMPORT_DESCRIPTOR*)(buf + BID_OFF);
        CHECK(bid[0].TimeDateStamp == 0x12345678, "剥离前 TimeDateStamp 非 0");
    }
    rc = pe_strip_bound_imports(&pe);
    CHECK(rc >= 1, "pe_strip_bound_imports 置零至少 1 个描述符");
    {
        IMAGE_BOUND_IMPORT_DESCRIPTOR* bid =
            (IMAGE_BOUND_IMPORT_DESCRIPTOR*)(buf + BID_OFF);
        CHECK(bid[0].TimeDateStamp == 0, "剥离后 TimeDateStamp == 0");
    }

    /* 导入表打印（人工核对：应见 kernel32.dll / ExitProcess） */
    printf("==== 用例 1 续：导入表打印 ====\n");
    pe_dump_imports(&pe);

    /* -------------------------------------------------------------- */
    /* 用例 2：版本边界 6.2 应被修正（major==6, minor>1）              */
    /* -------------------------------------------------------------- */
    printf("==== 用例 2：子系统版本 6.2 -> 6.1 ====\n");
    build_pe(buf, IMG_SIZE, 6, 2, 6, 2, 0);
    rc = pe_parse(buf, IMG_SIZE, &pe);
    CHECK(rc == PE_OK, "pe_parse 成功");
    rc = pe_fix_subsystem(&pe);
    CHECK(rc > 0, "6.2 触发修正");
    pe_get_subsystem_version(&pe, &maj, &min);
    CHECK(maj == 6 && min == 1, "6.2 修正为 6.1");

    /* -------------------------------------------------------------- */
    /* 用例 3：版本 6.1 无需修正                                       */
    /* -------------------------------------------------------------- */
    printf("==== 用例 3：子系统版本 6.1 不应修改 ====\n");
    build_pe(buf, IMG_SIZE, 6, 1, 6, 1, 0);
    rc = pe_parse(buf, IMG_SIZE, &pe);
    CHECK(rc == PE_OK, "pe_parse 成功");
    rc = pe_fix_subsystem(&pe);
    CHECK(rc == 0, "6.1 无需修正");
    pe_get_subsystem_version(&pe, &maj, &min);
    CHECK(maj == 6 && min == 1, "6.1 保持不变");

    /* -------------------------------------------------------------- */
    /* 用例 4：版本 5.1（低于 6.1）无需修正                            */
    /* -------------------------------------------------------------- */
    printf("==== 用例 4：子系统版本 5.1 不应修改 ====\n");
    build_pe(buf, IMG_SIZE, 5, 1, 5, 1, 0);
    rc = pe_parse(buf, IMG_SIZE, &pe);
    CHECK(rc == PE_OK, "pe_parse 成功");
    rc = pe_fix_subsystem(&pe);
    CHECK(rc == 0, "5.1 无需修正");
    pe_get_subsystem_version(&pe, &maj, &min);
    CHECK(maj == 5 && min == 1, "5.1 保持不变");

    /* -------------------------------------------------------------- */
    /* 用例 5：非法入参应被拒绝                                        */
    /* -------------------------------------------------------------- */
    printf("==== 用例 5：非法入参 ====\n");
    rc = pe_parse(buf, IMG_SIZE, NULL);
    CHECK(rc == PE_ERR_INVALID_ARG, "pe_parse 拒绝空 out");
    rc = pe_parse(NULL, IMG_SIZE, &pe);
    CHECK(rc == PE_ERR_INVALID_ARG, "pe_parse 拒绝空 data");

    free(buf);

    if (g_fail) {
        printf("\n==== 存在失败用例 ====\n");
        return 1;
    }
    printf("\n==== 全部通过 ====\n");
    return 0;
}
#endif /* WIN7BRIDGE_HOST_TEST */
