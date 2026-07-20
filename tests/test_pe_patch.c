/*
 * test_pe_patch.c - Win7Bridge SubTask 3.2.1 离线 PE patch 工具 host 测试
 *
 * 验证：
 *   1) pe_patch_e2e：构造 PE(10.0) -> 写入临时文件 -> patch -> 读回验证
 *      子系统降为 6.1 + bound import TimeDateStamp=0 + 字节数一致
 *   2) pe_patch_null_args：input_path=NULL 返回 1
 *   3) pe_patch_missing_file：不存在的文件返回 2
 *   4) pe_patch_bad_pe：写入非 PE 字节流（"xxxx"）返回 3
 *   5) pe_patch_parse_help：--help 设 help=1
 *
 * 仅在定义 WIN7BRIDGE_HOST_TEST 时编译 main。
 */

/* 暴露 pe_patch_main 内部接口用于测试
 * 需要前置 <stddef.h> 以获取 size_t（pe_inject_import 用到）。 */
#include <stddef.h>

extern int pe_patch_run(const char* input_path, const char* output_path);
extern int pe_patch_run_inject(const char* input_path, const char* output_path,
                               const char* inject_dll, const char* inject_func);
extern int pe_inject_import(unsigned char** pbuf, size_t* psize,
                            const char* dll_name, const char* func_name);
extern int pe_patch_parse_args(int argc, char** argv, void* out);
extern void pe_patch_print_help(const char* prog, void* stream);

/* PePatchArgs 结构在 pe_patch.c 内部定义，测试侧用对齐占位结构访问 help 字段
 * 字段顺序与 pe_patch.c 中的 PePatchArgs 一致，便于访问 inject 相关字段。 */
typedef struct {
    const char* input_path;   /* 偏移 0 */
    const char* output_path;  /* 偏移 8 (64-bit) / 4 (32-bit) */
    int         help;         /* 第 3 个字段 */
    int         inject;       /* 第 4 个字段 */
    const char* inject_dll;   /* 第 5 个字段 */
    const char* inject_func;  /* 第 6 个字段 */
} TestPePatchArgs;

#include "win7bridge/pe.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* 镜像布局常量（与 test_pe.c 一致，便于复用构造思路）              */
#define IMG_SIZE           0x400
#define DOS_OFF            0x00
#define NT_OFF             0x40
#define OPT_OFF            (NT_OFF + 4 + 20)            /* sig + FILE_HEADER */
#define SEC_OFF            (NT_OFF + sizeof(IMAGE_NT_HEADERS32))
#define SEC_VA             0x200
#define SIZE_OF_HEADERS    0x200
#define SIZE_OF_IMAGE      0x400
#define IMP_DESC_OFF       0x200
#define IMP_NAME_OFF       0x228
#define ILT_OFF            0x240
#define IAT_OFF            0x248
#define IBN_OFF            0x260
#define BID_OFF            0x280
#define BID_NAME_OFF       0x290

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
/* build_pe：构造最小 PE32 镜像（高子系统版本 + 含 bound import）      */
/* ------------------------------------------------------------------ */
static void build_pe(unsigned char* buf, size_t size)
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

    dos = (IMAGE_DOS_HEADER*)(buf + DOS_OFF);
    dos->e_magic = IMAGE_DOS_SIGNATURE;
    dos->e_lfanew = NT_OFF;

    nt = (IMAGE_NT_HEADERS32*)(buf + NT_OFF);
    nt->Signature = IMAGE_NT_SIGNATURE;
    nt->FileHeader.Machine = 0x014C;
    nt->FileHeader.NumberOfSections = 1;
    nt->FileHeader.SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER32);
    nt->FileHeader.Characteristics = 0x0102;

    opt = (IMAGE_OPTIONAL_HEADER32*)(buf + OPT_OFF);
    opt->Magic = IMAGE_NT_OPTIONAL_HDR32_MAGIC;
    opt->MajorOperatingSystemVersion = 10;
    opt->MinorOperatingSystemVersion = 0;
    opt->MajorSubsystemVersion = 10;
    opt->MinorSubsystemVersion = 0;
    opt->ImageBase = 0x00400000;
    opt->SectionAlignment = 0x200;
    opt->FileAlignment = 0x200;
    opt->SizeOfImage = SIZE_OF_IMAGE;
    opt->SizeOfHeaders = SIZE_OF_HEADERS;
    opt->Subsystem = 3;
    opt->NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
    opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = IMP_DESC_OFF;
    opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size = 2 * sizeof(IMAGE_IMPORT_DESCRIPTOR);
    opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].VirtualAddress = BID_OFF;
    opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].Size = 2 * sizeof(IMAGE_BOUND_IMPORT_DESCRIPTOR);

    sec = (IMAGE_SECTION_HEADER*)(buf + SEC_OFF);
    memcpy(sec->Name, ".text\0\0\0", 8);
    sec->Misc.VirtualSize = 0x200;
    sec->VirtualAddress = SEC_VA;
    sec->SizeOfRawData = 0x200;
    sec->PointerToRawData = SEC_VA;
    sec->Characteristics = 0x60000020;

    imp = (IMAGE_IMPORT_DESCRIPTOR*)(buf + IMP_DESC_OFF);
    imp[0].OriginalFirstThunk = ILT_OFF;
    imp[0].Name = IMP_NAME_OFF;
    imp[0].FirstThunk = IAT_OFF;
    memcpy(buf + IMP_NAME_OFF, "kernel32.dll", 13);

    ilt = (DWORD*)(buf + ILT_OFF);
    ilt[0] = IBN_OFF;
    iat = (DWORD*)(buf + IAT_OFF);
    iat[0] = IBN_OFF;
    ibn = (IMAGE_IMPORT_BY_NAME*)(buf + IBN_OFF);
    ibn->Hint = 0;
    memcpy(ibn->Name, "ExitProcess", 12);

    bid = (IMAGE_BOUND_IMPORT_DESCRIPTOR*)(buf + BID_OFF);
    bid[0].TimeDateStamp = 0x12345678;                 /* 非 0，应被置 0 */
    bid[0].OffsetModuleName = (WORD)(BID_NAME_OFF - BID_OFF);
    bid[0].NumberOfModuleForwarderRefs = 0;
    memcpy(buf + BID_NAME_OFF, "kernel32.dll", 13);
}

/* ------------------------------------------------------------------ */
/* 用例 1：pe_patch_e2e 端到端                                          */
/* ------------------------------------------------------------------ */
static void test_pe_patch_e2e(void)
{
    const char* in_path  = "/tmp/test_pe_patch_in.exe";
    const char* out_path = "/tmp/test_pe_patch_out.exe";
    unsigned char* in_buf;
    unsigned char* out_buf;
    FILE* fp;
    long in_size, out_size;
    int rc;
    IMAGE_NT_HEADERS32* nt;
    IMAGE_BOUND_IMPORT_DESCRIPTOR* bid;

    printf("==== 用例 1：pe_patch_e2e ====\n");

    /* 构造 PE 字节流并写入 in_path                                    */
    in_buf = (unsigned char*)malloc(IMG_SIZE);
    CHECK(in_buf != NULL, "malloc in_buf 成功");
    build_pe(in_buf, IMG_SIZE);

    fp = fopen(in_path, "wb");
    CHECK(fp != NULL, "创建输入文件成功");
    CHECK(fwrite(in_buf, 1, IMG_SIZE, fp) == IMG_SIZE, "写入输入文件成功");
    fclose(fp);
    free(in_buf);

    /* 调用 pe_patch_run                                                */
    rc = pe_patch_run(in_path, out_path);
    CHECK(rc == 0, "pe_patch_run 返回 0");

    /* 读回 out_path 验证                                              */
    fp = fopen(out_path, "rb");
    CHECK(fp != NULL, "打开输出文件成功");
    fseek(fp, 0, SEEK_END);
    out_size = ftell(fp);
    rewind(fp);
    CHECK(out_size == (long)IMG_SIZE, "输出文件字节数与输入一致");

    out_buf = (unsigned char*)malloc((size_t)out_size);
    CHECK(out_buf != NULL, "malloc out_buf 成功");
    CHECK(fread(out_buf, 1, (size_t)out_size, fp) == (size_t)out_size,
          "读回输出文件成功");
    fclose(fp);

    /* 验证子系统版本降为 6.1                                          */
    nt = (IMAGE_NT_HEADERS32*)(out_buf + NT_OFF);
    CHECK(nt->OptionalHeader.MajorSubsystemVersion == 6,
          "MajorSubsystemVersion == 6");
    CHECK(nt->OptionalHeader.MinorSubsystemVersion == 1,
          "MinorSubsystemVersion == 1");
    CHECK(nt->OptionalHeader.MajorOperatingSystemVersion == 6,
          "MajorOperatingSystemVersion == 6");

    /* 验证 bound import TimeDateStamp 置 0                            */
    bid = (IMAGE_BOUND_IMPORT_DESCRIPTOR*)(out_buf + BID_OFF);
    CHECK(bid[0].TimeDateStamp == 0, "bound import TimeDateStamp 已置 0");

    free(out_buf);
    unlink(in_path);
    unlink(out_path);
}

/* ------------------------------------------------------------------ */
/* 用例 2：pe_patch_null_args 返回 1                                    */
/* ------------------------------------------------------------------ */
static void test_pe_patch_null_args(void)
{
    int rc;
    printf("==== 用例 2：pe_patch_null_args ====\n");
    rc = pe_patch_run(NULL, "/tmp/out.exe");
    CHECK(rc == 1, "input=NULL 返回 1");
    rc = pe_patch_run("/tmp/in.exe", NULL);
    CHECK(rc == 1, "output=NULL 返回 1");
}

/* ------------------------------------------------------------------ */
/* 用例 3：pe_patch_missing_file 返回 2                                 */
/* ------------------------------------------------------------------ */
static void test_pe_patch_missing_file(void)
{
    int rc;
    printf("==== 用例 3：pe_patch_missing_file ====\n");
    rc = pe_patch_run("/tmp/does_not_exist_pe_patch.exe", "/tmp/out.exe");
    CHECK(rc == 2, "不存在的输入文件返回 2");
}

/* ------------------------------------------------------------------ */
/* 用例 4：pe_patch_bad_pe 返回 3                                       */
/* ------------------------------------------------------------------ */
static void test_pe_patch_bad_pe(void)
{
    const char* in_path  = "/tmp/test_pe_patch_bad.exe";
    const char* out_path = "/tmp/test_pe_patch_bad_out.exe";
    FILE* fp;
    int rc;
    const char* data = "not a PE file";

    printf("==== 用例 4：pe_patch_bad_pe ====\n");

    fp = fopen(in_path, "wb");
    CHECK(fp != NULL, "创建非 PE 文件成功");
    fwrite(data, 1, strlen(data), fp);
    fclose(fp);

    rc = pe_patch_run(in_path, out_path);
    CHECK(rc == 3, "非 PE 输入返回 3");

    unlink(in_path);
    if (unlink(out_path) == 0) {
        printf("[info] 输出文件被创建（不应发生）\n");
    }
}

/* ------------------------------------------------------------------ */
/* 用例 5：pe_patch_parse_help                                         */
/* ------------------------------------------------------------------ */
static void test_pe_patch_parse_help(void)
{
    TestPePatchArgs args;
    char* argv[] = { "pe_patch", "--help" };
    int rc;

    printf("==== 用例 5：pe_patch_parse_help ====\n");
    memset(&args, 0, sizeof(args));
    rc = pe_patch_parse_args(2, argv, &args);
    CHECK(rc == 0, "--help 解析返回 0");
    CHECK(args.help == 1, "help 字段被置 1");
}

/* ------------------------------------------------------------------ */
/* 用例 6：pe_inject_import NULL 入参返回 -1                            */
/* ------------------------------------------------------------------ */
static void test_pe_inject_null_args(void)
{
    unsigned char* buf = NULL;
    size_t         size = 0;
    int            rc;

    printf("==== 用例 6：pe_inject_import NULL 入参 ====\n");

    /* pbuf=NULL */
    rc = pe_inject_import(NULL, &size, "win7bridge.dll", "W7BridgeInit");
    CHECK(rc == -1, "pbuf=NULL 返回 -1");

    /* psize=NULL */
    rc = pe_inject_import(&buf, NULL, "win7bridge.dll", "W7BridgeInit");
    CHECK(rc == -1, "psize=NULL 返回 -1");

    /* *pbuf=NULL */
    rc = pe_inject_import(&buf, &size, "win7bridge.dll", "W7BridgeInit");
    CHECK(rc == -1, "*pbuf=NULL 返回 -1");

    /* dll_name=NULL */
    buf = (unsigned char*)malloc(16);
    size = 16;
    rc = pe_inject_import(&buf, &size, NULL, "W7BridgeInit");
    CHECK(rc == -1, "dll_name=NULL 返回 -1");

    /* func_name=NULL */
    rc = pe_inject_import(&buf, &size, "win7bridge.dll", NULL);
    CHECK(rc == -1, "func_name=NULL 返回 -1");

    free(buf);
}

/* ------------------------------------------------------------------ */
/* 用例 7：pe_patch_inject_e2e 端到端导入表注入                          */
/*   构造 PE(10.0) 含 kernel32.dll 导入 -> pe_patch_run_inject        */
/*   -> 读回验证 NumberOfSections+1、新节 .w7b、win7bridge.dll 出现  */
/* ------------------------------------------------------------------ */
static void test_pe_patch_inject_e2e(void)
{
    const char* in_path  = "/tmp/test_pe_patch_inject_in.exe";
    const char* out_path = "/tmp/test_pe_patch_inject_out.exe";
    unsigned char* in_buf;
    unsigned char* out_buf;
    FILE* fp;
    long out_size;
    int rc;
    IMAGE_NT_HEADERS32* nt;
    IMAGE_SECTION_HEADER* sec_hdr;
    IMAGE_IMPORT_DESCRIPTOR* imp;
    DWORD* ilt;
    DWORD* iat;
    IMAGE_IMPORT_BY_NAME* ibn;
    const char* dll_name_str;
    size_t i;

    /* 期望常量（基于 host 测试 PE 布局推算）                            */
    const DWORD SEC_OFF_IN_TEST  = 0x134;  /* first_section_off          */
    const DWORD NEW_SEC_HDR_OFF  = SEC_OFF_IN_TEST + 1 * 40; /* 0x15C    */
    const DWORD NEW_SEC_RVA      = 0x400;  /* align_up(0x400, 0x200)     */
    const DWORD NEW_SEC_FILE_OFF = 0x400;  /* align_up(0x400, 0x200)     */
    const DWORD NEW_IMP_SIZE     = 3 * 20; /* (1+2)*20 = 60              */
    const DWORD NEW_FILE_SIZE    = 0x600;  /* 0x400 + 0x200              */
    const DWORD NEW_SIZE_OF_IMAGE= 0x600;  /* 0x400 + align_up(106, 0x200)*/
    /* 节内偏移（func="W7BridgeInit" 12 字符，dll="win7bridge.dll" 14 字符）
     * off_ilt=60, off_iat=68, off_ibn=76, off_name=76+2+12+1=91          */
    const DWORD OFF_ILT  = 60;
    const DWORD OFF_IAT  = 68;
    const DWORD OFF_IBN  = 76;
    const DWORD OFF_NAME = 91;

    printf("==== 用例 7：pe_patch_inject_e2e ====\n");

    /* 1) 构造输入 PE                                                  */
    in_buf = (unsigned char*)malloc(IMG_SIZE);
    CHECK(in_buf != NULL, "malloc in_buf 成功");
    build_pe(in_buf, IMG_SIZE);

    fp = fopen(in_path, "wb");
    CHECK(fp != NULL, "创建输入文件成功");
    CHECK(fwrite(in_buf, 1, IMG_SIZE, fp) == IMG_SIZE, "写入输入文件成功");
    fclose(fp);
    free(in_buf);

    /* 2) 调用 pe_patch_run_inject（默认 dll/func）                   */
    rc = pe_patch_run_inject(in_path, out_path, NULL, NULL);
    CHECK(rc == 0, "pe_patch_run_inject 返回 0");

    /* 3) 读回输出文件                                                 */
    fp = fopen(out_path, "rb");
    CHECK(fp != NULL, "打开输出文件成功");
    fseek(fp, 0, SEEK_END);
    out_size = ftell(fp);
    rewind(fp);

    CHECK(out_size == (long)NEW_FILE_SIZE,
          "输出文件大小 == 0x600（含新节）");

    out_buf = (unsigned char*)malloc((size_t)out_size);
    CHECK(out_buf != NULL, "malloc out_buf 成功");
    CHECK(fread(out_buf, 1, (size_t)out_size, fp) == (size_t)out_size,
          "读回输出文件成功");
    fclose(fp);

    /* 4) 验证 NT 头                                                   */
    nt = (IMAGE_NT_HEADERS32*)(out_buf + NT_OFF);
    CHECK(nt->FileHeader.NumberOfSections == 2,
          "NumberOfSections == 2（原 1 + 新 1）");
    CHECK(nt->OptionalHeader.SizeOfImage == NEW_SIZE_OF_IMAGE,
          "SizeOfImage == 0x600");
    CHECK(nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]
              .VirtualAddress == NEW_SEC_RVA,
          "DataDirectory[IMPORT].VA == 0x400（指向新节）");
    CHECK(nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]
              .Size == NEW_IMP_SIZE,
          "DataDirectory[IMPORT].Size == 60（3 项含终止）");

    /* 5) 验证新节头                                                   */
    sec_hdr = (IMAGE_SECTION_HEADER*)(out_buf + NEW_SEC_HDR_OFF);
    CHECK(memcmp(sec_hdr->Name, ".w7b\0\0\0\0", 8) == 0,
          "新节名 == \".w7b\"");
    CHECK(sec_hdr->VirtualAddress == NEW_SEC_RVA,
          "新节 VirtualAddress == 0x400");
    CHECK(sec_hdr->PointerToRawData == NEW_SEC_FILE_OFF,
          "新节 PointerToRawData == 0x400");
    CHECK(sec_hdr->SizeOfRawData == 0x200,
          "新节 SizeOfRawData == 0x200");
    CHECK((sec_hdr->Characteristics & 0xC0000040u) == 0xC0000040u,
          "新节 Characteristics 含 INITIALIZED_DATA|READ|WRITE");

    /* 6) 验证新节内的导入描述符数组                                   */
    /* 第 0 项：原 kernel32.dll 描述符（被复制过来，Name=0x228 等）    */
    imp = (IMAGE_IMPORT_DESCRIPTOR*)(out_buf + NEW_SEC_FILE_OFF);
    CHECK(imp[0].Name == 0x228, "原 kernel32.dll 描述符 Name 仍为 0x228");
    CHECK(imp[0].OriginalFirstThunk == 0x240, "原 ILT RVA 仍为 0x240");
    CHECK(imp[0].FirstThunk == 0x248, "原 IAT RVA 仍为 0x248");

    /* 第 1 项：新 win7bridge.dll 描述符                               */
    CHECK(imp[1].OriginalFirstThunk == NEW_SEC_RVA + OFF_ILT,
          "新描述符 OriginalFirstThunk 指向新节内 ILT");
    CHECK(imp[1].FirstThunk == NEW_SEC_RVA + OFF_IAT,
          "新描述符 FirstThunk 指向新节内 IAT");
    CHECK(imp[1].Name == NEW_SEC_RVA + OFF_NAME,
          "新描述符 Name 指向新节内 DLL 名");

    /* 第 2 项：终止项（全 0）                                         */
    CHECK(imp[2].OriginalFirstThunk == 0 && imp[2].Name == 0 &&
          imp[2].FirstThunk == 0,
          "第 3 项为全 0 终止符");

    /* 7) 验证 ILT/IAT 指向 IMAGE_IMPORT_BY_NAME                      */
    ilt = (DWORD*)(out_buf + NEW_SEC_FILE_OFF + OFF_ILT);
    iat = (DWORD*)(out_buf + NEW_SEC_FILE_OFF + OFF_IAT);
    CHECK(ilt[0] == NEW_SEC_RVA + OFF_IBN, "ILT[0] 指向 IBN RVA");
    CHECK(iat[0] == NEW_SEC_RVA + OFF_IBN, "IAT[0] 指向 IBN RVA");
    CHECK(ilt[1] == 0, "ILT 终止项为 0");
    CHECK(iat[1] == 0, "IAT 终止项为 0");

    /* 8) 验证 IMAGE_IMPORT_BY_NAME 内容                               */
    ibn = (IMAGE_IMPORT_BY_NAME*)(out_buf + NEW_SEC_FILE_OFF + OFF_IBN);
    CHECK(ibn->Hint == 0, "IBN Hint == 0");
    CHECK(strcmp((const char*)ibn->Name, "W7BridgeInit") == 0,
          "IBN Name == \"W7BridgeInit\"");

    /* 9) 验证 DLL 名                                                  */
    dll_name_str = (const char*)(out_buf + NEW_SEC_FILE_OFF + OFF_NAME);
    CHECK(strcmp(dll_name_str, "win7bridge.dll") == 0,
          "DLL 名 == \"win7bridge.dll\"");

    /* 10) 验证原 kernel32.dll 导入数据仍完好（在原 .text 节中）       */
    CHECK(strcmp((const char*)(out_buf + IMP_NAME_OFF), "kernel32.dll") == 0,
          "原 kernel32.dll 名字符串未损坏");

    (void)i;
    free(out_buf);
    unlink(in_path);
    unlink(out_path);
}

/* ------------------------------------------------------------------ */
/* 用例 8：pe_patch_inject_parse_args 验证 --inject 选项解析            */
/* ------------------------------------------------------------------ */
static void test_pe_patch_inject_parse_args(void)
{
    TestPePatchArgs args;
    char* argv1[] = { "pe_patch", "in.exe", "out.exe", "--inject" };
    char* argv2[] = { "pe_patch", "in.exe", "out.exe",
                      "--inject=mydll.dll,MyInit" };
    int rc;

    printf("==== 用例 8：pe_patch_inject_parse_args ====\n");

    /* 8a. --inject：inject=1，dll/func 用默认（NULL）                 */
    memset(&args, 0, sizeof(args));
    rc = pe_patch_parse_args(4, argv1, &args);
    CHECK(rc == 0, "--inject 解析返回 0");
    CHECK(args.inject == 1, "inject 字段被置 1");
    CHECK(args.inject_dll == NULL, "默认 inject_dll 为 NULL");
    CHECK(args.inject_func == NULL, "默认 inject_func 为 NULL");
    CHECK(strcmp(args.input_path, "in.exe") == 0, "input_path 正确");
    CHECK(strcmp(args.output_path, "out.exe") == 0, "output_path 正确");

    /* 8b. --inject=dll,func：dll/func 被解析                          */
    memset(&args, 0, sizeof(args));
    rc = pe_patch_parse_args(4, argv2, &args);
    CHECK(rc == 0, "--inject=dll,func 解析返回 0");
    CHECK(args.inject == 1, "inject 字段被置 1");
    CHECK(args.inject_dll != NULL &&
          strcmp(args.inject_dll, "mydll.dll") == 0,
          "inject_dll == \"mydll.dll\"");
    CHECK(args.inject_func != NULL &&
          strcmp(args.inject_func, "MyInit") == 0,
          "inject_func == \"MyInit\"");
}

/* ------------------------------------------------------------------ */
/* 用例 9：pe_patch_inject_custom 自定义 dll/func 端到端                */
/* ------------------------------------------------------------------ */
static void test_pe_patch_inject_custom(void)
{
    const char* in_path  = "/tmp/test_pe_patch_inject_custom_in.exe";
    const char* out_path = "/tmp/test_pe_patch_inject_custom_out.exe";
    unsigned char* in_buf;
    unsigned char* out_buf;
    FILE* fp;
    long out_size;
    int rc;
    IMAGE_NT_HEADERS32* nt;
    IMAGE_IMPORT_BY_NAME* ibn;
    const DWORD NEW_SEC_FILE_OFF = 0x400;
    const DWORD OFF_IBN  = 76;          /* 与 func 名长度无关            */
    const DWORD OFF_NAME_CUSTOM = 85;   /* 76 + 2 + strlen("MyInit") + 1
                                         * "MyInit" 长度 6 -> 76+2+6+1=85 */
    const char* name_str;

    printf("==== 用例 9：pe_patch_inject_custom ====\n");

    in_buf = (unsigned char*)malloc(IMG_SIZE);
    CHECK(in_buf != NULL, "malloc in_buf 成功");
    build_pe(in_buf, IMG_SIZE);

    fp = fopen(in_path, "wb");
    CHECK(fp != NULL, "创建输入文件成功");
    CHECK(fwrite(in_buf, 1, IMG_SIZE, fp) == IMG_SIZE, "写入输入文件成功");
    fclose(fp);
    free(in_buf);

    /* 自定义 dll=mydll.dll, func=MyInit                              */
    rc = pe_patch_run_inject(in_path, out_path, "mydll.dll", "MyInit");
    CHECK(rc == 0, "pe_patch_run_inject 自定义 dll/func 返回 0");

    fp = fopen(out_path, "rb");
    CHECK(fp != NULL, "打开输出文件成功");
    fseek(fp, 0, SEEK_END);
    out_size = ftell(fp);
    rewind(fp);
    out_buf = (unsigned char*)malloc((size_t)out_size);
    CHECK(out_buf != NULL, "malloc out_buf 成功");
    CHECK(fread(out_buf, 1, (size_t)out_size, fp) == (size_t)out_size,
          "读回输出文件成功");
    fclose(fp);

    nt = (IMAGE_NT_HEADERS32*)(out_buf + NT_OFF);
    CHECK(nt->FileHeader.NumberOfSections == 2,
          "NumberOfSections == 2");

    /* IBN Name 应为 "MyInit"（用结构体访问，避免手算偏移错误）        */
    ibn = (IMAGE_IMPORT_BY_NAME*)(out_buf + NEW_SEC_FILE_OFF + OFF_IBN);
    CHECK(ibn->Hint == 0, "IBN Hint == 0");
    CHECK(strcmp((const char*)ibn->Name, "MyInit") == 0,
          "IBN Name == \"MyInit\"");

    /* DLL 名应为 "mydll.dll"（位于 OFF_NAME_CUSTOM = 84）             */
    name_str = (const char*)(out_buf + NEW_SEC_FILE_OFF + OFF_NAME_CUSTOM);
    CHECK(strcmp(name_str, "mydll.dll") == 0,
          "DLL 名 == \"mydll.dll\"");

    free(out_buf);
    unlink(in_path);
    unlink(out_path);
}

/* ------------------------------------------------------------------ */
/* main                                                                */
/* ------------------------------------------------------------------ */
#ifdef WIN7BRIDGE_HOST_TEST
int main(void)
{
    test_pe_patch_e2e();
    test_pe_patch_null_args();
    test_pe_patch_missing_file();
    test_pe_patch_bad_pe();
    test_pe_patch_parse_help();
    test_pe_inject_null_args();
    test_pe_patch_inject_e2e();
    test_pe_patch_inject_parse_args();
    test_pe_patch_inject_custom();

    if (g_fail) {
        printf("\n==== 存在失败用例 ====\n");
        return 1;
    }
    printf("\n==== 全部通过 ====\n");
    return 0;
}
#endif /* WIN7BRIDGE_HOST_TEST */
