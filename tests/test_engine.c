/*
 * test_engine.c - Win7Bridge L1 符号级重写引擎 host 测试
 *
 * 覆盖：
 *   1) engine_init / engine_add_dll_redirect / engine_add_func_redirect
 *      / engine_find_func_redirect 的规则表管理
 *   2) engine_rewrite_imports：合成 PE 的整 DLL 转发与单导出 thunk 改写
 *   3) inline_hook_length_decode：x86/x64 prologue 指令长度解码正确性
 *   4) inline_hook_install / remove：host 下 trampoline 构造（不写 target）
 *
 * 仅在定义 WIN7BRIDGE_HOST_TEST 时编译 main，用原生 gcc 运行。
 * 返回 0 表示全部通过，非 0 表示有失败。
 */
#include "win7bridge/engine.h"
#include "win7bridge/inline_hook.h"
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
#define IMP_NAME_OFF       0x228   /* DLL 名字符串                     */
#define ILT_OFF            0x240   /* Import Lookup Table              */
#define IAT_OFF            0x248   /* Import Address Table             */
#define IBN_OFF            0x260   /* IMAGE_IMPORT_BY_NAME             */

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
 *   dll_name  ：导入的 DLL 名（写入 IMP_NAME_OFF）
 *   func_name ：按名导入的函数名（写入 IBN_OFF）
 * 缓冲区需 ≥ IMG_SIZE 字节且可写。
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

    /* DLL 名 */
    memcpy(buf + IMP_NAME_OFF, dll_name, strlen(dll_name) + 1);

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
    memcpy(ibn->Name, func_name, strlen(func_name) + 1);
}

/* ------------------------------------------------------------------ */
/* 用例 1：规则表管理                                                  */
/* ------------------------------------------------------------------ */
static void test_rule_table(void)
{
    RewriteEngine e;
    ExportRedirect out;
    int rc;

    printf("==== 用例 1：规则表管理 ====\n");

    rc = engine_init(&e);
    CHECK(rc == ENGINE_OK, "engine_init 成功");
    CHECK(e.dll_count == 0 && e.func_count == 0, "init 后规则数为 0");

    /* 添加 DLL 转发规则 */
    rc = engine_add_dll_redirect(&e, "kernel32.dll", "kernel33.dll");
    CHECK(rc == ENGINE_OK, "add_dll_redirect(kernel32->kernel33)");
    CHECK(e.dll_count == 1, "dll_count == 1");

    rc = engine_add_dll_redirect(&e, "user32.dll", "user33.dll");
    CHECK(rc == ENGINE_OK, "add_dll_redirect(user32->user33)");
    CHECK(e.dll_count == 2, "dll_count == 2");

    /* 添加函数重定向规则 */
    rc = engine_add_func_redirect(&e, "kernel32.dll", "SetThreadDescription",
                                  REWRITE_REPLACE_FUNC, (void*)0xdeadbeef);
    CHECK(rc == ENGINE_OK, "add_func_redirect(SetThreadDescription, REPLACE)");
    CHECK(e.func_count == 1, "func_count == 1");

    rc = engine_add_func_redirect(&e, "kernel32.dll", "Wow64DisableWow64FsRedirection",
                                  REWRITE_STUB, (void*)0xcafebabe);
    CHECK(rc == ENGINE_OK, "add_func_redirect(Wow64..., STUB)");
    CHECK(e.func_count == 2, "func_count == 2");

    /* 非法 kind 应被拒绝 */
    rc = engine_add_func_redirect(&e, "kernel32.dll", "Bad", REWRITE_NONE, NULL);
    CHECK(rc == ENGINE_ERR_INVALID_ARG, "REWRITE_NONE 被拒绝");

    /* 查询命中 */
    rc = engine_find_func_redirect(&e, "kernel32.dll", "SetThreadDescription", &out);
    CHECK(rc == 1, "find_func_redirect 命中 SetThreadDescription");
    CHECK(out.kind == REWRITE_REPLACE_FUNC, "命中 kind == REPLACE_FUNC");
    CHECK(out.replacement == (void*)0xdeadbeef, "命中 replacement == 0xdeadbeef");

    /* 大小写不敏感查询 */
    rc = engine_find_func_redirect(&e, "KERNEL32.DLL", "setthreaddescription", &out);
    CHECK(rc == 1, "大小写不敏感查询命中");
    CHECK(out.replacement == (void*)0xdeadbeef, "大小写不敏感 replacement 正确");

    /* 查询未命中 */
    rc = engine_find_func_redirect(&e, "kernel32.dll", "NotExist", &out);
    CHECK(rc == 0, "find_func_redirect 未命中返回 0");

    rc = engine_find_func_redirect(&e, "ntdll.dll", "SetThreadDescription", &out);
    CHECK(rc == 0, "不同 DLL 未命中返回 0");

    /* 非法入参 */
    rc = engine_find_func_redirect(NULL, "a", "b", &out);
    CHECK(rc == ENGINE_ERR_INVALID_ARG, "find_func_redirect 拒绝空引擎");
    rc = engine_find_func_redirect(&e, NULL, "b", &out);
    CHECK(rc == ENGINE_ERR_INVALID_ARG, "find_func_redirect 拒绝空 dll");

    /* 释放规则表（避免内存泄漏告警） */
    free(e.dll_rules);
    free(e.func_rules);
}

/* ------------------------------------------------------------------ */
/* 用例 2：engine_rewrite_imports 单导出 thunk 改写                    */
/* ------------------------------------------------------------------ */
static void test_rewrite_imports_func(void)
{
    unsigned char* buf;
    PeInfo pe;
    RewriteEngine e;
    int rc;
    DWORD iat0;

    printf("==== 用例 2：单导出替换改写 IAT thunk ====\n");

    buf = (unsigned char*)malloc(IMG_SIZE);
    if (buf == NULL) {
        printf("[FAIL] malloc 失败\n");
        g_fail = 1;
        return;
    }
    build_pe_with_import(buf, IMG_SIZE, "kernel32.dll", "SetThreadDescription");

    rc = pe_parse(buf, IMG_SIZE, &pe);
    CHECK(rc == PE_OK, "pe_parse 成功");
    CHECK(pe.import_dir != NULL, "导入表已定位");

    /* 改写前 IAT[0] 应为 IBN_OFF（指向 IMPORT_BY_NAME） */
    iat0 = *(DWORD*)(buf + IAT_OFF);
    CHECK(iat0 == IBN_OFF, "改写前 IAT[0] == IBN_OFF");

    engine_init(&e);
    rc = engine_add_func_redirect(&e, "kernel32.dll", "SetThreadDescription",
                                  REWRITE_REPLACE_FUNC, (void*)0xdeadbeef);
    CHECK(rc == ENGINE_OK, "添加 func_redirect(kernel32!SetThreadDescription)");

    rc = engine_rewrite_imports(&e, &pe);
    CHECK(rc >= 1, "engine_rewrite_imports 报告改写 >=1 项");

    iat0 = *(DWORD*)(buf + IAT_OFF);
    CHECK(iat0 == 0xdeadbeef, "改写后 IAT[0] == 0xdeadbeef");

    /* ILT 应保持不变（仅改 IAT） */
    {
        DWORD ilt0 = *(DWORD*)(buf + ILT_OFF);
        CHECK(ilt0 == IBN_OFF, "ILT[0] 保持不变");
    }

    free(e.func_rules);
    free(buf);
}

/* ------------------------------------------------------------------ */
/* 用例 3：engine_rewrite_imports 整 DLL 转发                           */
/* ------------------------------------------------------------------ */
static void test_rewrite_imports_dll(void)
{
    unsigned char* buf;
    PeInfo pe;
    RewriteEngine e;
    int rc;
    const char* name_after;

    printf("==== 用例 3：整 DLL 转发改写 DLL 名 ====\n");

    buf = (unsigned char*)malloc(IMG_SIZE);
    if (buf == NULL) {
        printf("[FAIL] malloc 失败\n");
        g_fail = 1;
        return;
    }
    build_pe_with_import(buf, IMG_SIZE, "kernel32.dll", "SetThreadDescription");

    rc = pe_parse(buf, IMG_SIZE, &pe);
    CHECK(rc == PE_OK, "pe_parse 成功");

    engine_init(&e);
    /* 同长度转发名，避免破坏后续结构 */
    rc = engine_add_dll_redirect(&e, "kernel32.dll", "kernel33.dll");
    CHECK(rc == ENGINE_OK, "添加 dll_redirect(kernel32->kernel33)");

    rc = engine_rewrite_imports(&e, &pe);
    CHECK(rc >= 1, "engine_rewrite_imports 报告改写 >=1 项");

    name_after = (const char*)(buf + IMP_NAME_OFF);
    CHECK(strcmp(name_after, "kernel33.dll") == 0, "DLL 名已改为 kernel33.dll");

    /* 大小写不敏感匹配：原名为 kernel32.dll，规则用 KERNEL32.DLL */
    {
        unsigned char* buf2 = (unsigned char*)malloc(IMG_SIZE);
        PeInfo pe2;
        RewriteEngine e2;
        if (buf2 == NULL) {
            printf("[FAIL] malloc 失败\n");
            g_fail = 1;
            free(e.dll_rules);
            free(buf);
            return;
        }
        build_pe_with_import(buf2, IMG_SIZE, "kernel32.dll", "SetThreadDescription");
        pe_parse(buf2, IMG_SIZE, &pe2);
        engine_init(&e2);
        engine_add_dll_redirect(&e2, "KERNEL32.DLL", "kernel33.dll");
        rc = engine_rewrite_imports(&e2, &pe2);
        CHECK(rc >= 1, "大小写不敏感 DLL 名匹配成功");
        CHECK(strcmp((const char*)(buf2 + IMP_NAME_OFF), "kernel33.dll") == 0,
              "大小写不敏感匹配后 DLL 名已改");
        free(e2.dll_rules);
        free(buf2);
    }

    free(e.dll_rules);
    free(buf);
}

/* ------------------------------------------------------------------ */
/* 用例 4：inline_hook_length_decode 指令长度解码                       */
/* ------------------------------------------------------------------ */
static void test_length_decode(void)
{
    size_t out = 0;
    int rc;
    unsigned char buf[32];

    printf("==== 用例 4：inline_hook_length_decode ====\n");

    /* 4.1 nop = 1 字节 */
    memset(buf, 0x90, sizeof(buf));
    rc = inline_hook_length_decode(buf, 1, &out);
    CHECK(rc == INLINE_HOOK_OK && out == 1, "0x90 (nop) 长度 == 1");

    /* 4.2 ret = 1 字节 */
    buf[0] = 0xC3;
    rc = inline_hook_length_decode(buf, 1, &out);
    CHECK(rc == INLINE_HOOK_OK && out == 1, "0xC3 (ret) 长度 == 1");

    /* 4.3 push reg = 1 字节 */
    buf[0] = 0x50;  /* push eax */
    rc = inline_hook_length_decode(buf, 1, &out);
    CHECK(rc == INLINE_HOOK_OK && out == 1, "0x50 (push eax) 长度 == 1");

    /* 4.4 pop reg = 1 字节 */
    buf[0] = 0x58;  /* pop eax */
    rc = inline_hook_length_decode(buf, 1, &out);
    CHECK(rc == INLINE_HOOK_OK && out == 1, "0x58 (pop eax) 长度 == 1");

    /* 4.5 JMP rel32 = 5 字节 */
    buf[0] = 0xE9; buf[1] = 0x00; buf[2] = 0x00; buf[3] = 0x00; buf[4] = 0x00;
    rc = inline_hook_length_decode(buf, 5, &out);
    CHECK(rc == INLINE_HOOK_OK && out == 5, "0xE9 rel32 (jmp) 长度 == 5");

    /* 4.6 CALL rel32 = 5 字节 */
    buf[0] = 0xE8;
    rc = inline_hook_length_decode(buf, 5, &out);
    CHECK(rc == INLINE_HOOK_OK && out == 5, "0xE8 rel32 (call) 长度 == 5");

    /* 4.7 SUB esp, imm8 = 3 字节 (0x83 0xEC 0x20) */
    buf[0] = 0x83; buf[1] = 0xEC; buf[2] = 0x20;
    rc = inline_hook_length_decode(buf, 3, &out);
    CHECK(rc == INLINE_HOOK_OK && out == 3, "0x83 EC 20 (sub esp,0x20) 长度 == 3");

    /* 4.8 SUB esp, imm32 = 6 字节 (0x81 0xEC 0x00 0x01 0x00 0x00) */
    buf[0] = 0x81; buf[1] = 0xEC; buf[2] = 0x00; buf[3] = 0x01;
    buf[4] = 0x00; buf[5] = 0x00;
    rc = inline_hook_length_decode(buf, 6, &out);
    CHECK(rc == INLINE_HOOK_OK && out == 6, "0x81 EC 00010000 (sub esp,0x100) 长度 == 6");

    /* 4.9 MOV r/m32, r32 (寄存器直接) = 2 字节 (0x89 0xC1: mov ecx, eax) */
    buf[0] = 0x89; buf[1] = 0xC1;  /* ModR/M mod=3 reg=0 rm=1 */
    rc = inline_hook_length_decode(buf, 2, &out);
    CHECK(rc == INLINE_HOOK_OK && out == 2, "0x89 C1 (mov ecx,eax) 长度 == 2");

    /* 4.10 MOV [esp+8], ebx = 4 字节 (0x89 0x5C 0x24 0x08)
     *      ModR/M=0x5C mod=01 rm=100 -> SIB(0x24 base=esp) + disp8 */
    buf[0] = 0x89; buf[1] = 0x5C; buf[2] = 0x24; buf[3] = 0x08;
    rc = inline_hook_length_decode(buf, 4, &out);
    CHECK(rc == INLINE_HOOK_OK && out == 4, "0x89 5C 24 08 (mov [esp+8],ebx) 长度 == 4");

    /* 4.11 未识别指令返回 ERR_UNKNOWN_OPCODE (0xCC = int3) */
    buf[0] = 0xCC;
    rc = inline_hook_length_decode(buf, 1, &out);
    CHECK(rc == INLINE_HOOK_ERR_UNKNOWN_OPCODE, "0xCC (int3) 返回 UNKNOWN_OPCODE");

    /* 4.12 非法入参 */
    rc = inline_hook_length_decode(NULL, 1, &out);
    CHECK(rc == INLINE_HOOK_ERR_INVALID_ARG, "NULL code 被拒绝");
    rc = inline_hook_length_decode(buf, 1, NULL);
    CHECK(rc == INLINE_HOOK_ERR_INVALID_ARG, "NULL out_len 被拒绝");

    /* 4.13 多指令组合：nop + jmp rel32，min_len=6 应解码出 6 字节 */
    buf[0] = 0x90;  /* nop */
    buf[1] = 0xE9; buf[2] = 0x00; buf[3] = 0x00; buf[4] = 0x00; buf[5] = 0x00;
    rc = inline_hook_length_decode(buf, 6, &out);
    CHECK(rc == INLINE_HOOK_OK && out == 6, "nop + jmp rel32 组合长度 == 6");
}

/* ------------------------------------------------------------------ */
/* 用例 5：64 位专属指令长度解码（仅 64 位 host 验证）                  */
/* ------------------------------------------------------------------ */
#if defined(__x86_64__) || defined(_WIN64) || defined(__LP64__) || \
    defined(__amd64__)
static void test_length_decode_x64(void)
{
    size_t out = 0;
    int rc;
    unsigned char buf[32];

    printf("==== 用例 5：64 位专属指令长度解码 ====\n");

    /* 5.1 REX.W + MOV [rsp+8], rbx = 5 字节
     *     0x48 0x89 0x5C 0x24 0x08
     *     REX.W(0x48) + MOV(0x89) + ModR/M(0x5C mod=01 rm=100) + SIB(0x24) + disp8 */
    buf[0] = 0x48; buf[1] = 0x89; buf[2] = 0x5C; buf[3] = 0x24; buf[4] = 0x08;
    memset(buf + 5, 0x90, sizeof(buf) - 5);
    rc = inline_hook_length_decode(buf, 5, &out);
    CHECK(rc == INLINE_HOOK_OK && out == 5,
          "0x48 89 5C 24 08 (mov [rsp+8],rbx) 长度 == 5");

    /* 5.2 REX.W + SUB rsp, imm8 = 4 字节 (0x48 0x83 0xEC 0x28)
     *     min_len=5 时再补一条 nop 凑够 5 字节 */
    buf[0] = 0x48; buf[1] = 0x83; buf[2] = 0xEC; buf[3] = 0x28; buf[4] = 0x90;
    rc = inline_hook_length_decode(buf, 4, &out);
    CHECK(rc == INLINE_HOOK_OK && out == 4,
          "0x48 83 EC 28 (sub rsp,0x28) 长度 == 4");
    rc = inline_hook_length_decode(buf, 5, &out);
    CHECK(rc == INLINE_HOOK_OK && out == 5,
          "sub rsp,0x28 + nop 组合长度 == 5");

    /* 5.3 REX.W + MOV r64, r/m64 寄存器直接 = 3 字节 (0x48 0x8B 0xC3: mov rax, rbx) */
    buf[0] = 0x48; buf[1] = 0x8B; buf[2] = 0xC3;
    rc = inline_hook_length_decode(buf, 3, &out);
    CHECK(rc == INLINE_HOOK_OK && out == 3,
          "0x48 8B C3 (mov rax,rbx) 长度 == 3");
}
#else
static void test_length_decode_x64(void)
{
    printf("==== 用例 5：64 位专属测试跳过（非 64 位 host） ====\n");
}
#endif

/* ------------------------------------------------------------------ */
/* 用例 6：inline_hook_install / remove trampoline 构造                */
/* ------------------------------------------------------------------ */
static void test_install_trampoline(void)
{
    unsigned char target[32];
    InlineHook h;
    int rc;
    size_t i;

    printf("==== 用例 6：inline_hook_install trampoline 构造 ====\n");

    /* 用 nop 序列作为 target，确保解码成功 */
    memset(target, 0x90, sizeof(target));

    rc = inline_hook_install(&h, target, (void*)0xabcd1234);
    CHECK(rc == INLINE_HOOK_OK, "inline_hook_install 成功");
    CHECK(h.target == target, "h.target == target");
    CHECK(h.detour == (void*)0xabcd1234, "h.detour 记录正确");
    CHECK(h.trampoline != NULL, "h.trampoline 已分配");
    CHECK(h.patch_size == INLINE_HOOK_JMP_LEN, "h.patch_size == JMP_LEN");

    /* trampoline 前 patch_size 字节应等于 target 前 patch_size 字节 */
    if (h.trampoline != NULL) {
        int same = 1;
        for (i = 0; i < h.patch_size; ++i) {
            if (((unsigned char*)h.trampoline)[i] != target[i]) {
                same = 0;
                break;
            }
        }
        CHECK(same, "trampoline 前 patch_size 字节 == target 原指令");

        /* 跳回桩首字节：x86=0xE9，x64=0xFF 0x25 */
        {
            unsigned char* jmp = (unsigned char*)h.trampoline + h.patch_size;
#if INLINE_HOOK_JMP_LEN == 5
            CHECK(jmp[0] == 0xE9, "x86 trampoline 跳回桩首字节 == 0xE9");
#else
            CHECK(jmp[0] == 0xFF && jmp[1] == 0x25,
                  "x64 trampoline 跳回桩首字节 == FF 25");
#endif
        }
    }

    rc = inline_hook_remove(&h);
    CHECK(rc == INLINE_HOOK_OK, "inline_hook_remove 成功");
    CHECK(h.trampoline == NULL, "remove 后 trampoline == NULL");

    /* 非法入参 */
    rc = inline_hook_install(NULL, target, (void*)0x1);
    CHECK(rc == INLINE_HOOK_ERR_INVALID_ARG, "install 拒绝空句柄");
    rc = inline_hook_install(&h, NULL, (void*)0x1);
    CHECK(rc == INLINE_HOOK_ERR_INVALID_ARG, "install 拒绝空 target");
    rc = inline_hook_remove(NULL);
    CHECK(rc == INLINE_HOOK_ERR_INVALID_ARG, "remove 拒绝空句柄");
}

/* ------------------------------------------------------------------ */
/* main                                                                */
/* ------------------------------------------------------------------ */
#ifdef WIN7BRIDGE_HOST_TEST
int main(void)
{
    test_rule_table();
    test_rewrite_imports_func();
    test_rewrite_imports_dll();
    test_length_decode();
    test_length_decode_x64();
    test_install_trampoline();

    if (g_fail) {
        printf("\n==== 存在失败用例 ====\n");
        return 1;
    }
    printf("\n==== 全部通过 ====\n");
    return 0;
}
#endif /* WIN7BRIDGE_HOST_TEST */
