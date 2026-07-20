/*
 * pe_patch.c - Win7Bridge SubTask 3.2.1 离线 PE patch 工具
 *
 * 【开发文档】
 *
 * 目的：对目标 EXE 做 L0 PE 修正后落盘，生成"已 patch EXE"，便于
 *   不通过 Loader 注入的方式直接双击运行（携带兼容层 DLL）。
 *
 * 分点展开：
 *   1. CLI 接口
 *      pe_patch <input.exe> <output.exe> [--inject[=dll,func]] [--help]
 *      纯文件 IO，host 与 Windows 均可运行。
 *
 *   2. 处理流程（L0 路径，pe_patch_run）
 *      fopen/fread 整个 EXE -> malloc 内存
 *      pe_parse + pe_fix_subsystem + pe_strip_bound_imports
 *      fopen/fwrite 落盘到 output.exe
 *
 *   3. 处理流程（注入路径，pe_patch_run_inject）
 *      在 L0 修正之后追加：
 *        pe_inject_import(&buf, &size, dll, func)
 *          - 在 PE 末尾追加新节 ".w7b"，承载新导入描述符表
 *          - 复制原 N 个 import descriptor，追加 win7bridge.dll 项 + 终止项
 *          - 重定向 DataDirectory[IMPORT] 指向新节
 *          - 更新 NumberOfSections / SizeOfImage
 *      fopen/fwrite 落盘
 *
 *   4. 新节 ".w7b" 布局（节内偏移升序）
 *      +0x00              复制原 N 个 import descriptor   (N*20 字节)
 *      +N*20              新增 dll descriptor              (20 字节)
 *      +(N+1)*20          全 0 终止项                       (20 字节)
 *      +off_ilt           ILT: [IBN_RVA, 0]                (8 字节)
 *      +off_iat           IAT: [IBN_RVA, 0]                (8 字节)
 *      +off_ibn           IMAGE_IMPORT_BY_NAME             (2 + len(func) + 1)
 *                         Hint=0, Name=func\0
 *      +off_name          DLL 名 "win7bridge.dll\0"        (len(dll) + 1)
 *      节大小对齐到 FileAlignment；RVA 对齐到 SectionAlignment。
 *      Characteristics = INITIALIZED_DATA | READ | WRITE = 0xC0000040
 *
 *   5. 错误码
 *      0=成功；1=参数错误；2=读文件失败；3=PE 解析失败；4=写文件失败；
 *      5=PE 头部无空间放新节头；6=注入失败（其他）。
 *
 *   6. 平台隔离
 *      全部标准 C 文件 IO，无 Windows 专有调用。host 与 Windows
 *      共用同一份实现，便于 host 测试与 syntax-check。
 *
 *   7. 头部空间检查
 *      first_section_off = e_lfanew + 4 + 20 + SizeOfOptionalHeader
 *      after_last_sec    = first_section_off + NumberOfSections * 40
 *      要求 after_last_sec + 40 <= SizeOfHeaders，否则返回 5。
 *
 *   8. manifest 改写
 *      暂不集成；已有 src/pe/manifest.c 可在 3.2.2 真机阶段整合。
 */

#include "win7bridge/pe.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------ */
/* 常量：默认注入 DLL 与函数                                            */
/* ------------------------------------------------------------------ */
#define W7B_DEFAULT_INJECT_DLL  "win7bridge.dll"
#define W7B_DEFAULT_INJECT_FUNC "W7BridgeInit"

/* ------------------------------------------------------------------ */
/* pe_patch_print_help                                                 */
/* ------------------------------------------------------------------ */
void pe_patch_print_help(const char* prog, void* stream)
{
    FILE* fp = (FILE*)stream;
    if (fp == NULL) fp = stdout;
    if (prog == NULL) prog = "pe_patch";
    fprintf(fp,
        "Win7Bridge PE Patch - 离线修正 PE 子系统版本与 bound import\n"
        "\n"
        "用法: %s <input.exe> <output.exe> [--inject[=dll,func]] [--help]\n"
        "\n"
        "参数:\n"
        "  input.exe    待 patch 的 EXE 文件路径\n"
        "  output.exe   patch 后输出文件路径\n"
        "\n"
        "选项:\n"
        "  --help       显示本帮助\n"
        "  --inject     注入 win7bridge.dll 导入项到 PE 新节 .w7b\n"
        "  --inject=dll,func  指定注入的 DLL 与函数名（默认\n"
        "                %s,%s）\n"
        "\n"
        "示例:\n"
        "  %s case_high_subsys.exe case_patched.exe\n"
        "  %s in.exe out.exe --inject\n"
        "  %s in.exe out.exe --inject=mydll.dll,MyInit\n",
        prog, W7B_DEFAULT_INJECT_DLL, W7B_DEFAULT_INJECT_FUNC,
        prog, prog, prog);
}

/* ------------------------------------------------------------------ */
/* pe_patch_args 结构与解析                                            */
/* ------------------------------------------------------------------ */
typedef struct {
    const char* input_path;
    const char* output_path;
    int         help;
    int         inject;          /* 1 表示 --inject 模式                 */
    const char* inject_dll;      /* NULL -> 默认 W7B_DEFAULT_INJECT_DLL  */
    const char* inject_func;     /* NULL -> 默认 W7B_DEFAULT_INJECT_FUNC */
} PePatchArgs;

int pe_patch_parse_args(int argc, char** argv, PePatchArgs* out)
{
    int i;
    int positional = 0;
    if (out == NULL) return -1;
    memset(out, 0, sizeof(*out));

    for (i = 1; i < argc; ++i) {
        const char* a = argv[i];
        if (strcmp(a, "--help") == 0) {
            out->help = 1;
            return 0;
        } else if (strcmp(a, "--inject") == 0) {
            out->inject = 1;
        } else if (strncmp(a, "--inject=", 9) == 0) {
            /* 解析 --inject=dll,func */
            const char* eq = a + 9;
            const char* comma = strchr(eq, ',');
            out->inject = 1;
            if (comma == NULL) {
                /* 仅指定 dll，func 用默认 */
                out->inject_dll = eq;
            } else {
                /* 注意：argv 字符串可写，但此处不改原串；用偏移记录 */
                /* 由于 dll 名片段在 argv 内存里且 NUL 在 '=' 或行尾，
                 * 我们改用临时静态缓冲区拆分 */
                static char dll_buf[256];
                static char func_buf[256];
                size_t dlen = (size_t)(comma - eq);
                size_t flen = strlen(comma + 1);
                if (dlen >= sizeof(dll_buf)) dlen = sizeof(dll_buf) - 1;
                if (flen >= sizeof(func_buf)) flen = sizeof(func_buf) - 1;
                memcpy(dll_buf, eq, dlen); dll_buf[dlen] = 0;
                memcpy(func_buf, comma + 1, flen); func_buf[flen] = 0;
                out->inject_dll = dll_buf;
                out->inject_func = func_buf;
            }
        } else if (a[0] == '-' && a[1] == '-') {
            fprintf(stderr, "未知参数: %s\n", a);
            return -1;
        } else {
            if (positional == 0) {
                out->input_path = a;
            } else if (positional == 1) {
                out->output_path = a;
            } else {
                fprintf(stderr, "多余的位置参数: %s\n", a);
                return -1;
            }
            ++positional;
        }
    }
    if (positional < 2) {
        fprintf(stderr, "缺少 %s\n", positional == 0 ? "input.exe" : "output.exe");
        return -1;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* 内部：把 v 向上对齐到 alignment（alignment 必须是 2 的幂）            */
/* ------------------------------------------------------------------ */
static DWORD pe_align_up(DWORD v, DWORD alignment)
{
    if (alignment == 0) return v;
    return (v + alignment - 1) & ~(alignment - 1);
}

/* ------------------------------------------------------------------ */
/* 内部：数原导入描述符个数（遇全 0 终止项停止）                         */
/*   PE 约定：RVA == 文件偏移，因此可直接用 pe->import_dir 指针遍历。    */
/* ------------------------------------------------------------------ */
static int pe_count_import_descriptors(const PeInfo* pe)
{
    int count = 0;
    const IMAGE_IMPORT_DESCRIPTOR* imp;
    const unsigned char* end;

    if (pe == NULL || pe->import_dir == NULL) return 0;
    end = (const unsigned char*)pe->data + pe->size;
    imp = pe->import_dir;
    while (1) {
        const unsigned char* next = (const unsigned char*)(imp + 1);
        if (next > end) break;
        /* 全 0 终止项：5 个 DWORD 全为 0 */
        if (imp->OriginalFirstThunk == 0 && imp->Name == 0 &&
            imp->FirstThunk == 0 && imp->TimeDateStamp == 0 &&
            imp->ForwarderChain == 0) {
            break;
        }
        ++count;
        ++imp;
    }
    return count;
}

/* ------------------------------------------------------------------ */
/* pe_inject_import - 在 PE 末尾追加新节 .w7b，注入 dll_name/func_name  */
/*   pbuf/psize ：*pbuf 指向已 L0 修正的 PE 缓冲区；函数内 realloc，   */
/*                成功后 *pbuf/*psize 更新为新值，旧指针失效。          */
/*   dll_name   ：要注入的 DLL 名（如 "win7bridge.dll"）                */
/*   func_name  ：要导入的函数名（如 "W7BridgeInit"）                   */
/*                                                                  */
/*   返回：>=0 成功（新节 SizeOfRawData 字节数）；<0 失败：              */
/*        -1 入参非法；-2 PE 解析失败；-3 头部无空间；-4 realloc 失败。 */
/* ------------------------------------------------------------------ */
int pe_inject_import(unsigned char** pbuf, size_t* psize,
                     const char* dll_name, const char* func_name)
{
    unsigned char* buf;
    unsigned char* new_buf;
    size_t         size;
    PeInfo         pe;
    int            rc;
    DWORD          nt_off;
    int            is64;
    DWORD          orig_imp_rva;
    DWORD          orig_imp_count;
    DWORD          first_section_off;
    DWORD          after_last_sec_off;
    WORD           orig_num_sections;
    DWORD          orig_size_of_image;
    DWORD          orig_file_size;
    DWORD          sec_align, file_align, size_of_headers;
    DWORD          new_sec_rva;
    DWORD          new_sec_file_off;
    DWORD          new_imp_total_size;
    DWORD          off_ilt, off_iat, off_ibn, off_name;
    DWORD          ilt_rva, iat_rva, ibn_rva, name_rva;
    DWORD          virtual_size, raw_size;
    DWORD          new_file_size;
    size_t         dll_name_len, func_name_len;
    IMAGE_SECTION_HEADER* new_sec_hdr;
    unsigned char* sec_data;
    DWORD          i;

    if (pbuf == NULL || psize == NULL || *pbuf == NULL) return -1;
    if (dll_name == NULL || func_name == NULL) return -1;

    buf = *pbuf;
    size = *psize;

    rc = pe_parse(buf, size, &pe);
    if (rc != PE_OK) return -2;

    nt_off = pe.dos->e_lfanew;
    is64 = pe.is64;

    /* 读出后续要用到的所有字段（realloc 后 pe.* 指针会失效）            */
    if (is64) {
        const IMAGE_NT_HEADERS64* nt =
            (const IMAGE_NT_HEADERS64*)(buf + nt_off);
        WORD opt_size = nt->FileHeader.SizeOfOptionalHeader;
        orig_num_sections  = nt->FileHeader.NumberOfSections;
        orig_size_of_image = nt->OptionalHeader.SizeOfImage;
        size_of_headers    = nt->OptionalHeader.SizeOfHeaders;
        sec_align          = nt->OptionalHeader.SectionAlignment;
        file_align         = nt->OptionalHeader.FileAlignment;
        orig_imp_rva       = nt->OptionalHeader
                                 .DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]
                                     .VirtualAddress;
        /* PE 规范：节头紧跟 OptionalHeader，偏移由 SizeOfOptionalHeader 决定 */
        first_section_off  = nt_off + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER)
                                  + opt_size;
    } else {
        const IMAGE_NT_HEADERS32* nt =
            (const IMAGE_NT_HEADERS32*)(buf + nt_off);
        WORD opt_size = nt->FileHeader.SizeOfOptionalHeader;
        orig_num_sections  = nt->FileHeader.NumberOfSections;
        orig_size_of_image = nt->OptionalHeader.SizeOfImage;
        size_of_headers    = nt->OptionalHeader.SizeOfHeaders;
        sec_align          = nt->OptionalHeader.SectionAlignment;
        file_align         = nt->OptionalHeader.FileAlignment;
        orig_imp_rva       = nt->OptionalHeader
                                 .DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]
                                     .VirtualAddress;
        /* PE 规范：节头紧跟 OptionalHeader，偏移由 SizeOfOptionalHeader 决定 */
        first_section_off  = nt_off + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER)
                                  + opt_size;
    }

    /* 1. 头部空间检查：是否还有空间放新节头                            */
    after_last_sec_off = first_section_off +
                        (DWORD)orig_num_sections * IMAGE_SIZEOF_SECTION_HEADER;
    if (after_last_sec_off + IMAGE_SIZEOF_SECTION_HEADER > size_of_headers) {
        return -3;
    }

    /* 2. 计算新节 RVA 与文件偏移                                       */
    orig_file_size = (DWORD)size;
    new_sec_rva      = pe_align_up(orig_size_of_image, sec_align);
    new_sec_file_off = pe_align_up(orig_file_size,    file_align);

    /* 3. 原导入描述符个数                                              */
    orig_imp_count = (DWORD)pe_count_import_descriptors(&pe);

    /* 4. 新节内各结构偏移                                              */
    dll_name_len  = strlen(dll_name);
    func_name_len = strlen(func_name);
    new_imp_total_size = (orig_imp_count + 2) * sizeof(IMAGE_IMPORT_DESCRIPTOR);
    off_ilt  = new_imp_total_size;
    off_iat  = off_ilt + 8;
    off_ibn  = off_iat + 8;
    off_name = off_ibn + 2 + (DWORD)func_name_len + 1;
    virtual_size = off_name + (DWORD)dll_name_len + 1;
    raw_size = pe_align_up(virtual_size, file_align);

    /* 5. 新文件大小                                                    */
    new_file_size = new_sec_file_off + raw_size;

    /* 6. realloc 缓冲区                                                */
    new_buf = (unsigned char*)realloc(buf, new_file_size);
    if (new_buf == NULL) return -4;
    buf = new_buf;
    *pbuf = new_buf;

    /* 7. 文件对齐 padding [orig_file_size, new_sec_file_off) 填 0      */
    if (new_sec_file_off > orig_file_size) {
        memset(buf + orig_file_size, 0, new_sec_file_off - orig_file_size);
    }

    /* 8. 写新节数据                                                    */
    sec_data = buf + new_sec_file_off;
    memset(sec_data, 0, raw_size);  /* 含尾部对齐 padding */

    /* 8a. 复制原 N 个 import descriptor（如原 PE 有）                  */
    if (orig_imp_count > 0 && orig_imp_rva != 0 &&
        orig_imp_rva + orig_imp_count * sizeof(IMAGE_IMPORT_DESCRIPTOR)
            <= orig_file_size) {
        memcpy(sec_data,
               buf + orig_imp_rva,
               orig_imp_count * sizeof(IMAGE_IMPORT_DESCRIPTOR));
    }

    /* 8b. 计算各结构在镜像中的 RVA                                     */
    ilt_rva  = new_sec_rva + off_ilt;
    iat_rva  = new_sec_rva + off_iat;
    ibn_rva  = new_sec_rva + off_ibn;
    name_rva = new_sec_rva + off_name;

    /* 8c. 写新 dll descriptor（位于 sec_data + N*20）                  */
    {
        IMAGE_IMPORT_DESCRIPTOR* new_imp =
            (IMAGE_IMPORT_DESCRIPTOR*)
                (sec_data + orig_imp_count * sizeof(IMAGE_IMPORT_DESCRIPTOR));
        new_imp->OriginalFirstThunk = ilt_rva;
        new_imp->TimeDateStamp      = 0;
        new_imp->ForwarderChain     = 0;
        new_imp->Name               = name_rva;
        new_imp->FirstThunk         = iat_rva;
    }
    /* 终止项已由 memset 0 填好 */

    /* 8d. ILT: [IBN_RVA, 0]                                            */
    {
        DWORD* p = (DWORD*)(sec_data + off_ilt);
        p[0] = ibn_rva;
        p[1] = 0;
    }
    /* 8e. IAT: [IBN_RVA, 0]                                            */
    {
        DWORD* p = (DWORD*)(sec_data + off_iat);
        p[0] = ibn_rva;
        p[1] = 0;
    }
    /* 8f. IMAGE_IMPORT_BY_NAME: Hint=0, Name=func\0                    */
    {
        unsigned char* p = sec_data + off_ibn;
        p[0] = 0;  /* Hint 低字节 */
        p[1] = 0;  /* Hint 高字节 */
        memcpy(p + 2, func_name, func_name_len + 1);  /* 含 NUL */
    }
    /* 8g. DLL 名 dll_name\0                                            */
    memcpy(sec_data + off_name, dll_name, dll_name_len + 1);

    /* 9. 写新节头到 after_last_sec_off                                  */
    new_sec_hdr = (IMAGE_SECTION_HEADER*)(buf + after_last_sec_off);
    memset(new_sec_hdr, 0, IMAGE_SIZEOF_SECTION_HEADER);
    memcpy(new_sec_hdr->Name, ".w7b\0\0\0\0", 8);
    new_sec_hdr->Misc.VirtualSize  = virtual_size;
    new_sec_hdr->VirtualAddress    = new_sec_rva;
    new_sec_hdr->SizeOfRawData     = raw_size;
    new_sec_hdr->PointerToRawData  = new_sec_file_off;
    new_sec_hdr->Characteristics   = 0xC0000040u; /* INIT_DATA|READ|WRITE */

    /* 10. 更新 NT 头字段                                               */
    if (is64) {
        IMAGE_NT_HEADERS64* nt = (IMAGE_NT_HEADERS64*)(buf + nt_off);
        nt->FileHeader.NumberOfSections = (WORD)(orig_num_sections + 1);
        nt->OptionalHeader.SizeOfImage =
            new_sec_rva + pe_align_up(virtual_size, sec_align);
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]
            .VirtualAddress = new_sec_rva;
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]
            .Size = new_imp_total_size;
    } else {
        IMAGE_NT_HEADERS32* nt = (IMAGE_NT_HEADERS32*)(buf + nt_off);
        nt->FileHeader.NumberOfSections = (WORD)(orig_num_sections + 1);
        nt->OptionalHeader.SizeOfImage =
            new_sec_rva + pe_align_up(virtual_size, sec_align);
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]
            .VirtualAddress = new_sec_rva;
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]
            .Size = new_imp_total_size;
    }

    /* 11. 更新输出 size                                                */
    *psize = new_file_size;
    (void)i;  /* 暂未使用循环变量 */
    return (int)raw_size;
}

/* ------------------------------------------------------------------ */
/* pe_patch_run_inject - L0 修正 + 导入表注入 + 落盘                     */
/*   inject_dll/func：可为 NULL，NULL 时使用默认 win7bridge.dll/W7BridgeInit */
/*   返回：0=成功；1=参数；2=读失败；3=PE 解析失败；4=写失败；           */
/*        5=头部无空间；6=注入失败                                      */
/* ------------------------------------------------------------------ */
int pe_patch_run_inject(const char* input_path, const char* output_path,
                        const char* inject_dll, const char* inject_func)
{
    FILE*          fp = NULL;
    long           file_size;
    unsigned char* buf = NULL;
    size_t         nread, nwritten, total_size;
    PeInfo         pe;
    int            rc;
    int            pe_rc;
    const char*    dll;
    const char*    func;

    if (input_path == NULL || output_path == NULL) return 1;
    dll  = (inject_dll  != NULL) ? inject_dll  : W7B_DEFAULT_INJECT_DLL;
    func = (inject_func != NULL) ? inject_func : W7B_DEFAULT_INJECT_FUNC;

    /* 1) 读入整个文件（同 pe_patch_run）                               */
    fp = fopen(input_path, "rb");
    if (fp == NULL) {
        fprintf(stderr, "[pe_patch] 无法打开输入文件: %s\n", input_path);
        return 2;
    }
    if (fseek(fp, 0, SEEK_END) != 0) {
        fprintf(stderr, "[pe_patch] fseek END 失败\n");
        fclose(fp);
        return 2;
    }
    file_size = ftell(fp);
    if (file_size <= 0) {
        fprintf(stderr, "[pe_patch] 文件为空或 ftell 失败\n");
        fclose(fp);
        return 2;
    }
    rewind(fp);

    buf = (unsigned char*)malloc((size_t)file_size);
    if (buf == NULL) {
        fprintf(stderr, "[pe_patch] malloc 失败 size=%ld\n", file_size);
        fclose(fp);
        return 2;
    }
    nread = fread(buf, 1, (size_t)file_size, fp);
    fclose(fp);
    if (nread != (size_t)file_size) {
        fprintf(stderr, "[pe_patch] fread 不完整: %zu / %ld\n",
                nread, file_size);
        free(buf);
        return 2;
    }
    total_size = (size_t)file_size;

    /* 2) L0 修正                                                       */
    pe_rc = pe_parse(buf, total_size, &pe);
    if (pe_rc != PE_OK) {
        fprintf(stderr, "[pe_patch] pe_parse 失败: %d\n", pe_rc);
        free(buf);
        return 3;
    }
    pe_rc = pe_fix_subsystem(&pe);
    if (pe_rc < 0) {
        fprintf(stderr, "[pe_patch] pe_fix_subsystem 失败: %d\n", pe_rc);
        free(buf);
        return 3;
    }
    printf("[pe_patch] subsystem fix: %s (%d)\n",
           pe_rc > 0 ? "已修改" : "无需修改", pe_rc);

    pe_rc = pe_strip_bound_imports(&pe);
    if (pe_rc < 0) {
        fprintf(stderr, "[pe_patch] pe_strip_bound_imports 失败: %d\n", pe_rc);
        free(buf);
        return 3;
    }
    printf("[pe_patch] bound import strip: %d descriptor(s)\n", pe_rc);

    /* 3) 注入                                                          */
    rc = pe_inject_import(&buf, &total_size, dll, func);
    if (rc < 0) {
        fprintf(stderr, "[pe_patch] pe_inject_import 失败: %d\n", rc);
        free(buf);
        if (rc == -3) return 5;
        return 6;
    }
    printf("[pe_patch] inject %s!%s -> new section size %d bytes\n",
           dll, func, rc);

    /* 4) 落盘                                                          */
    fp = fopen(output_path, "wb");
    if (fp == NULL) {
        fprintf(stderr, "[pe_patch] 无法创建输出文件: %s\n", output_path);
        free(buf);
        return 4;
    }
    nwritten = fwrite(buf, 1, total_size, fp);
    fclose(fp);
    free(buf);
    if (nwritten != total_size) {
        fprintf(stderr, "[pe_patch] fwrite 不完整: %zu / %zu\n",
                nwritten, total_size);
        return 4;
    }

    printf("[pe_patch] 已写出: %s (%zu 字节)\n", output_path, total_size);
    return 0;
}

/* ------------------------------------------------------------------ */
/* pe_patch_run - 核心处理流程，host 可测试                              */
/*   返回：0=成功；2=读失败；3=PE 解析失败；4=写失败                     */
/* ------------------------------------------------------------------ */
int pe_patch_run(const char* input_path, const char* output_path)
{
    FILE*       fp = NULL;
    long        file_size;
    unsigned char* buf = NULL;
    size_t      nread, nwritten;
    PeInfo      pe;
    int         rc = 0;
    int         pe_rc;

    if (input_path == NULL || output_path == NULL) {
        return 1;
    }

    /* 1) 读入整个文件                                                    */
    fp = fopen(input_path, "rb");
    if (fp == NULL) {
        fprintf(stderr, "[pe_patch] 无法打开输入文件: %s\n", input_path);
        return 2;
    }
    if (fseek(fp, 0, SEEK_END) != 0) {
        fprintf(stderr, "[pe_patch] fseek END 失败\n");
        fclose(fp);
        return 2;
    }
    file_size = ftell(fp);
    if (file_size <= 0) {
        fprintf(stderr, "[pe_patch] 文件为空或 ftell 失败\n");
        fclose(fp);
        return 2;
    }
    rewind(fp);

    buf = (unsigned char*)malloc((size_t)file_size);
    if (buf == NULL) {
        fprintf(stderr, "[pe_patch] malloc 失败 size=%ld\n", file_size);
        fclose(fp);
        return 2;
    }
    nread = fread(buf, 1, (size_t)file_size, fp);
    fclose(fp);
    if (nread != (size_t)file_size) {
        fprintf(stderr, "[pe_patch] fread 不完整: %zu / %ld\n",
                nread, file_size);
        free(buf);
        return 2;
    }

    /* 2) PE 解析与修正                                                   */
    pe_rc = pe_parse(buf, (size_t)file_size, &pe);
    if (pe_rc != PE_OK) {
        fprintf(stderr, "[pe_patch] pe_parse 失败: %d\n", pe_rc);
        free(buf);
        return 3;
    }

    pe_rc = pe_fix_subsystem(&pe);
    if (pe_rc < 0) {
        fprintf(stderr, "[pe_patch] pe_fix_subsystem 失败: %d\n", pe_rc);
        free(buf);
        return 3;
    }
    printf("[pe_patch] subsystem fix: %s (%d)\n",
           pe_rc > 0 ? "已修改" : "无需修改", pe_rc);

    pe_rc = pe_strip_bound_imports(&pe);
    if (pe_rc < 0) {
        fprintf(stderr, "[pe_patch] pe_strip_bound_imports 失败: %d\n", pe_rc);
        free(buf);
        return 3;
    }
    printf("[pe_patch] bound import strip: %d descriptor(s)\n", pe_rc);

    /* 3) 落盘                                                            */
    fp = fopen(output_path, "wb");
    if (fp == NULL) {
        fprintf(stderr, "[pe_patch] 无法创建输出文件: %s\n", output_path);
        free(buf);
        return 4;
    }
    nwritten = fwrite(buf, 1, (size_t)file_size, fp);
    if (nwritten != (size_t)file_size) {
        fprintf(stderr, "[pe_patch] fwrite 不完整: %zu / %ld\n",
                nwritten, file_size);
        fclose(fp);
        free(buf);
        return 4;
    }
    fclose(fp);
    free(buf);

    printf("[pe_patch] 已写出: %s (%ld 字节)\n", output_path, file_size);
    return 0;
}

/* ------------------------------------------------------------------ */
/* main：host 与 Windows 共用同一份                                      */
/* ------------------------------------------------------------------ */
#if !defined(WIN7BRIDGE_HOST_TEST) && !defined(WIN7BRIDGE_SYNTAX_CHECK)
int main(int argc, char** argv)
{
    PePatchArgs args;
    int         rc;

    if (pe_patch_parse_args(argc, argv, &args) != 0) {
        pe_patch_print_help(argv[0], stderr);
        return 1;
    }
    if (args.help) {
        pe_patch_print_help(argv[0], stdout);
        return 0;
    }
    if (args.inject) {
        rc = pe_patch_run_inject(args.input_path, args.output_path,
                                  args.inject_dll, args.inject_func);
    } else {
        rc = pe_patch_run(args.input_path, args.output_path);
    }
    return rc;
}
#endif

/* ------------------------------------------------------------------ */
/* WIN7BRIDGE_HOST_TEST 下暴露 main 用于测试                             */
/* ------------------------------------------------------------------ */
#ifdef WIN7BRIDGE_HOST_TEST
int pe_patch_main(int argc, char** argv)
{
    PePatchArgs args;
    int         rc;

    if (pe_patch_parse_args(argc, argv, &args) != 0) {
        pe_patch_print_help(argv[0], stderr);
        return 1;
    }
    if (args.help) {
        pe_patch_print_help(argv[0], stdout);
        return 0;
    }
    if (args.inject) {
        rc = pe_patch_run_inject(args.input_path, args.output_path,
                                  args.inject_dll, args.inject_func);
    } else {
        rc = pe_patch_run(args.input_path, args.output_path);
    }
    return rc;
}
#endif
