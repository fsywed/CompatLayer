/*
 * pe.c - Win7Bridge L0 PE 解析与修正器实现
 *
 * 纯用户态、无 Windows API 依赖的 PE 镜像解析与修正。所有指针运算基于
 * "按镜像映射"的缓冲区：RVA 直接当作相对缓冲区起点的偏移使用。调用者
 * 需保证缓冲区可写（host 测试用 malloc；Windows 下用 WriteProcessMemory
 * 或可写文件映射）。
 */
#include "win7bridge/pe.h"

#include <stdio.h>
#include <stddef.h>

/* ------------------------------------------------------------------ */
/* 内部辅助：边界检查与 RVA -> 指针转换                                */
/* ------------------------------------------------------------------ */

/* 判断 [off, off+need) 是否完全落在缓冲区内 */
static int pe_in_bounds(const PeInfo* pe, size_t off, size_t need)
{
    return (pe != NULL) && (off <= pe->size) && (need <= pe->size - off);
}

/* RVA -> 只读指针，带边界检查；越界或 RVA==0 返回 NULL */
static const void* pe_rva_to_ptr(const PeInfo* pe, DWORD rva, size_t need)
{
    if (pe == NULL || rva == 0) {
        return NULL;
    }
    if (!pe_in_bounds(pe, rva, need)) {
        return NULL;
    }
    return (const unsigned char*)pe->data + rva;
}

/* 取可写基址（调用者已保证缓冲区可写） */
static unsigned char* pe_writable_base(PeInfo* pe)
{
    /* 刻意舍弃 const：修正/剥离操作需写入调用者提供的可写缓冲区 */
    return (unsigned char*)pe->data;
}

/* ------------------------------------------------------------------ */
/* pe_parse - 解析 PE 镜像                                            */
/* ------------------------------------------------------------------ */
int pe_parse(const void* data, size_t size, PeInfo* out)
{
    const IMAGE_DOS_HEADER* dos;
    DWORD lfanew;
    const IMAGE_NT_HEADERS32* nt32;
    WORD opt_magic;
    WORD opt_size;
    DWORD num_rva;
    size_t nt_off;
    size_t opt_off;
    size_t dir_off;
    size_t need;

    if (data == NULL || out == NULL || size == 0) {
        return PE_ERR_INVALID_ARG;
    }

    /* 清零输出，便于失败时也处于确定状态 */
    {
        size_t i;
        unsigned char* p = (unsigned char*)out;
        for (i = 0; i < sizeof(*out); ++i) {
            p[i] = 0;
        }
    }
    out->data = data;
    out->size = size;

    /* 1) DOS 头与 MZ 签名 */
    if (!pe_in_bounds(out, 0, sizeof(IMAGE_DOS_HEADER))) {
        return PE_ERR_TRUNCATED;
    }
    dos = (const IMAGE_DOS_HEADER*)data;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        return PE_ERR_BAD_DOS;
    }
    out->dos = dos;

    /* 2) 定位 NT 头 */
    lfanew = dos->e_lfanew;
    if (lfanew == 0 || !pe_in_bounds(out, lfanew, sizeof(DWORD))) {
        return PE_ERR_TRUNCATED;
    }
    nt_off = lfanew;
    if (*(const DWORD*)((const unsigned char*)data + nt_off) != IMAGE_NT_SIGNATURE) {
        return PE_ERR_BAD_PE;
    }

    /* 至少需要 Signature + FileHeader 才能读取可选头大小 */
    if (!pe_in_bounds(out, nt_off, sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER))) {
        return PE_ERR_TRUNCATED;
    }
    nt32 = (const IMAGE_NT_HEADERS32*)((const unsigned char*)data + nt_off);
    opt_size = nt32->FileHeader.SizeOfOptionalHeader;   /* 直接成员访问，不取址 */
    opt_off = nt_off + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER);
    /* OptionalHeader Magic 决定 PE32 / PE32+ */
    if (!pe_in_bounds(out, opt_off, sizeof(WORD))) {
        return PE_ERR_TRUNCATED;
    }
    opt_magic = *(const WORD*)((const unsigned char*)data + opt_off);
    out->optional = (const void*)((const unsigned char*)data + opt_off);

    /* 3) 判定 PE32 / PE32+ 并校验可选头完整性 */
    if (opt_magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        out->is64 = 0;
        out->nt32 = nt32;
        out->nt64 = NULL;
        need = sizeof(IMAGE_OPTIONAL_HEADER32);
        if (opt_size < need || !pe_in_bounds(out, opt_off, need)) {
            return PE_ERR_TRUNCATED;
        }
        dir_off = opt_off + offsetof(IMAGE_OPTIONAL_HEADER32, DataDirectory);
        num_rva = ((const IMAGE_OPTIONAL_HEADER32*)out->optional)->NumberOfRvaAndSizes;
        out->data_dir = (IMAGE_DATA_DIRECTORY*)((unsigned char*)data + dir_off);
        /* 子系统版本字段地址（用 offsetof 避免对 packed 成员取址） */
        out->major_subsystem = (WORD*)((unsigned char*)out->optional +
            offsetof(IMAGE_OPTIONAL_HEADER32, MajorSubsystemVersion));
        out->minor_subsystem = (WORD*)((unsigned char*)out->optional +
            offsetof(IMAGE_OPTIONAL_HEADER32, MinorSubsystemVersion));
        out->major_os = (WORD*)((unsigned char*)out->optional +
            offsetof(IMAGE_OPTIONAL_HEADER32, MajorOperatingSystemVersion));
        out->minor_os = (WORD*)((unsigned char*)out->optional +
            offsetof(IMAGE_OPTIONAL_HEADER32, MinorOperatingSystemVersion));
    } else if (opt_magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        out->is64 = 1;
        out->nt64 = (const IMAGE_NT_HEADERS64*)nt32;
        out->nt32 = NULL;
        need = sizeof(IMAGE_OPTIONAL_HEADER64);
        if (opt_size < need || !pe_in_bounds(out, opt_off, need)) {
            return PE_ERR_TRUNCATED;
        }
        dir_off = opt_off + offsetof(IMAGE_OPTIONAL_HEADER64, DataDirectory);
        num_rva = ((const IMAGE_OPTIONAL_HEADER64*)out->optional)->NumberOfRvaAndSizes;
        out->data_dir = (IMAGE_DATA_DIRECTORY*)((unsigned char*)data + dir_off);
        out->major_subsystem = (WORD*)((unsigned char*)out->optional +
            offsetof(IMAGE_OPTIONAL_HEADER64, MajorSubsystemVersion));
        out->minor_subsystem = (WORD*)((unsigned char*)out->optional +
            offsetof(IMAGE_OPTIONAL_HEADER64, MinorSubsystemVersion));
        out->major_os = (WORD*)((unsigned char*)out->optional +
            offsetof(IMAGE_OPTIONAL_HEADER64, MajorOperatingSystemVersion));
        out->minor_os = (WORD*)((unsigned char*)out->optional +
            offsetof(IMAGE_OPTIONAL_HEADER64, MinorOperatingSystemVersion));
    } else {
        return PE_ERR_BAD_OPTIONAL;
    }

    /* NumberOfRvaAndSizes 上限为 16，防止越界读 DataDirectory */
    if (num_rva > IMAGE_NUMBEROF_DIRECTORY_ENTRIES) {
        num_rva = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
    }

    /* 4) 定位常用数据目录（仅当目录存在且 RVA 有效） */
    if (num_rva > IMAGE_DIRECTORY_ENTRY_IMPORT) {
        DWORD va = out->data_dir[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
        DWORD sz = out->data_dir[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
        if (va != 0 && sz >= sizeof(IMAGE_IMPORT_DESCRIPTOR) &&
            pe_in_bounds(out, va, sizeof(IMAGE_IMPORT_DESCRIPTOR))) {
            out->import_dir = (IMAGE_IMPORT_DESCRIPTOR*)
                (pe_writable_base(out) + va);
        }
    }

    if (num_rva > IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT) {
        DWORD va = out->data_dir[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].VirtualAddress;
        DWORD sz = out->data_dir[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].Size;
        if (va != 0 && sz >= sizeof(IMAGE_BOUND_IMPORT_DESCRIPTOR) &&
            pe_in_bounds(out, va, sizeof(IMAGE_BOUND_IMPORT_DESCRIPTOR))) {
            out->bound_import_dir = (IMAGE_BOUND_IMPORT_DESCRIPTOR*)
                (pe_writable_base(out) + va);
        }
    }

    if (num_rva > IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT) {
        DWORD va = out->data_dir[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].VirtualAddress;
        DWORD sz = out->data_dir[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].Size;
        if (va != 0 && sz >= sizeof(IMAGE_DELAYLOAD_DESCRIPTOR) &&
            pe_in_bounds(out, va, sizeof(IMAGE_DELAYLOAD_DESCRIPTOR))) {
            out->delay_import_dir = (IMAGE_DELAYLOAD_DESCRIPTOR*)
                (pe_writable_base(out) + va);
        }
    }

    if (num_rva > IMAGE_DIRECTORY_ENTRY_EXPORT) {
        DWORD va = out->data_dir[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        DWORD sz = out->data_dir[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
        if (va != 0 && sz >= sizeof(IMAGE_EXPORT_DIRECTORY) &&
            pe_in_bounds(out, va, sizeof(IMAGE_EXPORT_DIRECTORY))) {
            out->export_dir = (IMAGE_EXPORT_DIRECTORY*)
                (pe_writable_base(out) + va);
        }
    }

    return PE_OK;
}

/* ------------------------------------------------------------------ */
/* pe_get_subsystem_version - 读取子系统版本                          */
/* ------------------------------------------------------------------ */
int pe_get_subsystem_version(const PeInfo* pe, WORD* major, WORD* minor)
{
    if (pe == NULL || major == NULL || minor == NULL) {
        if (major) *major = 0;
        if (minor) *minor = 0;
        return PE_ERR_INVALID_ARG;
    }
    if (pe->major_subsystem == NULL || pe->minor_subsystem == NULL) {
        *major = 0;
        *minor = 0;
        return PE_ERR_BAD_OPTIONAL;
    }
    *major = *pe->major_subsystem;
    *minor = *pe->minor_subsystem;
    return PE_OK;
}

/* ------------------------------------------------------------------ */
/* pe_fix_subsystem - 修正子系统/OS 版本至 Win7 (6.1)                 */
/* ------------------------------------------------------------------ */
int pe_fix_subsystem(PeInfo* pe)
{
    int changed = 0;
    WORD wmajor, wminor, omajor, ominor;

    if (pe == NULL || pe->major_subsystem == NULL || pe->major_os == NULL) {
        return PE_ERR_INVALID_ARG;
    }

    wmajor = *pe->major_subsystem;
    wminor = *pe->minor_subsystem;
    omajor = *pe->major_os;
    ominor = *pe->minor_os;

    /* 需要修正：主版本 > 6，或 主版本==6 且 次版本 > 1 */
    if (wmajor > WIN7_SUBSYSTEM_MAJOR ||
        (wmajor == WIN7_SUBSYSTEM_MAJOR && wminor > WIN7_SUBSYSTEM_MINOR)) {
        *pe->major_subsystem = WIN7_SUBSYSTEM_MAJOR;
        *pe->minor_subsystem = WIN7_SUBSYSTEM_MINOR;
        changed = 1;
    }

    if (omajor > WIN7_SUBSYSTEM_MAJOR ||
        (omajor == WIN7_SUBSYSTEM_MAJOR && ominor > WIN7_SUBSYSTEM_MINOR)) {
        *pe->major_os = WIN7_SUBSYSTEM_MAJOR;
        *pe->minor_os = WIN7_SUBSYSTEM_MINOR;
        changed = 1;
    }

    return changed;
}

/* ------------------------------------------------------------------ */
/* pe_strip_bound_imports - 剥离绑定导入                              */
/* ------------------------------------------------------------------ */
int pe_strip_bound_imports(PeInfo* pe)
{
    IMAGE_DATA_DIRECTORY* dir;
    DWORD dir_va, dir_sz;
    IMAGE_BOUND_IMPORT_DESCRIPTOR* desc;
    size_t off;
    int count = 0;

    if (pe == NULL || pe->data_dir == NULL) {
        return PE_ERR_INVALID_ARG;
    }

    dir = &pe->data_dir[IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT];
    dir_va = dir->VirtualAddress;
    dir_sz = dir->Size;
    if (dir_va == 0 || dir_sz == 0) {
        return 0;  /* 无绑定导入表，无需处理 */
    }

    /* 遍历描述符数组，遇全零终止项停止 */
    off = 0;
    while (off + sizeof(IMAGE_BOUND_IMPORT_DESCRIPTOR) <= dir_sz) {
        size_t abs_off = dir_va + off;
        if (!pe_in_bounds(pe, abs_off, sizeof(IMAGE_BOUND_IMPORT_DESCRIPTOR))) {
            break;
        }
        desc = (IMAGE_BOUND_IMPORT_DESCRIPTOR*)
            (pe_writable_base(pe) + abs_off);

        /* 终止项：三个字段全为 0 */
        if (desc->TimeDateStamp == 0 &&
            desc->OffsetModuleName == 0 &&
            desc->NumberOfModuleForwarderRefs == 0) {
            break;
        }

        /* 置零 TimeDateStamp，强制加载器重新解析 IAT */
        desc->TimeDateStamp = 0;
        ++count;

        /* 跳过当前描述符后跟随的转发引用（每个 8 字节） */
        off += sizeof(IMAGE_BOUND_IMPORT_DESCRIPTOR) +
               (size_t)desc->NumberOfModuleForwarderRefs *
                   sizeof(IMAGE_BOUND_FORWARDER_REF);
    }

    return count;
}

/* ------------------------------------------------------------------ */
/* pe_dump_imports - 打印导入表（调试用）                             */
/* ------------------------------------------------------------------ */
void pe_dump_imports(const PeInfo* pe)
{
    IMAGE_DATA_DIRECTORY* dir;
    DWORD dir_va, dir_sz;
    size_t off;
    size_t thunk_size;

    if (pe == NULL || pe->data_dir == NULL) {
        return;
    }

    dir = &pe->data_dir[IMAGE_DIRECTORY_ENTRY_IMPORT];
    dir_va = dir->VirtualAddress;
    dir_sz = dir->Size;
    if (dir_va == 0 || dir_sz == 0) {
        printf("[pe] 无导入表\n");
        return;
    }

    thunk_size = pe->is64 ? sizeof(QWORD) : sizeof(DWORD);
    printf("[pe] 导入表 @ RVA 0x%08X, Size 0x%X (%s)\n",
           dir_va, dir_sz, pe->is64 ? "PE32+" : "PE32");

    off = 0;
    while (off + sizeof(IMAGE_IMPORT_DESCRIPTOR) <= dir_sz) {
        const IMAGE_IMPORT_DESCRIPTOR* d;
        const char* dll_name;
        DWORD thunk_rva;
        size_t thunk_off;
        size_t abs_off = dir_va + off;

        if (!pe_in_bounds(pe, abs_off, sizeof(IMAGE_IMPORT_DESCRIPTOR))) {
            break;
        }
        d = (const IMAGE_IMPORT_DESCRIPTOR*)
            ((const unsigned char*)pe->data + abs_off);

        /* 终止项 */
        if (d->Name == 0 && d->OriginalFirstThunk == 0 && d->FirstThunk == 0) {
            break;
        }

        dll_name = (const char*)pe_rva_to_ptr(pe, d->Name, 1);
        printf("[pe]   DLL: %s (OFT=0x%X FT=0x%X)\n",
               dll_name ? dll_name : "<bad rva>",
               d->OriginalFirstThunk, d->FirstThunk);

        /* 优先使用 OriginalFirstThunk(ILT)，缺失时回退 FirstThunk(IAT) */
        thunk_rva = d->OriginalFirstThunk ? d->OriginalFirstThunk : d->FirstThunk;
        if (thunk_rva == 0) {
            off += sizeof(IMAGE_IMPORT_DESCRIPTOR);
            continue;
        }

        thunk_off = 0;
        for (;;) {
            const void* tp;
            QWORD tv = 0;
            size_t abs_t = (size_t)thunk_rva + thunk_off;

            if (!pe_in_bounds(pe, abs_t, thunk_size)) {
                break;
            }
            tp = (const unsigned char*)pe->data + abs_t;
            if (pe->is64) {
                tv = *(const QWORD*)tp;
            } else {
                tv = *(const DWORD*)tp;
            }
            if (tv == 0) {
                break;  /* thunks 数组终止 */
            }

            if (pe->is64 && (tv & 0x8000000000000000ULL)) {
                /* 按序号导入 */
                printf("[pe]     <ordinal %llu>\n",
                       (unsigned long long)(tv & 0xFFFF));
            } else if (!pe->is64 && (tv & 0x80000000UL)) {
                printf("[pe]     <ordinal %u>\n",
                       (unsigned)(tv & 0xFFFF));
            } else {
                /* 按名导入：低 31/63 位为 IMAGE_IMPORT_BY_NAME 的 RVA */
                DWORD name_rva = (DWORD)(tv & (pe->is64 ? 0x7FFFFFFFFFFFFFFFULL
                                                        : 0x7FFFFFFFUL));
                const IMAGE_IMPORT_BY_NAME* ibn =
                    (const IMAGE_IMPORT_BY_NAME*)pe_rva_to_ptr(pe, name_rva, 2);
                if (ibn != NULL) {
                    printf("[pe]     %s (hint=%u)\n",
                           (const char*)ibn->Name, (unsigned)ibn->Hint);
                } else {
                    printf("[pe]     <bad name rva 0x%X>\n", name_rva);
                }
            }

            thunk_off += thunk_size;
        }

        off += sizeof(IMAGE_IMPORT_DESCRIPTOR);
    }
}
