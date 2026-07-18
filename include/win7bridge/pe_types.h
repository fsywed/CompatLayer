/*
 * pe_types.h - Win7Bridge PE 类型定义
 *
 * 本头文件不依赖 <windows.h>/<winnt.h>，仅用 <stdint.h> 自定义 Windows
 * 常用基本类型与 PE 镜像结构体。这样 PE 解析逻辑（纯数据结构操作）可
 * 用原生 gcc 编译为 host 测试程序验证，最终目标仍是 MinGW-w64 + Windows。
 *
 * 结构体布局严格按 1 字节对齐，与磁盘/内存中的 PE 镜像布局一致。
 */
#ifndef WIN7BRIDGE_PE_TYPES_H
#define WIN7BRIDGE_PE_TYPES_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------ */
/* 基本标量类型（对标 Windows SDK 的同名类型）                        */
/* ------------------------------------------------------------------ */
typedef uint8_t   BYTE;
typedef uint16_t  WORD;
typedef uint32_t  DWORD;
typedef uint64_t  QWORD;
typedef void      VOID;
typedef void*     PVOID;
typedef BYTE*     LPBYTE;
typedef char*     LPSTR;
typedef const char* LPCSTR;
typedef uint32_t* LPDWORD;
typedef void*     HANDLE;

#ifndef NULL
#define NULL ((void*)0)
#endif

/* PE 镜像相关常量                                                     */
#define IMAGE_DOS_SIGNATURE     0x5A4D      /* "MZ"                       */
#define IMAGE_OS2_SIGNATURE     0x454E      /* "NE"                       */
#define IMAGE_NT_SIGNATURE      0x00004550  /* "PE\0\0"                   */
#define IMAGE_NT_OPTIONAL_HDR32_MAGIC 0x10B /* PE32                       */
#define IMAGE_NT_OPTIONAL_HDR64_MAGIC 0x20B /* PE32+                      */

#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES 16 /* 数据目录条目数              */
#define IMAGE_SIZEOF_SHORT_NAME        8    /* 节名长度                    */
#define IMAGE_SIZEOF_SECTION_HEADER    40   /* 节头大小                    */
#define IMAGE_SIZEOF_FILE_HEADER       20   /* 文件头大小                  */

/* 数据目录索引                                                        */
#define IMAGE_DIRECTORY_ENTRY_EXPORT      0   /* 导出表                    */
#define IMAGE_DIRECTORY_ENTRY_IMPORT      1   /* 导入表                    */
#define IMAGE_DIRECTORY_ENTRY_RESOURCE    2   /* 资源表                    */
#define IMAGE_DIRECTORY_ENTRY_EXCEPTION   3
#define IMAGE_DIRECTORY_ENTRY_SECURITY    4
#define IMAGE_DIRECTORY_ENTRY_BASERELOC   5
#define IMAGE_DIRECTORY_ENTRY_DEBUG       6
#define IMAGE_DIRECTORY_ENTRY_ARCHITECTURE 7
#define IMAGE_DIRECTORY_ENTRY_GLOBALPTR   8
#define IMAGE_DIRECTORY_ENTRY_TLS         9
#define IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG 10
#define IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT 11 /* 绑定导入表                */
#define IMAGE_DIRECTORY_ENTRY_IAT         12
#define IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT 13 /* 延迟导入表                */
#define IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR 14

/* Win7 SP1 目标子系统版本：6.1                                       */
#define WIN7_SUBSYSTEM_MAJOR 6
#define WIN7_SUBSYSTEM_MINOR 1

/* ------------------------------------------------------------------ */
/* PE 结构体定义（1 字节对齐，与镜像布局一致）                          */
/* ------------------------------------------------------------------ */
#pragma pack(push, 1)

/* MS-DOS 头（64 字节）                                                */
typedef struct _IMAGE_DOS_HEADER {
    WORD  e_magic;        /* "MZ"                                     */
    WORD  e_cblp;
    WORD  e_cp;
    WORD  e_crlc;
    WORD  e_cparhdr;
    WORD  e_minalloc;
    WORD  e_maxalloc;
    WORD  e_ss;
    WORD  e_sp;
    WORD  e_csum;
    WORD  e_ip;
    WORD  e_cs;
    WORD  e_lfarlc;
    WORD  e_ovno;
    WORD  e_res[4];
    WORD  e_oemid;
    WORD  e_oeminfo;
    WORD  e_res2[10];
    DWORD e_lfanew;       /* PE 头相对偏移                             */
} IMAGE_DOS_HEADER;

/* COFF 文件头（20 字节）                                              */
typedef struct _IMAGE_FILE_HEADER {
    WORD  Machine;
    WORD  NumberOfSections;
    DWORD TimeDateStamp;
    DWORD PointerToSymbolTable;
    DWORD NumberOfSymbols;
    WORD  SizeOfOptionalHeader;
    WORD  Characteristics;
} IMAGE_FILE_HEADER;

/* 数据目录条目（8 字节）                                              */
typedef struct _IMAGE_DATA_DIRECTORY {
    DWORD VirtualAddress; /* RVA                                       */
    DWORD Size;
} IMAGE_DATA_DIRECTORY;

/* PE32 可选头                                                         */
typedef struct _IMAGE_OPTIONAL_HEADER32 {
    WORD  Magic;                       /* 0x10B                        */
    BYTE  MajorLinkerVersion;
    BYTE  MinorLinkerVersion;
    DWORD SizeOfCode;
    DWORD SizeOfInitializedData;
    DWORD SizeOfUninitializedData;
    DWORD AddressOfEntryPoint;
    DWORD BaseOfCode;
    DWORD BaseOfData;                  /* PE32 独有                    */
    DWORD ImageBase;
    DWORD SectionAlignment;
    DWORD FileAlignment;
    WORD  MajorOperatingSystemVersion;
    WORD  MinorOperatingSystemVersion;
    WORD  MajorSubsystemVersion;
    WORD  MinorSubsystemVersion;
    DWORD Win32VersionValue;
    DWORD SizeOfImage;
    DWORD SizeOfHeaders;
    DWORD CheckSum;
    WORD  Subsystem;
    WORD  DllCharacteristics;
    DWORD SizeOfStackReserve;
    DWORD SizeOfStackCommit;
    DWORD SizeOfHeapReserve;
    DWORD SizeOfHeapCommit;
    DWORD LoaderFlags;
    DWORD NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER32;

/* PE32+ 可选头                                                        */
typedef struct _IMAGE_OPTIONAL_HEADER64 {
    WORD  Magic;                       /* 0x20B                        */
    BYTE  MajorLinkerVersion;
    BYTE  MinorLinkerVersion;
    DWORD SizeOfCode;
    DWORD SizeOfInitializedData;
    DWORD SizeOfUninitializedData;
    DWORD AddressOfEntryPoint;
    DWORD BaseOfCode;
    /* 无 BaseOfData                                                   */
    QWORD ImageBase;
    DWORD SectionAlignment;
    DWORD FileAlignment;
    WORD  MajorOperatingSystemVersion;
    WORD  MinorOperatingSystemVersion;
    WORD  MajorSubsystemVersion;
    WORD  MinorSubsystemVersion;
    DWORD Win32VersionValue;
    DWORD SizeOfImage;
    DWORD SizeOfHeaders;
    DWORD CheckSum;
    WORD  Subsystem;
    WORD  DllCharacteristics;
    QWORD SizeOfStackReserve;
    QWORD SizeOfStackCommit;
    QWORD SizeOfHeapReserve;
    QWORD SizeOfHeapCommit;
    DWORD LoaderFlags;
    DWORD NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER64;

/* NT 头（PE32）                                                       */
typedef struct _IMAGE_NT_HEADERS32 {
    DWORD                   Signature;   /* "PE\0\0"                  */
    IMAGE_FILE_HEADER       FileHeader;
    IMAGE_OPTIONAL_HEADER32 OptionalHeader;
} IMAGE_NT_HEADERS32;

/* NT 头（PE32+）                                                      */
typedef struct _IMAGE_NT_HEADERS64 {
    DWORD                   Signature;
    IMAGE_FILE_HEADER       FileHeader;
    IMAGE_OPTIONAL_HEADER64 OptionalHeader;
} IMAGE_NT_HEADERS64;

/* 节头（40 字节）                                                     */
typedef struct _IMAGE_SECTION_HEADER {
    BYTE  Name[IMAGE_SIZEOF_SHORT_NAME];
    union {
        DWORD PhysicalAddress;
        DWORD VirtualSize;
    } Misc;
    DWORD VirtualAddress;
    DWORD SizeOfRawData;
    DWORD PointerToRawData;
    DWORD PointerToRelocations;
    DWORD PointerToLinenumbers;
    WORD  NumberOfRelocations;
    WORD  NumberOfLinenumbers;
    DWORD Characteristics;
} IMAGE_SECTION_HEADER;

/* 导入描述符（20 字节）                                               */
typedef struct _IMAGE_IMPORT_DESCRIPTOR {
    DWORD OriginalFirstThunk; /* RVA -> ILT                            */
    DWORD TimeDateStamp;
    DWORD ForwarderChain;
    DWORD Name;               /* RVA -> DLL 名                          */
    DWORD FirstThunk;         /* RVA -> IAT                             */
} IMAGE_IMPORT_DESCRIPTOR;

/* 绑定导入描述符（8 字节）                                            */
typedef struct _IMAGE_BOUND_IMPORT_DESCRIPTOR {
    DWORD TimeDateStamp;
    WORD  OffsetModuleName;        /* 相对绑定导入表的偏移             */
    WORD  NumberOfModuleForwarderRefs;
} IMAGE_BOUND_IMPORT_DESCRIPTOR;

/* 绑定导入转发引用（8 字节）                                          */
typedef struct _IMAGE_BOUND_FORWARDER_REF {
    DWORD TimeDateStamp;
    WORD  OffsetModuleName;
    WORD  Reserved;
} IMAGE_BOUND_FORWARDER_REF;

/* 延迟导入描述符（32 字节）                                           */
typedef struct _IMAGE_DELAYLOAD_DESCRIPTOR {
    DWORD Attributes;
    DWORD DllNameRVA;
    DWORD ModuleHandleRVA;
    DWORD ImportAddressTableRVA;
    DWORD ImportNameTableRVA;
    DWORD BoundImportAddressTableRVA;
    DWORD UnloadInformationTableRVA;
    DWORD TimeDateStamp;
} IMAGE_DELAYLOAD_DESCRIPTOR;

/* 导出目录（40 字节）                                                 */
typedef struct _IMAGE_EXPORT_DIRECTORY {
    DWORD Characteristics;
    DWORD TimeDateStamp;
    WORD  MajorVersion;
    WORD  MinorVersion;
    DWORD Name;
    DWORD Base;
    DWORD NumberOfFunctions;
    DWORD NumberOfNames;
    DWORD AddressOfFunctions;
    DWORD AddressOfNames;
    DWORD AddressOfNameOrdinals;
} IMAGE_EXPORT_DIRECTORY;

/* 导入名结构（按名导入时由 ILT/IAT 指向）                            */
typedef struct _IMAGE_IMPORT_BY_NAME {
    WORD  Hint;
    BYTE  Name[1];   /* 变长，以 NUL 结尾                              */
} IMAGE_IMPORT_BY_NAME;

#pragma pack(pop)

/* ------------------------------------------------------------------ */
/* 编译期尺寸校验（确保布局与镜像一致）                                */
/* ------------------------------------------------------------------ */
#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
_Static_assert(sizeof(IMAGE_DOS_HEADER) == 64,
               "IMAGE_DOS_HEADER 必须 64 字节");
_Static_assert(sizeof(IMAGE_FILE_HEADER) == IMAGE_SIZEOF_FILE_HEADER,
               "IMAGE_FILE_HEADER 必须 20 字节");
_Static_assert(sizeof(IMAGE_DATA_DIRECTORY) == 8,
               "IMAGE_DATA_DIRECTORY 必须 8 字节");
_Static_assert(sizeof(IMAGE_IMPORT_DESCRIPTOR) == 20,
               "IMAGE_IMPORT_DESCRIPTOR 必须 20 字节");
_Static_assert(sizeof(IMAGE_BOUND_IMPORT_DESCRIPTOR) == 8,
               "IMAGE_BOUND_IMPORT_DESCRIPTOR 必须 8 字节");
_Static_assert(sizeof(IMAGE_BOUND_FORWARDER_REF) == 8,
               "IMAGE_BOUND_FORWARDER_REF 必须 8 字节");
_Static_assert(sizeof(IMAGE_DELAYLOAD_DESCRIPTOR) == 32,
               "IMAGE_DELAYLOAD_DESCRIPTOR 必须 32 字节");
_Static_assert(sizeof(IMAGE_EXPORT_DIRECTORY) == 40,
               "IMAGE_EXPORT_DIRECTORY 必须 40 字节");
_Static_assert(sizeof(IMAGE_SECTION_HEADER) == IMAGE_SIZEOF_SECTION_HEADER,
               "IMAGE_SECTION_HEADER 必须 40 字节");
#endif

#ifdef __cplusplus
}
#endif

#endif /* WIN7BRIDGE_PE_TYPES_H */
