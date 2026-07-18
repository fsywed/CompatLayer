/*
 * pe.h - Win7Bridge L0 PE 解析与修正器接口
 *
 * 提供对已映射到内存的 PE 镜像的纯用户态解析与修正能力：
 *   - 验证 MZ/PE 签名、判定 PE32/PE32+
 *   - 修正 MajorSubsystemVersion / MajorOperatingSystemVersion > 6.1 为 6.1
 *   - 剥离 bound import（TimeDateStamp 置 0）强制 IAT 重新解析
 *   - 调试打印导入表
 *
 * 约定：传入的 PE 数据必须是"按镜像映射"的缓冲区（RVA 可直接当作相对
 * 缓冲区起点的偏移使用）。调用者需保证缓冲区可写（Windows 下可用
 * WriteProcessMemory 或映射文件；host 测试用 malloc 内存）。
 */
#ifndef WIN7BRIDGE_PE_H
#define WIN7BRIDGE_PE_H

#include <stddef.h>
#include "win7bridge/pe_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* 返回码                                                              */
#define PE_OK                 0   /* 成功                               */
#define PE_ERR_INVALID_ARG   (-1) /* 入参非法                            */
#define PE_ERR_BAD_DOS       (-2) /* MZ 签名校验失败                    */
#define PE_ERR_BAD_PE        (-3) /* PE 签名校验失败                    */
#define PE_ERR_TRUNCATED     (-4) /* 数据截断/越界                      */
#define PE_ERR_BAD_OPTIONAL  (-5) /* OptionalHeader Magic 未知          */

/*
 * PeInfo - PE 解析结果句柄
 *
 * 持有映射数据指针与各关键结构指针。所有指针指向调用者传入的缓冲区，
 * 因此 PeInfo 的生命周期不得超过该缓冲区。
 */
typedef struct _PeInfo {
    const void*  data;          /* 镜像数据起点                         */
    size_t       size;          /* 镜像数据字节数                       */
    int          is64;          /* 非 0 表示 PE32+，0 表示 PE32          */

    const IMAGE_DOS_HEADER*      dos;           /* DOS 头              */
    const IMAGE_NT_HEADERS32*    nt32;          /* NT 头（PE32）       */
    const IMAGE_NT_HEADERS64*    nt64;          /* NT 头（PE32+）      */
    const void*                  optional;      /* OptionalHeader 起点 */
    IMAGE_DATA_DIRECTORY*        data_dir;      /* 数据目录数组        */

    /* 常用目录指针（无对应目录时为 NULL）                              */
    IMAGE_IMPORT_DESCRIPTOR*         import_dir;       /* 导入表        */
    IMAGE_BOUND_IMPORT_DESCRIPTOR*   bound_import_dir; /* 绑定导入表    */
    IMAGE_DELAYLOAD_DESCRIPTOR*      delay_import_dir; /* 延迟导入表    */
    IMAGE_EXPORT_DIRECTORY*          export_dir;       /* 导出表        */

    /* 子系统版本字段的可写指针，便于修正                               */
    WORD* major_subsystem;       /* -> MajorSubsystemVersion             */
    WORD* minor_subsystem;       /* -> MinorSubsystemVersion             */
    WORD* major_os;              /* -> MajorOperatingSystemVersion       */
    WORD* minor_os;              /* -> MinorOperatingSystemVersion       */
} PeInfo;

/*
 * pe_parse - 解析 PE 镜像
 *   data/size：已映射镜像缓冲区
 *   out      ：解析结果（调用者分配）
 * 返回：PE_OK 成功；负值见 PE_ERR_*
 */
int pe_parse(const void* data, size_t size, PeInfo* out);

/*
 * pe_fix_subsystem - 修正子系统版本
 *   当 MajorSubsystemVersion > 6，或 ==6 且 MinorSubsystemVersion > 1 时，
 *   改为 6.1；MajorOperatingSystemVersion 同理。
 * 返回：>0 表示已修改；0 表示无需修改；<0 表示出错。
 */
int pe_fix_subsystem(PeInfo* pe);

/*
 * pe_strip_bound_imports - 剥离绑定导入
 *   遍历 bound import directory，把每个 IMAGE_BOUND_IMPORT_DESCRIPTOR 的
 *   TimeDateStamp 置 0，强制加载器重新解析 IAT。
 * 返回：>=0 表示已置零的描述符个数；<0 表示出错。
 */
int pe_strip_bound_imports(PeInfo* pe);

/*
 * pe_dump_imports - 打印导入的 DLL 与函数（调试用）
 */
void pe_dump_imports(const PeInfo* pe);

/*
 * pe_get_subsystem_version - 读取子系统版本
 *   major/minor 不可为 NULL。失败时两者置 0。
 * 返回：PE_OK 成功；负值出错。
 */
int pe_get_subsystem_version(const PeInfo* pe, WORD* major, WORD* minor);

#ifdef __cplusplus
}
#endif

#endif /* WIN7BRIDGE_PE_H */
