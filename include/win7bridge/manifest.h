/*
 * manifest.h - Win7Bridge PE manifest 改写接口
 *
 * 提供 Win10 PE manifest 的兼容性改写能力：
 *   - 在 compatibility/application 节点内注入 Win7 supportedOS GUID
 *   - 剥离 Win10-only 元素（maxversiontested、msix 等）
 *   - 从 PE 资源目录定位 RT_MANIFEST 并提取 manifest XML
 *
 * 约定：xml 缓冲区为 NUL 结尾的文本，xml_size 为有效字节数（不含 NUL），
 * xml_capacity 为缓冲区总容量且必须 >= xml_size + 1，以容纳末尾 NUL。
 * 所有改写函数维护 NUL 结尾，并通过 out_new_size 回写新的有效长度。
 *
 * 资源目录遍历基于"按镜像映射"模型：RVA 直接当作相对缓冲区起点的偏移，
 * 与 pe.c / pe.h 一致。
 */
#ifndef WIN7BRIDGE_MANIFEST_H
#define WIN7BRIDGE_MANIFEST_H

#include <stddef.h>
#include "win7bridge/pe_types.h"
#include "win7bridge/pe.h"

#ifdef __cplusplus
extern "C" {
#endif

/* supportedOS GUID 常量（带花括号）                                    */
#define WIN7_SUPPORTEDOS_GUID  "{35138b9a-5d96-4fbd-8e2d-a2440225f93a}"
#define WIN10_SUPPORTEDOS_GUID "{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}"

/* RT_MANIFEST 资源类型（标准值 24）                                    */
#define RT_MANIFEST 24

/* 返回码                                                                */
#define MANIFEST_OK               0
#define MANIFEST_ERR_INVALID_ARG (-1)  /* 入参非法                       */
#define MANIFEST_ERR_NO_ROOM     (-2)  /* 缓冲区容量不足                  */
#define MANIFEST_ERR_NOT_FOUND   (-3)  /* 未找到 manifest 资源            */
#define MANIFEST_ERR_BAD_PE      (-4)  /* PE 解析/资源目录异常            */

/*
 * manifest_inject_win7_guid - 在 compatibility/application 节点内注入
 *   Win7 supportedOS Id。若 manifest 已含 Win7 GUID 则跳过（不重复注入）。
 *   无 <compatibility> 块时，在 </assembly> 前追加一个最小 compatibility 块。
 *   xml         ：NUL 结尾的 manifest XML，可写
 *   xml_size    ：xml 有效字节数（不含 NUL）
 *   xml_capacity：缓冲区总容量
 *   out_new_size：写出新的有效字节数（不含 NUL）
 * 返回：1=已注入；0=无需注入（已含 Win7 GUID）；<0=出错（见 MANIFEST_ERR_*）。
 */
int manifest_inject_win7_guid(char* xml, size_t xml_size, size_t xml_capacity,
                              size_t* out_new_size);

/*
 * manifest_strip_win10_only - 剥离 <maxversiontested>、<msix> 等 Win10-only
 *   元素（含自闭合 <.../> 与配对 <tag>...</tag> 形式）。采用简单字符串匹配，
 *   非完整 XML 解析。
 * 返回：>=0=已剥离的元素个数；<0=出错。
 */
int manifest_strip_win10_only(char* xml, size_t xml_size, size_t xml_capacity,
                              size_t* out_new_size);

/*
 * manifest_get_from_pe - 从 PE 资源目录（IMAGE_DIRECTORY_ENTRY_RESOURCE）
 *   定位 RT_MANIFEST（类型 24），遍历"类型 -> 名称/ID -> 语言"三层目录树，
 *   取首个语言条目指向的数据，拷贝 manifest XML 至 out_buf。
 *   pe          ：已由 pe_parse 解析的 PE 信息
 *   out_buf     ：输出缓冲区
 *   buf_capacity：缓冲区容量（需 >= manifest_size + 1 以容纳 NUL）
 *   out_size    ：写出 manifest 字节数（不含末尾 NUL）
 * 返回：MANIFEST_OK 成功；负值见 MANIFEST_ERR_*。
 */
int manifest_get_from_pe(const PeInfo* pe, char* out_buf, size_t buf_capacity,
                         size_t* out_size);

#ifdef __cplusplus
}
#endif

#endif /* WIN7BRIDGE_MANIFEST_H */
