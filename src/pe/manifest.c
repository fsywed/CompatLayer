/*
 * manifest.c - Win7Bridge PE manifest 改写实现
 *
 * 纯用户态、无 Windows API 依赖。资源目录遍历基于"按镜像映射"模型：
 * RVA 直接当作相对缓冲区起点的偏移使用，与 pe.c 一致。
 *
 * 改写采用简单字符串匹配（非完整 XML 解析），满足 manifest 兼容性改写
 * 的实际需求：manifest XML 结构规整、标签小写，字符串匹配足够可靠。
 */
#include "win7bridge/manifest.h"

#include <string.h>

/* ------------------------------------------------------------------ */
/* 资源目录结构体（1 字节对齐，与镜像布局一致）                        */
/* ------------------------------------------------------------------ */
#pragma pack(push, 1)
typedef struct _MANIFEST_RESOURCE_DIRECTORY {
    DWORD Characteristics;
    DWORD TimeDateStamp;
    WORD  MajorVersion;
    WORD  MinorVersion;
    WORD  NumberOfNamedEntries;  /* 字符串名条目数                       */
    WORD  NumberOfIdEntries;     /* 整数 ID 条目数                       */
} MANIFEST_RESOURCE_DIRECTORY;  /* 16 字节，等价 IMAGE_RESOURCE_DIRECTORY */

typedef struct _MANIFEST_RESOURCE_DIRECTORY_ENTRY {
    DWORD Name;         /* 高位(0x80000000)置 1=字符串名，否则为整数 ID  */
    DWORD OffsetToData; /* 高位置 1=指向子目录，否则指向数据条目         */
} MANIFEST_RESOURCE_DIRECTORY_ENTRY;  /* 8 字节 */

typedef struct _MANIFEST_RESOURCE_DATA_ENTRY {
    DWORD OffsetToData; /* 数据 RVA（相对镜像基址）                      */
    DWORD Size;          /* 数据字节数                                    */
    DWORD CodePage;
    DWORD Reserved;
} MANIFEST_RESOURCE_DATA_ENTRY;  /* 16 字节 */
#pragma pack(pop)

/* 编译期布局校验 */
#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
_Static_assert(sizeof(MANIFEST_RESOURCE_DIRECTORY) == 16,
               "资源目录必须 16 字节");
_Static_assert(sizeof(MANIFEST_RESOURCE_DIRECTORY_ENTRY) == 8,
               "资源目录条目必须 8 字节");
_Static_assert(sizeof(MANIFEST_RESOURCE_DATA_ENTRY) == 16,
               "资源数据条目必须 16 字节");
#endif

/* 子目录/数据条目偏移的高位标志 */
#define MANIFEST_RES_NAME_FLAG    0x80000000UL
#define MANIFEST_RES_SUBDIR_FLAG  0x80000000UL
/* mf_res_pick 的失败哨兵值（合法偏移不可能达到 0xFFFFFFFF） */
#define MANIFEST_RES_INVALID      0xFFFFFFFFUL

/* ------------------------------------------------------------------ */
/* 内部辅助                                                            */
/* ------------------------------------------------------------------ */

/* 边界检查的 RVA -> 只读指针；越界或 RVA==0 返回 NULL */
static const unsigned char* mf_ptr(const PeInfo* pe, DWORD rva, size_t need)
{
    if (pe == NULL || rva == 0) {
        return NULL;
    }
    if ((size_t)rva > pe->size) {
        return NULL;
    }
    if (need > pe->size - (size_t)rva) {
        return NULL;
    }
    return (const unsigned char*)pe->data + rva;
}

/* 大小写不敏感 ASCII 字符比较 */
static int mf_ci_eq(char a, char b)
{
    if (a >= 'A' && a <= 'Z') {
        a = (char)(a + ('a' - 'A'));
    }
    if (b >= 'A' && b <= 'Z') {
        b = (char)(b + ('a' - 'A'));
    }
    return a == b;
}

/*
 * 大小写不敏感子串查找：在 [hay, hay+n) 中查找 NUL 结尾的 needle。
 * 找到返回指向该子串的可写指针，否则 NULL。
 */
static char* mf_ci_memstr(const char* hay, size_t n, const char* needle)
{
    size_t nl = strlen(needle);
    size_t i;
    if (nl == 0 || n < nl) {
        return NULL;
    }
    for (i = 0; i + nl <= n; ++i) {
        size_t j = 0;
        for (; j < nl; ++j) {
            if (!mf_ci_eq(hay[i + j], needle[j])) {
                break;
            }
        }
        if (j == nl) {
            return (char*)(hay + i);
        }
    }
    return NULL;
}

/* 在 buf 的 pos 位置插入 ins（长度 ins_len），维护 *size 与 NUL 结尾 */
static int mf_buf_insert(char* buf, size_t* size, size_t cap,
                         size_t pos, const char* ins, size_t ins_len)
{
    if (pos > *size) {
        return -1;
    }
    /* 需保留 1 字节给末尾 NUL：要求 cap >= *size + ins_len + 1 */
    if (ins_len > cap - *size - 1) {
        return -2;  /* 容量不足 */
    }
    memmove(buf + pos + ins_len, buf + pos, *size - pos);
    memcpy(buf + pos, ins, ins_len);
    *size += ins_len;
    buf[*size] = '\0';
    return 0;
}

/* 删除 [pos, pos+len) 区间，维护 *size 与 NUL 结尾 */
static void mf_buf_erase(char* buf, size_t* size, size_t pos, size_t len)
{
    if (len == 0 || pos > *size) {
        return;
    }
    if (len > *size - pos) {
        len = *size - pos;
    }
    memmove(buf + pos, buf + pos + len, *size - pos - len);
    *size -= len;
    buf[*size] = '\0';
}

/* ------------------------------------------------------------------ */
/* 资源目录遍历                                                        */
/* ------------------------------------------------------------------ */

/*
 * 资源目录单层遍历：在 dir_rva 处的目录中按规则选取一个条目，返回其
 * OffsetToData 原始值（含高位标志）。失败返回 MANIFEST_RES_INVALID。
 *   sel_mode=0：按整数 ID 匹配（Name 高位 0 且低 31 位 == selector）
 *   sel_mode=1：取第一个条目
 */
static DWORD mf_res_pick(const PeInfo* pe, DWORD dir_rva, int sel_mode,
                         DWORD selector)
{
    const MANIFEST_RESOURCE_DIRECTORY* dir;
    const MANIFEST_RESOURCE_DIRECTORY_ENTRY* entries;
    DWORD n;
    DWORD i;

    dir = (const MANIFEST_RESOURCE_DIRECTORY*)mf_ptr(pe, dir_rva, sizeof(*dir));
    if (dir == NULL) {
        return MANIFEST_RES_INVALID;
    }
    /* 两类条目数之和，上限为两个 WORD 之和（<= 131070），无溢出风险 */
    n = (DWORD)dir->NumberOfNamedEntries + dir->NumberOfIdEntries;
    if (n == 0) {
        return MANIFEST_RES_INVALID;
    }
    entries = (const MANIFEST_RESOURCE_DIRECTORY_ENTRY*)mf_ptr(
        pe, dir_rva + sizeof(*dir), (size_t)n * sizeof(*entries));
    if (entries == NULL) {
        return MANIFEST_RES_INVALID;
    }

    if (sel_mode == 0) {
        for (i = 0; i < n; ++i) {
            if ((entries[i].Name & MANIFEST_RES_NAME_FLAG) == 0 &&
                (entries[i].Name & 0x7FFFFFFFUL) == selector) {
                return entries[i].OffsetToData;
            }
        }
        return MANIFEST_RES_INVALID;
    }
    return entries[0].OffsetToData;
}

/*
 * 三层资源目录定位 RT_MANIFEST 数据条目：
 *   类型层(按 ID=type_id) -> 名称/ID层(取首项) -> 语言层(取首项)
 * 类型层与名称层应指向子目录（高位=1），语言层应指向数据条目（高位=0）。
 */
static const MANIFEST_RESOURCE_DATA_ENTRY* mf_res_find(const PeInfo* pe,
                                                       DWORD base_rva,
                                                       DWORD type_id)
{
    DWORD t_off, n_off, l_off;

    /* 第 1 层：类型，按 ID 匹配，应指向子目录 */
    t_off = mf_res_pick(pe, base_rva, 0, type_id);
    if (t_off == MANIFEST_RES_INVALID ||
        (t_off & MANIFEST_RES_SUBDIR_FLAG) == 0) {
        return NULL;
    }
    /* 第 2 层：名称/ID，取第一个条目，应指向子目录 */
    n_off = mf_res_pick(pe, base_rva + (t_off & 0x7FFFFFFFUL), 1, 0);
    if (n_off == MANIFEST_RES_INVALID ||
        (n_off & MANIFEST_RES_SUBDIR_FLAG) == 0) {
        return NULL;
    }
    /* 第 3 层：语言，取第一个条目，应指向数据条目 */
    l_off = mf_res_pick(pe, base_rva + (n_off & 0x7FFFFFFFUL), 1, 0);
    if (l_off == MANIFEST_RES_INVALID ||
        (l_off & MANIFEST_RES_SUBDIR_FLAG) != 0) {
        return NULL;
    }
    return (const MANIFEST_RESOURCE_DATA_ENTRY*)mf_ptr(
        pe, base_rva + (l_off & 0x7FFFFFFFUL),
        sizeof(MANIFEST_RESOURCE_DATA_ENTRY));
}

/* ------------------------------------------------------------------ */
/* manifest_get_from_pe - 从 PE 资源目录提取 manifest XML              */
/* ------------------------------------------------------------------ */
int manifest_get_from_pe(const PeInfo* pe, char* out_buf, size_t buf_capacity,
                         size_t* out_size)
{
    IMAGE_DATA_DIRECTORY* rdir;
    DWORD base_rva;
    const MANIFEST_RESOURCE_DATA_ENTRY* data_entry;
    const unsigned char* data;
    DWORD msize;
    size_t copy;

    if (out_size != NULL) {
        *out_size = 0;
    }
    if (pe == NULL || out_buf == NULL || out_size == NULL) {
        return MANIFEST_ERR_INVALID_ARG;
    }
    if (buf_capacity == 0) {
        return MANIFEST_ERR_INVALID_ARG;
    }
    if (pe->data_dir == NULL) {
        return MANIFEST_ERR_BAD_PE;
    }

    rdir = &pe->data_dir[IMAGE_DIRECTORY_ENTRY_RESOURCE];
    base_rva = rdir->VirtualAddress;
    if (base_rva == 0) {
        return MANIFEST_ERR_NOT_FOUND;
    }

    data_entry = mf_res_find(pe, base_rva, RT_MANIFEST);
    if (data_entry == NULL) {
        return MANIFEST_ERR_NOT_FOUND;
    }
    msize = data_entry->Size;
    if (msize == 0) {
        return MANIFEST_ERR_NOT_FOUND;
    }
    /* 数据条目的 OffsetToData 是数据 RVA，按映射模型直接定位 */
    data = mf_ptr(pe, data_entry->OffsetToData, msize);
    if (data == NULL) {
        return MANIFEST_ERR_BAD_PE;
    }

    /* 拷贝至输出缓冲区并 NUL 结尾；容量不足时截断并报错 */
    copy = (msize < buf_capacity - 1) ? (size_t)msize : (buf_capacity - 1);
    memcpy(out_buf, data, copy);
    out_buf[copy] = '\0';
    *out_size = copy;
    if (copy < (size_t)msize) {
        return MANIFEST_ERR_NO_ROOM;
    }
    return MANIFEST_OK;
}

/* ------------------------------------------------------------------ */
/* manifest_inject_win7_guid - 注入 Win7 supportedOS GUID              */
/* ------------------------------------------------------------------ */
int manifest_inject_win7_guid(char* xml, size_t xml_size, size_t xml_capacity,
                              size_t* out_new_size)
{
    /* Win7 GUID 主体（去掉花括号），用于幂等检测 */
    static const char win7_guid_body[] =
        "35138b9a-5d96-4fbd-8e2d-a2440225f93a";
    /* 在已有 <supportedOS> 前插入的 Win7 行 */
    static const char inject_line[] =
        "    <supportedOS Id=\"" WIN7_SUPPORTEDOS_GUID "\"/>\n";
    /* 无 <compatibility> 块时插入的最小 compatibility 块 */
    static const char minimal_block[] =
        "  <compatibility xmlns=\"urn:schemas-microsoft-com:compatibility.v1\">\n"
        "    <application>\n"
        "      <supportedOS Id=\"" WIN7_SUPPORTEDOS_GUID "\"/>\n"
        "    </application>\n"
        "  </compatibility>\n";
    /* 有 <compatibility> 但无 <application> 时插入的最小 application 块 */
    static const char minimal_app[] =
        "    <application>\n"
        "      <supportedOS Id=\"" WIN7_SUPPORTEDOS_GUID "\"/>\n"
        "    </application>\n";

    char* comp;
    char* app;
    char* supp;
    char* app_close;
    char* comp_close;
    char* asm_close;
    size_t pos;
    size_t remain;

    if (out_new_size != NULL) {
        *out_new_size = xml_size;
    }
    if (xml == NULL || out_new_size == NULL) {
        return MANIFEST_ERR_INVALID_ARG;
    }
    /* 维护 NUL 结尾的前置条件 */
    if (xml_capacity < xml_size + 1) {
        return MANIFEST_ERR_INVALID_ARG;
    }
    xml[xml_size] = '\0';

    /* 1) 已含 Win7 GUID（大小写不敏感）则跳过，保证幂等 */
    if (mf_ci_memstr(xml, xml_size, win7_guid_body) != NULL) {
        return 0;
    }

    /* 2) 定位 <compatibility> 块 */
    comp = mf_ci_memstr(xml, xml_size, "<compatibility");
    if (comp == NULL) {
        /* 无 compatibility 块：在 </assembly> 前追加最小块 */
        asm_close = mf_ci_memstr(xml, xml_size, "</assembly>");
        pos = (asm_close != NULL) ? (size_t)(asm_close - xml) : xml_size;
        if (mf_buf_insert(xml, &xml_size, xml_capacity, pos,
                          minimal_block, sizeof(minimal_block) - 1) != 0) {
            *out_new_size = xml_size;
            return MANIFEST_ERR_NO_ROOM;
        }
        *out_new_size = xml_size;
        return 1;
    }

    /* 3) compatibility 块内定位 <application> */
    remain = xml_size - (size_t)(comp - xml);
    app = mf_ci_memstr(comp, remain, "<application");
    if (app == NULL) {
        /* 有 compatibility 但无 application：在 </compatibility> 前插入 app */
        comp_close = mf_ci_memstr(comp, remain, "</compatibility>");
        pos = (comp_close != NULL) ? (size_t)(comp_close - xml) : xml_size;
        if (mf_buf_insert(xml, &xml_size, xml_capacity, pos,
                          minimal_app, sizeof(minimal_app) - 1) != 0) {
            *out_new_size = xml_size;
            return MANIFEST_ERR_NO_ROOM;
        }
        *out_new_size = xml_size;
        return 1;
    }

    /* 4) application 内定位第一个 <supportedOS> */
    remain = xml_size - (size_t)(app - xml);
    supp = mf_ci_memstr(app, remain, "<supportedOS");
    if (supp != NULL) {
        /* 在第一个 supportedOS 前插入 Win7 行 */
        pos = (size_t)(supp - xml);
        if (mf_buf_insert(xml, &xml_size, xml_capacity, pos,
                          inject_line, sizeof(inject_line) - 1) != 0) {
            *out_new_size = xml_size;
            return MANIFEST_ERR_NO_ROOM;
        }
        *out_new_size = xml_size;
        return 1;
    }

    /* 5) application 内无 supportedOS：在 </application> 前插入 Win7 行 */
    app_close = mf_ci_memstr(app, remain, "</application>");
    if (app_close != NULL) {
        pos = (size_t)(app_close - xml);
    } else {
        /* 退化为 </compatibility> 前 */
        comp_close = mf_ci_memstr(comp, xml_size - (size_t)(comp - xml),
                                  "</compatibility>");
        pos = (comp_close != NULL) ? (size_t)(comp_close - xml) : xml_size;
    }
    if (mf_buf_insert(xml, &xml_size, xml_capacity, pos,
                      inject_line, sizeof(inject_line) - 1) != 0) {
        *out_new_size = xml_size;
        return MANIFEST_ERR_NO_ROOM;
    }
    *out_new_size = xml_size;
    return 1;
}

/* ------------------------------------------------------------------ */
/* manifest_strip_win10_only - 剥离 Win10-only 元素                    */
/* ------------------------------------------------------------------ */

/*
 * 剥离单个元素（自闭合 <tag.../> 或配对 <tag>...</tag>）。
 *   open_tag  ：开标签前缀，如 "<maxversiontested"
 *   close_tag ：闭合标签，如 "</maxversiontested>"
 * 返回：1=已剥离一个；0=未找到；<0=畸形出错。
 * 通过简单字符串匹配定位，删除区间后顺带吃掉一个尾随换行以保持排版。
 */
static int mf_strip_element(char* xml, size_t* size,
                            const char* open_tag, const char* close_tag)
{
    char* start;
    char* gt;
    char* slash;
    char* close;
    char* span_end;  /* 待删除区间末尾（不含） */
    size_t close_len = strlen(close_tag);
    size_t p;

    start = mf_ci_memstr(xml, *size, open_tag);
    if (start == NULL) {
        return 0;
    }
    /* 找开标签的 '>' */
    gt = memchr(start, '>', *size - (size_t)(start - xml));
    if (gt == NULL) {
        return -1;  /* 畸形：开标签未闭合 */
    }
    /* 判断是否自闭合：[start, gt) 内是否含 '/' */
    slash = memchr(start, '/', (size_t)(gt - start));
    if (slash != NULL) {
        /* 自闭合，删除 [start, gt+1) */
        span_end = gt + 1;
    } else {
        /* 配对，查找闭合标签 */
        close = mf_ci_memstr(gt, *size - (size_t)(gt - xml), close_tag);
        if (close == NULL) {
            /* 无闭合标签，仅删除开标签 */
            span_end = gt + 1;
        } else {
            span_end = close + close_len;
        }
    }

    p = (size_t)(start - xml);
    mf_buf_erase(xml, size, p, (size_t)(span_end - start));

    /* 顺带删除尾随换行（\r\n 或 \n），保持排版整洁 */
    if (p + 1 < *size && xml[p] == '\r' && xml[p + 1] == '\n') {
        mf_buf_erase(xml, size, p, 2);
    } else if (p < *size && xml[p] == '\n') {
        mf_buf_erase(xml, size, p, 1);
    }
    return 1;
}

int manifest_strip_win10_only(char* xml, size_t xml_size, size_t xml_capacity,
                              size_t* out_new_size)
{
    int removed = 0;
    int r;

    if (out_new_size != NULL) {
        *out_new_size = xml_size;
    }
    if (xml == NULL || out_new_size == NULL) {
        return MANIFEST_ERR_INVALID_ARG;
    }
    if (xml_capacity < xml_size + 1) {
        return MANIFEST_ERR_INVALID_ARG;
    }
    xml[xml_size] = '\0';

    /* 循环剥离所有 <maxversiontested> 元素 */
    for (;;) {
        r = mf_strip_element(xml, &xml_size, "<maxversiontested",
                             "</maxversiontested>");
        if (r < 0) {
            *out_new_size = xml_size;
            return r;
        }
        if (r == 0) {
            break;
        }
        ++removed;
    }

    /* 循环剥离所有 <msix> 元素 */
    for (;;) {
        r = mf_strip_element(xml, &xml_size, "<msix", "</msix>");
        if (r < 0) {
            *out_new_size = xml_size;
            return r;
        }
        if (r == 0) {
            break;
        }
        ++removed;
    }

    *out_new_size = xml_size;
    return removed;
}
