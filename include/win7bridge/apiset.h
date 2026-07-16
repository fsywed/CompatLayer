/*
 * apiset.h - Win7Bridge L2 API Set 虚拟解析层接口
 *
 * 背景：Win7 SP1 仅含 v2 极简 API Set schema；Win10 引入数百个
 * api-ms-win-* / ext-ms-win-* 虚拟名。Win7 加载器不解析这些新条目，
 * 导致 STATUS_DLL_NOT_FOUND (0xC0000135)。
 *
 * 本层维护一张"虚拟名 → 实现源"映射表，PE 导入表出现 api-ms-win-* /
 * ext-ms-win-* 时查表，决定转发到 Win7 真实 DLL、本地模拟层，或标注
 * 不可解（如 WinRT / AVX xstate）。
 *
 * 与 L1 engine 协作：engine 完成"规则匹配 + IAT 改写"；本层负责"虚拟名
 * 识别 + 实现源定位"，为 engine 提供整 DLL 转发目标（host_dll）。
 *
 * 不依赖 <windows.h>。PE 类型来自 win7bridge/pe_types.h / pe.h。
 */
#ifndef WIN7BRIDGE_APISET_H
#define WIN7BRIDGE_APISET_H

#include <stddef.h>
#include "win7bridge/pe.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------ */
/* 返回码                                                              */
/* ------------------------------------------------------------------ */
#define APISET_OK              0   /* 成功                            */
#define APISET_ERR_INVALID_ARG (-1) /* 入参非法                        */
#define APISET_ERR_NOMEM       (-2) /* 内存分配失败                    */

/* ------------------------------------------------------------------ */
/* 目标类型                                                            */
/* ------------------------------------------------------------------ */
typedef enum _ApiSetTargetKind {
    APISET_TO_REAL_DLL  = 0,  /* 转发到 Win7 真实 DLL（host_dll 指明）*/
    APISET_TO_LOCAL     = 1,  /* 转发到本地模拟层（host=兼容层自身）  */
    APISET_UNSOLVABLE   = 2   /* 不可解（WinRT/AVX/扩展 API set 等）  */
} ApiSetTargetKind;

/* 单条映射：虚拟名 -> 实现源                                          */
typedef struct _ApiSetEntry {
    const char*       virtual_name;  /* api-ms-win-* / ext-ms-win-*  */
    ApiSetTargetKind  kind;          /* 目标类型                      */
    const char*       host_dll;      /* TO_REAL_DLL 时为宿主 DLL 名；
                                       TO_LOCAL 时为本地模拟层标识
                                       （可空）；UNSOLVABLE 时为 NULL */
    const char*       note;         /* 备注（如"AVX 扩展上下文"）    */
} ApiSetEntry;

/* 映射表：动态数组（realloc 扩容）                                    */
typedef struct _ApiSetMap {
    ApiSetEntry* entries;
    size_t       count;
    size_t       capacity;
} ApiSetMap;

/* ------------------------------------------------------------------ */
/* 接口函数                                                            */
/* ------------------------------------------------------------------ */

/*
 * apiset_init - 初始化映射表（清零、置空）
 *   m：调用者分配的映射表
 * 返回：APISET_OK 成功；负值出错。
 */
int apiset_init(ApiSetMap* m);

/*
 * apiset_load_default - 加载预置映射表（硬编码常见条目）
 *   覆盖 api-ms-win-core-* 关键项、crt-*、winrt-*、ext-ms-win-* 等，
 *   参考 docs/api-diff.md §2.3。
 *   追加到现有表后，不清空已有条目。
 * 返回：APISET_OK 成功；负值出错。
 */
int apiset_load_default(ApiSetMap* m);

/*
 * apiset_lookup - 大小写不敏感查找
 *   virtual_name：含或不含 .dll 后缀均可（按整串比较，调用方需保证一致
 *                 或在调用前归一化）
 *   out         ：命中时填充，可为 NULL（仅探测）
 * 返回：1 命中；0 未命中；负值出错。
 */
int apiset_lookup(const ApiSetMap* m, const char* virtual_name,
                  ApiSetEntry* out);

/*
 * apiset_add - 追加一条映射
 *   vname/host/note 字符串由调用方保活（映射表只保存指针）
 *   kind 为 APISET_UNSOLVABLE 时 host 可为 NULL
 * 返回：APISET_OK 成功；负值出错。
 */
int apiset_add(ApiSetMap* m, const char* vname, ApiSetTargetKind kind,
               const char* host, const char* note);

/*
 * apiset_resolve_imports - 遍历 PE 导入表，对虚拟名查表
 *   对每个 api-ms-win-* / ext-ms-win-* 名查表，返回"需要处理的条目数"
 *   （即命中映射表的虚拟名导入项个数；这些条目可由 engine 进一步改写
 *   或本地层接管）。命中 UNSOLVABLE 的条目也计入，便于上层报告。
 * 返回：>=0 需要处理的条目数；<0 出错。
 */
int apiset_resolve_imports(const ApiSetMap* m, PeInfo* pe);

/*
 * apiset_is_virtual_name - 判断是否为 api-ms-win-* 或 ext-ms-win-* 前缀
 *   dll_name：DLL 名（可为 NULL，返回 0）
 * 返回：1 是虚拟名；0 不是。
 */
int apiset_is_virtual_name(const char* dll_name);

#ifdef __cplusplus
}
#endif

#endif /* WIN7BRIDGE_APISET_H */
