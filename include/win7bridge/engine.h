/*
 * engine.h - Win7Bridge L1 符号级重写引擎接口
 *
 * 这是相对 VxKex 最大的结构性改进：VxKex 只能整 DLL 重定向、不覆盖
 * GetProcAddress 动态解析；本引擎实现三层粒度：
 *   ① 整 DLL 转发（REWRITE_FORWARD_DLL）：把导入表中的 DLL 名改写为
 *      转发目标 DLL，由 loader 加载转发目标。
 *   ② 单导出替换/forward/stub（REWRITE_REPLACE_FUNC / REWRITE_STUB）：
 *      在 IAT 层面把单个函数的 thunk 改写为 replacement 地址；stub
 *      模式 replacement 可指向一个 no-op 桩。
 *   ③ 运行时 IAT/inline hook：通过 engine_find_func_redirect 提供规则
 *      查询供 GetProcAddress/LdrGetProcedureAddress hook 使用，并由
 *      inline_hook 模块提供函数入口 patch 能力。
 *
 * 不依赖 <windows.h>。PE 类型来自 win7bridge/pe_types.h。
 */
#ifndef WIN7BRIDGE_ENGINE_H
#define WIN7BRIDGE_ENGINE_H

#include <stddef.h>
#include "win7bridge/pe.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------ */
/* 返回码                                                              */
/* ------------------------------------------------------------------ */
#define ENGINE_OK                0   /* 成功                           */
#define ENGINE_ERR_INVALID_ARG  (-1) /* 入参非法                        */
#define ENGINE_ERR_NOMEM        (-2) /* 内存分配失败                    */
#define ENGINE_ERR_BAD_PE       (-3) /* PE 镜像无效或缺少导入表         */
#define ENGINE_ERR_NOT_FOUND    (-4) /* 未匹配到规则                    */
#define ENGINE_ERR_NO_ROOM      (-5) /* 缓冲区空间不足（如 DLL 名覆盖） */

/* ------------------------------------------------------------------ */
/* 重写类型                                                            */
/* ------------------------------------------------------------------ */
typedef enum _RewriteKind {
    REWRITE_NONE          = 0,  /* 无操作                            */
    REWRITE_FORWARD_DLL   = 1,  /* 整 DLL 转发                       */
    REWRITE_REPLACE_FUNC  = 2,  /* 单导出替换为 replacement          */
    REWRITE_STUB          = 3   /* 单导出替换为 no-op stub           */
} RewriteKind;

/* 单个导出重定向规则                                                  */
typedef struct _ExportRedirect {
    const char*  dll_name;      /* 所属 DLL 名（大小写不敏感）       */
    const char*  func_name;     /* 导出名（大小写不敏感）            */
    RewriteKind  kind;          /* 重写类型                          */
    void*        replacement;   /* 替换函数地址（STUB 时为桩地址）   */
} ExportRedirect;

/* 整 DLL 转发规则                                                     */
typedef struct _DllRedirect {
    const char*  orig_dll;      /* 原 DLL 名                         */
    const char*  forward_dll;   /* 转发目标 DLL 名                   */
} DllRedirect;

/* 引擎句柄：持有 DLL 级与函数级规则表（动态数组）                     */
typedef struct _RewriteEngine {
    DllRedirect*    dll_rules;  /* DLL 转发规则数组                  */
    size_t          dll_count;  /* 已用条目数                        */
    size_t          dll_cap;    /* 数组容量                          */
    ExportRedirect* func_rules; /* 函数重定向规则数组                */
    size_t          func_count; /* 已用条目数                        */
    size_t          func_cap;   /* 数组容量                          */
} RewriteEngine;

/* ------------------------------------------------------------------ */
/* 接口函数                                                            */
/* ------------------------------------------------------------------ */

/*
 * engine_init - 初始化引擎（清零、置空所有规则表）
 *   e：调用者分配的引擎结构
 * 返回：ENGINE_OK 成功；负值出错。
 */
int engine_init(RewriteEngine* e);

/*
 * engine_add_dll_redirect - 增加一条整 DLL 转发规则
 *   orig/forward 字符串由调用方保活（引擎只保存指针）
 * 返回：ENGINE_OK 成功；负值出错。
 */
int engine_add_dll_redirect(RewriteEngine* e, const char* orig, const char* forward);

/*
 * engine_add_func_redirect - 增加一条单导出重定向规则
 *   dll/func 字符串由调用方保活；replacement 为替换函数地址
 *   kind 必须为 REWRITE_REPLACE_FUNC 或 REWRITE_STUB
 * 返回：ENGINE_OK 成功；负值出错。
 */
int engine_add_func_redirect(RewriteEngine* e, const char* dll, const char* func,
                             RewriteKind kind, void* replacement);

/*
 * engine_rewrite_imports - 把规则应用到 PE 导入表
 *   - 匹配 dll_rules：改写 IMAGE_IMPORT_DESCRIPTOR.Name 指向的 DLL 名
 *     字符串为 forward_dll（要求缓冲区有足够空间）
 *   - 匹配 func_rules：把对应 IAT thunk 改写为 replacement
 *   pe：已解析的 PE 镜像（缓冲区必须可写）
 * 返回：>=0 表示成功改写的 thunk/名称数；<0 出错。
 */
int engine_rewrite_imports(RewriteEngine* e, PeInfo* pe);

/*
 * engine_find_func_redirect - 查询单导出规则（供 GetProcAddress hook 用）
 *   dll/func 大小写不敏感匹配；命中则填充 *out 并返回 1，否则返回 0。
 *   出错（入参非法）返回负值。
 */
int engine_find_func_redirect(RewriteEngine* e, const char* dll, const char* func,
                              ExportRedirect* out);

#ifdef __cplusplus
}
#endif

#endif /* WIN7BRIDGE_ENGINE_H */
