/*
 * inline_hook.h - Win7Bridge L1 inline hook 接口
 *
 * 提供 x86/x64 函数入口 patch 能力：把 target 函数入口前若干字节
 * 拷贝到 trampoline 缓冲区并追加一条跳回 target+N 的 jmp，再在 target
 * 处写入跳往 detour 的 jmp。这样 detour 可在 hook 链中通过调用
 * trampoline 复原原始指令序列后回到 target+N。
 *
 * 与 VxKex 不同，本模块配合 engine_find_func_redirect 可覆盖运行时
 * GetProcAddress / LdrGetProcedureAddress 动态解析的导出，而不仅是
 * 静态 IAT。
 *
 * 指令长度解码器 inline_hook_length_decode 是纯函数，可在 host 测试中
 * 验证；inline_hook_install 在 host 下因代码段不可写只做解码与
 * trampoline 构造，不实际 patch target。
 */
#ifndef WIN7BRIDGE_INLINE_HOOK_H
#define WIN7BRIDGE_INLINE_HOOK_H

#include <stddef.h>
#include "win7bridge/pe_types.h"   /* BYTE */

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------ */
/* 返回码                                                              */
/* ------------------------------------------------------------------ */
#define INLINE_HOOK_OK                   0   /* 成功                  */
#define INLINE_HOOK_ERR_INVALID_ARG     (-1) /* 入参非法              */
#define INLINE_HOOK_ERR_DECODE          (-2) /* 指令解码失败（截断）  */
#define INLINE_HOOK_ERR_UNKNOWN_OPCODE  (-3) /* 未识别的操作码        */
#define INLINE_HOOK_ERR_ALLOC           (-4) /* trampoline 分配失败   */
#define INLINE_HOOK_ERR_PROTECT         (-5) /* VirtualProtect 失败   */

/* 跳转桩长度：x86 rel32 = 5；x64 FF 25 [rip+0] + abs64 = 14            */
#if defined(_WIN64) || defined(__x86_64__) || defined(__LP64__) || \
    defined(__amd64__) || defined(__aarch64__)
#define INLINE_HOOK_JMP_LEN  14
#else
#define INLINE_HOOK_JMP_LEN  5
#endif

/* trampoline 缓冲区最大容量：拷贝的原指令 + 跳回桩                   */
#define INLINE_HOOK_TRAMPOLINE_MAX  (INLINE_HOOK_JMP_LEN + 16)

/* ------------------------------------------------------------------ */
/* InlineHook 句柄                                                     */
/* ------------------------------------------------------------------ */
typedef struct _InlineHook {
    void*  target;       /* 被 hook 的目标函数入口                     */
    void*  detour;       /* detour 函数地址                           */
    void*  trampoline;   /* 持有原入口指令 + 跳回 target+N 的桩        */
    size_t patch_size;   /* 从 target 拷贝出的原始指令字节数           */
} InlineHook;

/* ------------------------------------------------------------------ */
/* 接口函数                                                            */
/* ------------------------------------------------------------------ */

/*
 * inline_hook_length_decode - 最小 x86/x64 指令长度解码器
 *   code    ：指令字节流
 *   min_len ：需要被覆盖的最小字节数（x86=5，x64=14）
 *   out_len ：输出覆盖 min_len 所需的完整指令序列总长度
 *   调用方需保证 code 后至少 min_len + 15 字节可读（x86 指令最长 15B）
 * 返回：INLINE_HOOK_OK 成功；负值见 INLINE_HOOK_ERR_*。
 */
int inline_hook_length_decode(const void* code, size_t min_len, size_t* out_len);

/*
 * inline_hook_install - 安装 inline hook
 *   h       ：调用者分配的句柄（函数内填充）
 *   target  ：被 hook 的函数入口
 *   detour  ：detour 函数入口
 *   成功后 h->trampoline 指向持有原指令 + 跳回 target+N 的缓冲区，
 *   调用方负责在卸载时通过 inline_hook_remove 释放。
 *   host 测试模式下因代码段不可写，仅完成解码与 trampoline 构造，
 *   不实际写 target；返回 INLINE_HOOK_OK 表示解码与构造成功。
 * 返回：INLINE_HOOK_OK 成功；负值出错。
 */
int inline_hook_install(InlineHook* h, void* target, void* detour);

/*
 * inline_hook_remove - 卸载 inline hook
 *   释放 trampoline 缓冲区并把句柄字段清零。
 *   host 测试模式下不恢复 target 原始字节（因未实际写入）。
 * 返回：INLINE_HOOK_OK 成功；负值出错。
 */
int inline_hook_remove(InlineHook* h);

#ifdef __cplusplus
}
#endif

#endif /* WIN7BRIDGE_INLINE_HOOK_H */
