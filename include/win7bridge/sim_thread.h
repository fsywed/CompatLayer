/*
 * sim_thread.h - Win7Bridge L3 线程/控制台/内存 API 模拟接口
 *
 * 对应 docs/api-diff.md §2.5：为 Win10 新增、Win7 缺失的下列 API 提供
 * 退化/模拟实现：
 *   - SetThreadDescription / GetThreadDescription（Win10 1607）：TLS 槽存储，
 *     host 下用全局数组按线程 id 索引模拟。
 *   - VirtualAlloc2（Win10 1607）：退化为 VirtualAlloc。
 *   - MapViewOfFileNuma2（Win10 1703）：退化为 MapViewOfFile。
 *   - CreatePseudoConsole 系列（Win10 1809）：管道 + 控制台缓冲模拟。
 *
 * 本头文件不依赖 <windows.h>：HANDLE/DWORD 复用 pe_types.h，其余类型
 * （SIZE_T/BOOL/HRESULT/ULONG_PTR/COORD）在此补充定义，以便用原生 gcc
 * 做 host 测试与语法检查。Windows 专有 API 用 extern 声明 + #ifdef _WIN32
 * 隔离，仅在真实 Windows 编译时生效。
 */
#ifndef WIN7BRIDGE_SIM_THREAD_H
#define WIN7BRIDGE_SIM_THREAD_H

#include "win7bridge/pe_types.h"   /* HANDLE, DWORD, BYTE, PVOID 等       */
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------ */
/* 类型补充（pe_types.h 已提供 HANDLE=void*、DWORD=uint32_t）          */
/* ------------------------------------------------------------------ */
#ifndef _WIN7BRIDGE_SIZE_T_DEFINED
typedef uint64_t SIZE_T;            /* 任务约定：64 位                    */
#define _WIN7BRIDGE_SIZE_T_DEFINED
#endif

#ifndef _WIN7BRIDGE_BOOL_DEFINED
typedef int BOOL;                   /* Win32 BOOL                        */
#define _WIN7BRIDGE_BOOL_DEFINED
#endif

#ifndef TRUE
#define TRUE 1
#endif
#ifndef FALSE
#define FALSE 0
#endif

typedef int32_t  HRESULT;           /* COM HRESULT                        */
typedef uint64_t ULONG_PTR;         /* 指针宽度无符号（任务约定 64 位）    */

typedef int16_t SHORT;
/* 控制台坐标                                                          */
typedef struct _COORD {
    SHORT X;
    SHORT Y;
} COORD;

/* HRESULT 常用值                                                      */
#ifndef S_OK
#define S_OK            ((HRESULT)0)
#endif
#ifndef E_FAIL
#define E_FAIL          ((HRESULT)0x80004005L)
#endif
#ifndef E_INVALIDARG
#define E_INVALIDARG    ((HRESULT)0x80070057L)
#endif
#ifndef E_NOTIMPL
#define E_NOTIMPL       ((HRESULT)0x80004001L)
#endif
#ifndef E_OUTOFMEMORY
#define E_OUTOFMEMORY   ((HRESULT)0x8007000EL)
#endif
#ifndef E_POINTER
#define E_POINTER       ((HRESULT)0x80004003L)
#endif

/* 内存分配类型/保护标志占位常量（供调用方传入，退化实现仅作识别）      */
#define SIM_MEM_COMMIT      0x00001000
#define SIM_MEM_RESERVE     0x00002000
#define SIM_MEM_RESET       0x00080000
#define SIM_PAGE_READWRITE  0x00000004

/* 伪控制台创建标志占位（对应 Win10 PSEUDOCONSOLE_INHERIT_CURSOR）       */
#define SIM_PSEUDOCONSOLE_INHERIT_CURSOR 0x1

/* ------------------------------------------------------------------ */
/* 线程描述（SetThreadDescription / GetThreadDescription）             */
/* ------------------------------------------------------------------ */
/* 设置线程描述；desc 为 NULL 表示清空。host 下 thread 用 1/2/3 模拟。  */
HRESULT sim_SetThreadDescription(HANDLE thread, const wchar_t* desc);

/* 读取线程描述；*out 指向新分配的宽字符串，调用方需 free() 释放。     */
HRESULT sim_GetThreadDescription(HANDLE thread, wchar_t** out);

/* ------------------------------------------------------------------ */
/* 内存（VirtualAlloc2 / MapViewOfFileNuma2 退化）                     */
/* ------------------------------------------------------------------ */
/* 退化为 VirtualAlloc；host 下用 malloc。忽略 addr 与 extended_params，
 * 丢失占位符/替换语义。返回的内存 host 下用 free() 释放。             */
void* sim_VirtualAlloc2(HANDLE process, void* addr, SIZE_T size,
                        DWORD type, DWORD protect, void* extended_params);

/* 退化为 MapViewOfFile；host 下无真实文件映射对象，返回 NULL。可变参数
 * 对应 Win10 的 AllocationType / PageProtection / NodeNumber。        */
void* sim_MapViewOfFileNuma2(HANDLE filemapping, ULONG_PTR offset,
                             void* base, SIZE_T size, ...);

/* ------------------------------------------------------------------ */
/* 伪控制台（CreatePseudoConsole 系列）                                */
/* ------------------------------------------------------------------ */
/* 用管道 + 控制台缓冲模拟；host 下分配结构体作为句柄并返回 S_OK。     */
HRESULT sim_CreatePseudoConsole(COORD size, HANDLE input, HANDLE output,
                                DWORD flags, void** out_hpc);

/* 关闭伪控制台；NULL 与非法句柄安全。                                 */
void sim_ClosePseudoConsole(void* hpc);

/* 调整伪控制台尺寸；NULL 与非法句柄返回错误码。                       */
HRESULT sim_ResizePseudoConsole(void* hpc, COORD size);

#ifdef __cplusplus
}
#endif

#endif /* WIN7BRIDGE_SIM_THREAD_H */
