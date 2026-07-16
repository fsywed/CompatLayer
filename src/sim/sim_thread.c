/*
 * sim_thread.c - Win7Bridge L3 线程/控制台/内存 API 模拟实现
 *
 * 对应 docs/api-diff.md §2.5：
 *   - SetThreadDescription / GetThreadDescription：用 TLS 槽存储的回退方案，
 *     host 下用全局数组按线程 id 索引模拟（句柄用 1/2/3 代表线程）。
 *   - VirtualAlloc2 / MapViewOfFileNuma2：退化为 VirtualAlloc / MapViewOfFile。
 *   - CreatePseudoConsole 系列：管道 + 控制台缓冲模拟，host 下分配结构体
 *     作为伪句柄。
 *
 * Windows 专有 API 用 extern 声明 + #ifdef _WIN32 调真实实现；host 路径
 * 用 malloc/free/access 等标准库模拟，确保原生 gcc 可编译运行。
 */
#include "win7bridge/sim_thread.h"

#include <stdlib.h>
#include <string.h>
#include <wchar.h>

/* 线程描述符表最大条目数（host 模拟按线程 id 索引）                    */
#define SIM_MAX_THREADS 64

/* 线程描述符全局表：g_thread_desc[idx] 存储线程 idx 的描述宽字符串。
 * 非线程安全；生产环境应加临界段保护。                                */
static wchar_t* g_thread_desc[SIM_MAX_THREADS];

/* 伪控制台内部结构（host 模拟句柄的真实载体）                         */
typedef struct {
    COORD  size;        /* 控制台缓冲尺寸                              */
    HANDLE input;       /* 输入端句柄                                   */
    HANDLE output;      /* 输出端句柄                                   */
    DWORD  flags;       /* 创建标志                                     */
    int    magic;       /* 校验魔数，防止误释放                         */
} SimPseudoConsole;

#define SIM_PCON_MAGIC 0x50434F4E   /* "PCON"                            */

/* ------------------------------------------------------------------ */
/* 内部辅助：线程句柄 -> 描述符表索引                                  */
/* ------------------------------------------------------------------ */
static int sim_thread_index(HANDLE thread)
{
#ifdef _WIN32
    /* Windows：用真实线程 id 取模索引（简化回退，存在冲突可能）        */
    extern DWORD GetThreadId(HANDLE);
    DWORD tid = GetThreadId((HANDLE)thread);
    if (tid == 0) {
        return -1;
    }
    return (int)(tid % SIM_MAX_THREADS);
#else
    /* host：句柄用 1/2/3 模拟，直接当作索引                            */
    intptr_t idx = (intptr_t)thread;
    if (idx <= 0 || idx >= SIM_MAX_THREADS) {
        return -1;
    }
    return (int)idx;
#endif
}

/* ------------------------------------------------------------------ */
/* SetThreadDescription / GetThreadDescription                         */
/* ------------------------------------------------------------------ */
HRESULT sim_SetThreadDescription(HANDLE thread, const wchar_t* desc)
{
    int idx;

    idx = sim_thread_index(thread);
    if (idx < 0) {
        return E_INVALIDARG;
    }

    /* 释放旧描述                                                      */
    if (g_thread_desc[idx] != NULL) {
        free(g_thread_desc[idx]);
        g_thread_desc[idx] = NULL;
    }

    if (desc != NULL) {
        size_t   len  = wcslen(desc);
        wchar_t* copy = (wchar_t*)malloc((len + 1) * sizeof(wchar_t));
        if (copy == NULL) {
            return E_OUTOFMEMORY;
        }
        wcscpy(copy, desc);
        g_thread_desc[idx] = copy;
    }
    return S_OK;
}

HRESULT sim_GetThreadDescription(HANDLE thread, wchar_t** out)
{
    int      idx;
    wchar_t* src;
    wchar_t* copy;

    if (out == NULL) {
        return E_POINTER;
    }
    *out = NULL;

    idx = sim_thread_index(thread);
    if (idx < 0) {
        return E_INVALIDARG;
    }

    src = g_thread_desc[idx];
    if (src == NULL) {
        /* 无描述时返回空串，便于调用方一致处理                        */
        copy = (wchar_t*)malloc(sizeof(wchar_t));
        if (copy == NULL) {
            return E_OUTOFMEMORY;
        }
        copy[0] = L'\0';
        *out = copy;
        return S_OK;
    }

    copy = (wchar_t*)malloc((wcslen(src) + 1) * sizeof(wchar_t));
    if (copy == NULL) {
        return E_OUTOFMEMORY;
    }
    wcscpy(copy, src);
    *out = copy;
    return S_OK;
}

/* ------------------------------------------------------------------ */
/* VirtualAlloc2（退化为 VirtualAlloc / malloc）                        */
/* ------------------------------------------------------------------ */
void* sim_VirtualAlloc2(HANDLE process, void* addr, SIZE_T size,
                        DWORD type, DWORD protect, void* extended_params)
{
    (void)process;
    (void)addr;             /* 退化实现无法指定基址，忽略                */
    (void)type;
    (void)protect;
    (void)extended_params;  /* 占位符/扩展参数语义丢失                   */

#ifdef _WIN32
    /* Windows：退化为 VirtualAlloc，丢失占位符/替换语义                */
    extern void* VirtualAlloc(void* addr, SIZE_T size, DWORD type, DWORD protect);
    return VirtualAlloc(NULL, size, type, protect);
#else
    /* host：用 malloc 模拟（调用方用 free 释放）                       */
    if (size == 0) {
        return NULL;
    }
    return malloc((size_t)size);
#endif
}

/* ------------------------------------------------------------------ */
/* MapViewOfFileNuma2（退化为 MapViewOfFile）                           */
/* ------------------------------------------------------------------ */
void* sim_MapViewOfFileNuma2(HANDLE filemapping, ULONG_PTR offset,
                             void* base, SIZE_T size, ...)
{
    /* 可变参数（Win10）：AllocationType / PageProtection / NodeNumber，
     * 退化实现忽略 NUMA 节点参数。                                     */
    (void)filemapping;
    (void)offset;
    (void)base;
    (void)size;

#ifdef _WIN32
    {
        /* 真实实现需解析可变参数并转发到 MapViewOfFileEx；此处仅给出
         * 回退路径声明，编译时由 _WIN32 分支接管。                     */
        extern void* MapViewOfFileEx(HANDLE, DWORD, DWORD, DWORD,
                                     SIZE_T, void*);
        return MapViewOfFileEx((HANDLE)filemapping, SIM_PAGE_READWRITE,
                               (DWORD)(offset >> 32), (DWORD)offset,
                               size, base);
    }
#else
    /* host：无真实文件映射对象，无法模拟，返回 NULL                    */
    return NULL;
#endif
}

/* ------------------------------------------------------------------ */
/* CreatePseudoConsole 系列（管道 + 控制台缓冲模拟）                    */
/* ------------------------------------------------------------------ */
HRESULT sim_CreatePseudoConsole(COORD size, HANDLE input, HANDLE output,
                                DWORD flags, void** out_hpc)
{
    SimPseudoConsole* p;

    if (out_hpc == NULL) {
        return E_POINTER;
    }
    *out_hpc = NULL;

    p = (SimPseudoConsole*)malloc(sizeof(SimPseudoConsole));
    if (p == NULL) {
        return E_OUTOFMEMORY;
    }
    p->size   = size;
    p->input  = input;
    p->output = output;
    p->flags  = flags;
    p->magic  = SIM_PCON_MAGIC;
    *out_hpc  = p;

    /* 真实实现：CreatePipe 建立输入/输出管道，分配控制台屏幕缓冲，
     * 将管道写端绑定到子进程 STARTUPINFO 的 hStdInput/hStdOutput。     */
    return S_OK;
}

void sim_ClosePseudoConsole(void* hpc)
{
    SimPseudoConsole* p = (SimPseudoConsole*)hpc;

    if (p == NULL || p->magic != SIM_PCON_MAGIC) {
        return;
    }
    /* 真实实现：先 CloseHandle 关闭管道两端与控制台缓冲，再释放结构体 */
    p->magic = 0;
    free(p);
}

HRESULT sim_ResizePseudoConsole(void* hpc, COORD size)
{
    SimPseudoConsole* p = (SimPseudoConsole*)hpc;

    if (p == NULL) {
        return E_POINTER;
    }
    if (p->magic != SIM_PCON_MAGIC) {
        return E_INVALIDARG;
    }
    p->size = size;
    return S_OK;
}
