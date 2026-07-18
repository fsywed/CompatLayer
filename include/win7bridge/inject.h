/*
 * inject.h - Win7Bridge Loader 进程注入接口
 *
 * 【开发文档】
 *
 * 目的：把 win7bridge.dll 注入到目标 Win10 EXE 进程，使兼容层在
 *   目标进程加载任何静态导入之前就完成 inline hook 安装。
 *
 * 分点展开：
 *   1. 方法：CreateProcess(CREATE_SUSPENDED) 暂停主线程，在目标进程
 *      中 VirtualAllocEx 分配一块内存写入 DLL 路径字符串，再
 *      CreateRemoteThread(LoadLibraryA, dll_path) 加载 DLL。
 *      DllMain 在远线程中执行，安装 hook 后返回；随后主线程被
 *      ResumeThread 唤醒，此时所有 Win10 API 已被 hook 接管。
 *
 *   2. 可逆性：注入的 DLL 仅在目标进程内生效，不修改磁盘上的 EXE
 *      也不改写系统注册表；进程退出即自然卸载。
 *
 *   3. 平台隔离：所有 Windows API 调用都在 inject.c 中以
 *      #if defined(_WIN32) && !defined(WIN7BRIDGE_HOST_TEST) &&
 *                         !defined(WIN7BRIDGE_SYNTAX_CHECK)
 *      守卫；host / syntax-check 模式下 inject_launch 返回
 *      INJECT_ERR_HOST_NOT_SUPPORTED，便于 make test 链接。
 */
#ifndef WIN7BRIDGE_INJECT_H
#define WIN7BRIDGE_INJECT_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------ */
/* 注入方法                                                            */
/* ------------------------------------------------------------------ */
typedef enum {
    INJECT_METHOD_REMOTE_THREAD = 0,   /* CreateRemoteThread + LoadLibraryA */
    INJECT_METHOD_APC           = 1    /* QueueUserAPC（暂未实现，回退到 REMOTE_THREAD） */
} InjectMethod;

/* ------------------------------------------------------------------ */
/* 返回码                                                              */
/* ------------------------------------------------------------------ */
#define INJECT_OK                     0
#define INJECT_ERR_INVALID_ARG       (-1)   /* 入参非法                  */
#define INJECT_ERR_HOST_NOT_SUPPORTED (-2)  /* host/syntax-check 环境    */
#define INJECT_ERR_CREATE_PROCESS    (-3)   /* CreateProcess 失败        */
#define INJECT_ERR_ALLOC             (-4)   /* VirtualAllocEx 失败       */
#define INJECT_ERR_WRITE             (-5)   /* WriteProcessMemory 失败   */
#define INJECT_ERR_NO_LOADLIB        (-6)   /* kernel32!LoadLibraryA 缺失 */
#define INJECT_ERR_REMOTE_THREAD     (-7)   /* CreateRemoteThread 失败   */
#define INJECT_ERR_TIMEOUT           (-8)   /* 远线程等待超时            */
#define INJECT_ERR_BAD_EXIT          (-9)   /* LoadLibraryA 返回 NULL    */

/* ------------------------------------------------------------------ */
/* InjectContext - 注入会话上下文                                      */
/*   生命周期：inject_init → set_dll_path/set_target/set_work_dir →    */
/*              inject_launch → inject_cleanup                         */
/* ------------------------------------------------------------------ */
typedef struct _InjectContext {
    const char* dll_path;     /* 待注入 DLL 路径（ANSI）               */
    const char* exe_path;     /* 目标 EXE 路径                          */
    const char* args;         /* 命令行附加参数（可为 NULL）            */
    const char* work_dir;     /* 工作目录（可为 NULL，用 EXE 所在目录） */
    InjectMethod method;      /* 注入方法                              */

    /* 输出（inject_launch 填充）                                       */
    void*  hProcess;          /* 目标进程句柄                          */
    void*  hThread;           /* 主线程句柄                            */
    unsigned long pid;        /* 目标进程 ID                           */
} InjectContext;

/* 初始化上下文为空状态。返回 INJECT_OK。*/
int inject_init(InjectContext* ctx);

/* 设置 DLL 路径。dll_path 不可为 NULL。返回 INJECT_OK / INJECT_ERR_INVALID_ARG。*/
int inject_set_dll_path(InjectContext* ctx, const char* dll_path);

/* 设置目标 EXE 路径。exe_path 不可为 NULL。*/
int inject_set_target(InjectContext* ctx, const char* exe_path,
                      const char* args);

/* 设置工作目录。work_dir 为 NULL 时用 EXE 所在目录。*/
int inject_set_work_dir(InjectContext* ctx, const char* work_dir);

/*
 * inject_launch - 启动目标进程并注入 DLL
 *   成功后 ctx->hProcess / hThread / pid 被填充，主线程已恢复执行。
 *   调用方随后可 WaitForSingleObject(ctx->hProcess, INFINITE) 等待退出。
 * 返回：INJECT_OK 成功；负值见 INJECT_ERR_*。
 */
int inject_launch(InjectContext* ctx);

/* 释放上下文持有的句柄。ctx 可能为 NULL。返回 INJECT_OK。*/
int inject_cleanup(InjectContext* ctx);

#ifdef __cplusplus
}
#endif

#endif /* WIN7BRIDGE_INJECT_H */
