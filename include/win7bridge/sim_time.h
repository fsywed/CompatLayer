/*
 * sim_time.h - Win7Bridge L3 时间与同步 API 模拟接口
 *
 * Win7 缺失 Win8+ 引入的两个能力：
 *   1) GetSystemTimePreciseAsFileTime（Win8+）—— 高精度系统时间。
 *   2) WaitOnAddress / WakeByAddressSingle / WakeByAddressAll（Win8+）
 *      —— 基于地址的无锁等待/唤醒。
 * 本层提供本地回退实现，使 Win10 软件在 Win7 上不因这两个 API 缺失而崩。
 *
 * 不依赖 <windows.h>。Windows 基本类型来自 win7bridge/pe_types.h
 * （DWORD 等）；SIZE_T/FILETIME 在本头自定义。可在原生 gcc 下 host 测试。
 *
 * 参考 docs/api-diff.md §2.5（单函数级缺失 API）。
 */
#ifndef WIN7BRIDGE_SIM_TIME_H
#define WIN7BRIDGE_SIM_TIME_H

#include <stdint.h>
#include "win7bridge/pe_types.h"   /* DWORD */

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------ */
/* 类型定义                                                            */
/* ------------------------------------------------------------------ */
/* SIZE_T：无符号指针宽度整数（对标 Windows SDK SIZE_T），统一取 64 位 */
typedef uint64_t SIZE_T;

/* FILETIME：自 1601-01-01 起的 100ns 计数（低 32 + 高 32）            */
typedef struct _FILETIME {
    DWORD dwLowDateTime;
    DWORD dwHighDateTime;
} FILETIME;

/* ------------------------------------------------------------------ */
/* 等待返回码与错误码（与 Windows 取值一致）                            */
/* ------------------------------------------------------------------ */
#ifndef WAIT_OBJECT_0
#define WAIT_OBJECT_0           0       /* 等待成功                   */
#endif
#ifndef WAIT_TIMEOUT
#define WAIT_TIMEOUT            258     /* 超时                        */
#endif
#ifndef ERROR_INVALID_PARAMETER
#define ERROR_INVALID_PARAMETER 87      /* 入参非法                    */
#endif

/* ------------------------------------------------------------------ */
/* 接口函数                                                            */
/* ------------------------------------------------------------------ */

/*
 * sim_GetSystemTimePreciseAsFileTime - 模拟 GetSystemTimePreciseAsFileTime
 *   out_filetime：输出 FILETIME（自 1601-01-01 的 100ns 计数）
 *   host 测试用 clock_gettime(CLOCK_REALTIME) 填充；Windows 回退到
 *   GetSystemTimeAsFileTime（精度 ~15.6ms，语义一致）。
 * 返回：1 成功；0 出错（out_filetime 为空或取时失败）。
 */
int sim_GetSystemTimePreciseAsFileTime(void* out_filetime);

/*
 * sim_WaitOnAddress - 模拟 WaitOnAddress
 *   addr        ：待监控的地址（volatile）
 *   compare_addr：指向比较值的缓冲
 *   size        ：1/2/4/8，addr 处待比较的字节数
 *   timeout_ms  ：超时毫秒（0 表示仅探测一次）
 *   语义：若 *addr 与 *compare 不相等，立即返回 WAIT_OBJECT_0；
 *         否则等待 WakeByAddress* 唤醒或超时。
 *   host 下用带超时的轮询模拟；真实 Windows 实现应用事件对象阻塞。
 * 返回：WAIT_OBJECT_0(0) 成功；WAIT_TIMEOUT(258) 超时；
 *       ERROR_INVALID_PARAMETER(87) 入参非法。
 */
int sim_WaitOnAddress(volatile void* addr, void* compare_addr,
                      SIZE_T size, DWORD timeout_ms);

/*
 * sim_WakeByAddressSingle - 模拟 WakeByAddressSingle
 *   唤醒一个在 addr 上等待的线程。host 下设置该地址的唤醒标志。
 * 返回：0 成功。
 */
int sim_WakeByAddressSingle(void* addr);

/*
 * sim_WakeByAddressAll - 模拟 WakeByAddressAll
 *   唤醒所有在 addr 上等待的线程。host 下设置该地址的唤醒标志。
 * 返回：0 成功。
 */
int sim_WakeByAddressAll(void* addr);

#ifdef __cplusplus
}
#endif

#endif /* WIN7BRIDGE_SIM_TIME_H */
