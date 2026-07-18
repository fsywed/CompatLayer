/*
 * sim_time.c - Win7Bridge L3 时间与同步 API 模拟实现
 *
 * 实现 sim_time.h 中的接口：
 *   - sim_GetSystemTimePreciseAsFileTime：host 用 clock_gettime 填充
 *     FILETIME；Windows 回退 GetSystemTimeAsFileTime。
 *   - sim_WaitOnAddress：先 memcmp，不等即返回；相等则带超时轮询唤醒
 *     标志。host 用 clock_gettime+nanosleep，Windows 用 Sleep+GetTickCount64。
 *   - sim_WakeByAddressSingle/All：维护 per-addr 唤醒标志表。
 *
 * 平台隔离与 inline_hook.c 一致：Windows 专有 extern 用
 *   #if defined(_WIN32) && !defined(WIN7BRIDGE_HOST_TEST) && !defined(WIN7BRIDGE_SYNTAX_CHECK)
 * 其余情况走 host 路径（clock_gettime/nanosleep），在原生 gcc 下可测试。
 */
#include "win7bridge/sim_time.h"

#include <string.h>
#include <stdint.h>
#include <time.h>   /* clock_gettime / nanosleep / struct timespec */

/* ------------------------------------------------------------------ */
/* 唤醒标志表：记录 WakeByAddress* 设置的唤醒标志，供 WaitOnAddress 轮询 */
/* 真实 Windows 实现应使用事件对象（CreateEvent/SetEvent/ResetEvent） +  */
/* WaitForSingleObject 阻塞；此处 host 测试用简化标志表模拟。           */
/* ------------------------------------------------------------------ */
#define SIM_WAKE_SLOTS 16
static struct {
    volatile void* addr;   /* 关联地址，NULL 表示空槽                 */
    volatile int   flag;   /* 唤醒标志：非 0 表示有待处理的唤醒        */
} g_wake_slots[SIM_WAKE_SLOTS];

/* 检查并清除 addr 的唤醒标志，返回是否命中 */
static int sim_wake_check_clear(volatile void* addr)
{
    int i;
    for (i = 0; i < SIM_WAKE_SLOTS; ++i) {
        if (g_wake_slots[i].addr == addr && g_wake_slots[i].flag) {
            g_wake_slots[i].flag = 0;
            return 1;
        }
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* sim_GetSystemTimePreciseAsFileTime                                  */
/* ------------------------------------------------------------------ */
int sim_GetSystemTimePreciseAsFileTime(void* out_filetime)
{
    FILETIME* ft = (FILETIME*)out_filetime;
    if (ft == NULL) {
        return 0;
    }

#if defined(_WIN32) && !defined(WIN7BRIDGE_HOST_TEST) && !defined(WIN7BRIDGE_SYNTAX_CHECK)
    /* Windows：回退到 GetSystemTimeAsFileTime（精度 ~15.6ms，语义一致） */
    extern void __stdcall GetSystemTimeAsFileTime(FILETIME*);
    GetSystemTimeAsFileTime(ft);
#else
    /* host 测试 / 语法检查：用 clock_gettime(CLOCK_REALTIME) 填充 FILETIME */
    struct timespec ts;
    uint64_t ft100ns;

    if (clock_gettime(CLOCK_REALTIME, &ts) != 0) {
        memset(ft, 0, sizeof(*ft));
        return 0;
    }
    /* 1601-01-01 至 1970-01-01 间隔 11644473600 秒；FILETIME 为 100ns 单位 */
    ft100ns = (uint64_t)ts.tv_sec + 11644473600ULL;
    ft100ns = ft100ns * 10000000ULL + (uint64_t)(ts.tv_nsec / 100);
    ft->dwLowDateTime  = (DWORD)(ft100ns & 0xFFFFFFFFu);
    ft->dwHighDateTime = (DWORD)(ft100ns >> 32);
#endif
    return 1;
}

/* ------------------------------------------------------------------ */
/* sim_WaitOnAddress                                                   */
/* ------------------------------------------------------------------ */
int sim_WaitOnAddress(volatile void* addr, void* compare_addr,
                      SIZE_T size, DWORD timeout_ms)
{
    if (addr == NULL || compare_addr == NULL ||
        (size != 1 && size != 2 && size != 4 && size != 8)) {
        return ERROR_INVALID_PARAMETER;
    }

    /* 1) 若 *addr 与 *compare 不相等，立即返回 WAIT_OBJECT_0 */
    if (memcmp((const void*)addr, compare_addr, (size_t)size) != 0) {
        return WAIT_OBJECT_0;
    }

    /* 2) 相等则等待唤醒或超时 */
#if defined(_WIN32) && !defined(WIN7BRIDGE_HOST_TEST) && !defined(WIN7BRIDGE_SYNTAX_CHECK)
    /* Windows 简化实现：轮询 + Sleep（真实实现应用事件对象阻塞） */
    extern void __stdcall Sleep(DWORD);
    extern unsigned long long __stdcall GetTickCount64(void);
    {
        unsigned long long deadline =
            GetTickCount64() + (unsigned long long)timeout_ms;
        for (;;) {
            if (sim_wake_check_clear(addr)) {
                return WAIT_OBJECT_0;
            }
            if (GetTickCount64() >= deadline) {
                return WAIT_TIMEOUT;
            }
            Sleep(1);
        }
    }
#else
    /* host：clock_gettime(CLOCK_MONOTONIC) 计算截止时间 + nanosleep 轮询 */
    {
        struct timespec deadline, now;
        long ms = (long)timeout_ms;

        clock_gettime(CLOCK_MONOTONIC, &deadline);
        deadline.tv_sec  += ms / 1000;
        deadline.tv_nsec += (ms % 1000) * 1000000L;
        if (deadline.tv_nsec >= 1000000000L) {
            deadline.tv_sec  += 1;
            deadline.tv_nsec -= 1000000000L;
        }

        for (;;) {
            if (sim_wake_check_clear(addr)) {
                return WAIT_OBJECT_0;
            }
            clock_gettime(CLOCK_MONOTONIC, &now);
            if (now.tv_sec > deadline.tv_sec ||
                (now.tv_sec == deadline.tv_sec && now.tv_nsec >= deadline.tv_nsec)) {
                return WAIT_TIMEOUT;
            }
            {
                struct timespec sl = { 0, 1000000L };   /* 1ms */
                nanosleep(&sl, NULL);
            }
        }
    }
#endif
}

/* ------------------------------------------------------------------ */
/* sim_WakeByAddressSingle                                             */
/* ------------------------------------------------------------------ */
int sim_WakeByAddressSingle(void* addr)
{
    int i;
    if (addr == NULL) {
        return 0;
    }

    /* 优先命中既有槽 */
    for (i = 0; i < SIM_WAKE_SLOTS; ++i) {
        if (g_wake_slots[i].addr == addr) {
            g_wake_slots[i].flag = 1;
            return 0;
        }
    }
    /* 无既有槽则占用一个空槽 */
    for (i = 0; i < SIM_WAKE_SLOTS; ++i) {
        if (g_wake_slots[i].addr == NULL) {
            g_wake_slots[i].addr = addr;
            g_wake_slots[i].flag = 1;
            return 0;
        }
    }
    /* 表满则忽略（host 测试不会触达） */
    return 0;
}

/* ------------------------------------------------------------------ */
/* sim_WakeByAddressAll                                                */
/* ------------------------------------------------------------------ */
int sim_WakeByAddressAll(void* addr)
{
    int i;
    int hit = 0;
    if (addr == NULL) {
        return 0;
    }

    /* 置所有匹配 addr 的槽标志 */
    for (i = 0; i < SIM_WAKE_SLOTS; ++i) {
        if (g_wake_slots[i].addr == addr) {
            g_wake_slots[i].flag = 1;
            hit = 1;
        }
    }
    /* 无匹配则占用一个空槽 */
    if (!hit) {
        for (i = 0; i < SIM_WAKE_SLOTS; ++i) {
            if (g_wake_slots[i].addr == NULL) {
                g_wake_slots[i].addr = addr;
                g_wake_slots[i].flag = 1;
                break;
            }
        }
    }
    return 0;
}
