/*
 * test_spin_wait.c - Win7Bridge SubTask 4.2.3 验证
 *
 * 验证 sim_WaitOnAddress + sim_WakeByAddress* 能支撑"无锁代码自旋等待"
 * 模式：
 *     while (*addr == compare) {
 *         if (WaitOnAddress(addr, &compare, size, timeout) == WAIT_OBJECT_0)
 *             break;
 *     }
 *
 * 在不引入 pthread 依赖的前提下，覆盖以下边界：
 *   1) spin_wait_exit      —— 预先 wake，spin-wait 循环应在第 1 次迭代退出
 *   2) spin_wait_timeout   —— 无 wake + timeout=20ms 循环 3 次，每次 WAIT_TIMEOUT
 *   3) wake_once_consumed  —— 唤醒标志被首次 WaitOnAddress 消费后，第二次 0
 *                              超时调用应返回 WAIT_TIMEOUT（避免虚假唤醒）
 *   4) size_variants       —— size=1/2/4/8 且 addr!=compare 时立即 WAIT_OBJECT_0
 *   5) invalid_params      —— NULL addr / NULL compare / 非法 size 返回
 *                              ERROR_INVALID_PARAMETER(87)
 *
 * 仅在定义 WIN7BRIDGE_HOST_TEST 时编译 main，用原生 gcc 运行。
 */
#include "win7bridge/sim_time.h"

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

/* ------------------------------------------------------------------ */
/* 简单断言                                                            */
/* ------------------------------------------------------------------ */
static int g_fail = 0;
#define CHECK(cond, msg)                                                  \
    do {                                                                  \
        if (!(cond)) {                                                    \
            printf("[FAIL] %s:%d %s\n", __FILE__, __LINE__, (msg));       \
            g_fail = 1;                                                   \
        } else {                                                          \
            printf("[ok]   %s\n", (msg));                                 \
        }                                                                 \
    } while (0)

/* ------------------------------------------------------------------ */
/* 辅助：取 CLOCK_MONOTONIC 毫秒时间戳                                 */
/* ------------------------------------------------------------------ */
static long long now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (long long)ts.tv_sec * 1000LL + (long long)(ts.tv_nsec / 1000000L);
}

/* ------------------------------------------------------------------ */
/* 用例 1：spin_wait_exit                                              */
/*   预先 WakeByAddressSingle 设置唤醒标志，再进入 spin-wait 循环。    */
/*   循环应在第 1 次迭代退出（迭代次数==1）。                          */
/* ------------------------------------------------------------------ */
static void test_spin_wait_exit(void)
{
    volatile int val = 5;
    int          compare = 5;   /* 与 val 相等 -> 触发 WaitOnAddress 等待 */
    int          iter = 0;
    int          rc;
    int          i;

    printf("==== 用例 1：spin_wait_exit ====\n");

    /* 预先设置唤醒标志 */
    sim_WakeByAddressSingle((void*)&val);

    /* spin-wait：最多迭代 5 次（防止失控） */
    for (i = 0; i < 5; ++i) {
        ++iter;
        rc = sim_WaitOnAddress((volatile void*)&val, (void*)&compare,
                               (SIZE_T)sizeof(int), 0);
        if (rc == WAIT_OBJECT_0) {
            break;
        }
    }
    CHECK(iter == 1, "spin-wait 在第 1 次迭代退出");
    CHECK(rc == WAIT_OBJECT_0, "最终返回 WAIT_OBJECT_0");
}

/* ------------------------------------------------------------------ */
/* 用例 2：spin_wait_timeout                                           */
/*   无 wake + timeout=20ms 循环 3 次，总耗时 >= 60ms，每次 WAIT_TIMEOUT */
/* ------------------------------------------------------------------ */
static void test_spin_wait_timeout(void)
{
    volatile int val = 7;
    int          compare = 7;
    int          rc;
    int          i;
    long long    t0, t1;
    int          timeouts = 0;

    printf("==== 用例 2：spin_wait_timeout ====\n");

    t0 = now_ms();
    for (i = 0; i < 3; ++i) {
        rc = sim_WaitOnAddress((volatile void*)&val, (void*)&compare,
                               (SIZE_T)sizeof(int), 20);
        if (rc == WAIT_TIMEOUT) {
            ++timeouts;
        } else {
            printf("[FAIL] 第 %d 次迭代期望 WAIT_TIMEOUT(258)，实际 %d\n",
                   i + 1, rc);
            g_fail = 1;
        }
    }
    t1 = now_ms();

    CHECK(timeouts == 3, "3 次迭代均返回 WAIT_TIMEOUT");
    CHECK((t1 - t0) >= 60, "总耗时 >= 60ms（实际测量避免假通过）");
}

/* ------------------------------------------------------------------ */
/* 用例 3：wake_once_consumed                                          */
/*   WakeByAddressSingle 设置唤醒标志后：                              */
/*     - 第一次 0 超时 WaitOnAddress 应返回 WAIT_OBJECT_0（消费标志） */
/*     - 第二次 0 超时 WaitOnAddress 应返回 WAIT_TIMEOUT（标志已消费）*/
/*   这验证唤醒标志不会被重复命中（避免虚假唤醒）。                    */
/* ------------------------------------------------------------------ */
static void test_wake_once_consumed(void)
{
    volatile int val = 9;
    int          compare = 9;
    int          rc1, rc2;

    printf("==== 用例 3：wake_once_consumed ====\n");

    sim_WakeByAddressSingle((void*)&val);

    rc1 = sim_WaitOnAddress((volatile void*)&val, (void*)&compare,
                            (SIZE_T)sizeof(int), 0);
    CHECK(rc1 == WAIT_OBJECT_0, "第一次 WaitOnAddress 返回 WAIT_OBJECT_0");

    rc2 = sim_WaitOnAddress((volatile void*)&val, (void*)&compare,
                            (SIZE_T)sizeof(int), 0);
    CHECK(rc2 == WAIT_TIMEOUT, "第二次 WaitOnAddress 返回 WAIT_TIMEOUT（标志已消费）");
}

/* ------------------------------------------------------------------ */
/* 用例 4：size_variants                                               */
/*   size=1/2/4/8 且 addr != compare 时立即返回 WAIT_OBJECT_0。       */
/*   覆盖 WaitOnAddress 文档允许的所有 size 取值。                     */
/* ------------------------------------------------------------------ */
static void test_size_variants(void)
{
    uint8_t  v8  = 0xAA;
    uint8_t  c8  = 0x55;
    uint16_t v16 = 0x1234;
    uint16_t c16 = 0x5678;
    uint32_t v32 = 0xDEADBEEFu;
    uint32_t c32 = 0xCAFEBABEu;
    uint64_t v64 = 0x0123456789ABCDEFuLL;
    uint64_t c64 = 0xFEDCBA9876543210uLL;
    int      rc;

    printf("==== 用例 4：size_variants ====\n");

    rc = sim_WaitOnAddress((volatile void*)&v8, (void*)&c8,
                           (SIZE_T)sizeof(v8), 100);
    CHECK(rc == WAIT_OBJECT_0, "size=1 立即返回 WAIT_OBJECT_0");

    rc = sim_WaitOnAddress((volatile void*)&v16, (void*)&c16,
                           (SIZE_T)sizeof(v16), 100);
    CHECK(rc == WAIT_OBJECT_0, "size=2 立即返回 WAIT_OBJECT_0");

    rc = sim_WaitOnAddress((volatile void*)&v32, (void*)&c32,
                           (SIZE_T)sizeof(v32), 100);
    CHECK(rc == WAIT_OBJECT_0, "size=4 立即返回 WAIT_OBJECT_0");

    rc = sim_WaitOnAddress((volatile void*)&v64, (void*)&c64,
                           (SIZE_T)sizeof(v64), 100);
    CHECK(rc == WAIT_OBJECT_0, "size=8 立即返回 WAIT_OBJECT_0");
}

/* ------------------------------------------------------------------ */
/* 用例 5：invalid_params                                              */
/*   NULL addr / NULL compare / size∈{0,3,16} 返回                    */
/*   ERROR_INVALID_PARAMETER(87)。                                     */
/* ------------------------------------------------------------------ */
static void test_invalid_params(void)
{
    volatile int val = 1;
    int          compare = 1;
    int          rc;

    printf("==== 用例 5：invalid_params ====\n");

    rc = sim_WaitOnAddress(NULL, (void*)&compare,
                           (SIZE_T)sizeof(int), 100);
    CHECK(rc == ERROR_INVALID_PARAMETER, "NULL addr 返回 87");

    rc = sim_WaitOnAddress((volatile void*)&val, NULL,
                           (SIZE_T)sizeof(int), 100);
    CHECK(rc == ERROR_INVALID_PARAMETER, "NULL compare 返回 87");

    rc = sim_WaitOnAddress((volatile void*)&val, (void*)&compare,
                           (SIZE_T)0, 100);
    CHECK(rc == ERROR_INVALID_PARAMETER, "size=0 返回 87");

    rc = sim_WaitOnAddress((volatile void*)&val, (void*)&compare,
                           (SIZE_T)3, 100);
    CHECK(rc == ERROR_INVALID_PARAMETER, "size=3 返回 87");

    rc = sim_WaitOnAddress((volatile void*)&val, (void*)&compare,
                           (SIZE_T)16, 100);
    CHECK(rc == ERROR_INVALID_PARAMETER, "size=16 返回 87");
}

/* ------------------------------------------------------------------ */
/* main                                                                */
/* ------------------------------------------------------------------ */
#ifdef WIN7BRIDGE_HOST_TEST
int main(void)
{
    test_spin_wait_exit();
    test_spin_wait_timeout();
    test_wake_once_consumed();
    test_size_variants();
    test_invalid_params();

    if (g_fail) {
        printf("\n==== 存在失败用例 ====\n");
        return 1;
    }
    printf("\n==== 全部通过 ====\n");
    return 0;
}
#endif /* WIN7BRIDGE_HOST_TEST */
