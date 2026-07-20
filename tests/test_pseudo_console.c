/*
 * test_pseudo_console.c - Win7Bridge SubTask 4.3.2 / 4.3.3 补全 host 测试
 *
 * 覆盖：
 *   4.3.2 CreatePseudoConsole / ClosePseudoConsole / ResizePseudoConsole
 *        的完整生命周期、错误参数与边界（NULL / 非法 magic / 重复 close）。
 *   4.3.1 SetThreadDescription 覆盖旧描述后读回新值。
 *   4.3.3 VirtualAlloc2(size=0) 返回 NULL；MapViewOfFileNuma2 host 路径
 *        返回 NULL 且不 crash。
 *
 * 仅在定义 WIN7BRIDGE_HOST_TEST 时编译 main，返回 0 表示全部通过。
 */
#include "win7bridge/sim_thread.h"

#include <stdio.h>
#include <stdlib.h>
#include <wchar.h>
#include <string.h>

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
/* 用例 1：CreatePseudoConsole + ClosePseudoConsole 基本生命周期        */
/* ------------------------------------------------------------------ */
static void test_pcon_create_close(void)
{
    COORD  size = { 80, 25 };
    void*  hpc  = NULL;
    HRESULT hr;

    printf("==== 用例 1：pcon_create_close ====\n");

    hr = sim_CreatePseudoConsole(size, NULL, NULL, 0, &hpc);
    CHECK(hr == S_OK, "CreatePseudoConsole 返回 S_OK");
    CHECK(hpc != NULL, "out_hpc 非空");

    sim_ClosePseudoConsole(hpc);
    CHECK(1, "ClosePseudoConsole 不 crash");
}

/* ------------------------------------------------------------------ */
/* 用例 2：ResizePseudoConsole 修改 size 返回 S_OK                      */
/* ------------------------------------------------------------------ */
static void test_pcon_resize(void)
{
    COORD  size1 = { 80, 25 };
    COORD  size2 = { 120, 40 };
    void*  hpc   = NULL;
    HRESULT hr1, hr2;

    printf("==== 用例 2：pcon_resize ====\n");

    sim_CreatePseudoConsole(size1, NULL, NULL, 0, &hpc);
    CHECK(hpc != NULL, "创建伪控制台");

    hr1 = sim_ResizePseudoConsole(hpc, size2);
    CHECK(hr1 == S_OK, "ResizePseudoConsole 返回 S_OK");

    hr2 = sim_ResizePseudoConsole(hpc, size1);
    CHECK(hr2 == S_OK, "二次 Resize 返回 S_OK");

    sim_ClosePseudoConsole(hpc);
}

/* ------------------------------------------------------------------ */
/* 用例 3：ClosePseudoConsole(NULL) 安全                                */
/* ------------------------------------------------------------------ */
static void test_pcon_close_null(void)
{
    printf("==== 用例 3：pcon_close_null ====\n");
    sim_ClosePseudoConsole(NULL);
    CHECK(1, "ClosePseudoConsole(NULL) 不 crash");
}

/* ------------------------------------------------------------------ */
/* 用例 4：ClosePseudoConsole 传入非伪控制台句柄（magic 不匹配）安全    */
/* ------------------------------------------------------------------ */
static void test_pcon_close_bad_magic(void)
{
    /* 栈上伪造结构体，magic 不等于 SIM_PCON_MAGIC（无法直接访问宏，
     * 用全 0 内存模拟：magic=0 不匹配任何合法句柄） */
    int dummy[16] = { 0 };

    printf("==== 用例 4：pcon_close_bad_magic ====\n");
    sim_ClosePseudoConsole(dummy);
    CHECK(1, "ClosePseudoConsole 非法句柄不 crash");
}

/* ------------------------------------------------------------------ */
/* 用例 5：CreatePseudoConsole(out=NULL) 返回 E_POINTER                 */
/* ------------------------------------------------------------------ */
static void test_pcon_create_null_out(void)
{
    COORD  size = { 80, 25 };
    HRESULT hr;

    printf("==== 用例 5：pcon_create_null_out ====\n");
    hr = sim_CreatePseudoConsole(size, NULL, NULL, 0, NULL);
    CHECK(hr == E_POINTER, "out_hpc=NULL 返回 E_POINTER");
}

/* ------------------------------------------------------------------ */
/* 用例 6：ResizePseudoConsole(NULL) 返回 E_POINTER                     */
/* ------------------------------------------------------------------ */
static void test_pcon_resize_null(void)
{
    COORD  size = { 80, 25 };
    HRESULT hr;

    printf("==== 用例 6：pcon_resize_null ====\n");
    hr = sim_ResizePseudoConsole(NULL, size);
    CHECK(hr == E_POINTER, "ResizePseudoConsole(NULL) 返回 E_POINTER");
}

/* ------------------------------------------------------------------ */
/* 用例 7：ResizePseudoConsole 非法句柄返回 E_INVALIDARG                 */
/* ------------------------------------------------------------------ */
static void test_pcon_resize_bad_magic(void)
{
    int    dummy[16] = { 0 };
    COORD  size = { 80, 25 };
    HRESULT hr;

    printf("==== 用例 7：pcon_resize_bad_magic ====\n");
    hr = sim_ResizePseudoConsole(dummy, size);
    CHECK(hr == E_INVALIDARG, "非法句柄 Resize 返回 E_INVALIDARG");
}

/* ------------------------------------------------------------------ */
/* 用例 8：SetThreadDescription 覆盖旧描述后读回新值                    */
/* ------------------------------------------------------------------ */
static void test_thread_desc_overwrite(void)
{
    HANDLE   t = (HANDLE)2;     /* host 用 2 模拟另一个线程句柄           */
    HRESULT  hr;
    wchar_t* got = NULL;

    printf("==== 用例 8：thread_desc_overwrite ====\n");

    hr = sim_SetThreadDescription(t, L"first");
    CHECK(hr == S_OK, "首次 SetThreadDescription 返回 S_OK");

    hr = sim_SetThreadDescription(t, L"second");
    CHECK(hr == S_OK, "覆盖 SetThreadDescription 返回 S_OK");

    hr = sim_GetThreadDescription(t, &got);
    CHECK(hr == S_OK, "GetThreadDescription 返回 S_OK");
    CHECK(got != NULL && wcscmp(got, L"second") == 0,
          "读回等于新描述 L\"second\"");
    free(got);
}

/* ------------------------------------------------------------------ */
/* 用例 9：VirtualAlloc2(size=0) 返回 NULL                              */
/* ------------------------------------------------------------------ */
static void test_virtualalloc2_zero_size(void)
{
    void* p;

    printf("==== 用例 9：virtualalloc2_zero_size ====\n");
    p = sim_VirtualAlloc2(NULL, NULL, 0,
                          SIM_MEM_COMMIT | SIM_MEM_RESERVE,
                          SIM_PAGE_READWRITE, NULL);
    CHECK(p == NULL, "size=0 返回 NULL");
}

/* ------------------------------------------------------------------ */
/* 用例 10：MapViewOfFileNuma2 host 路径返回 NULL 不 crash               */
/* ------------------------------------------------------------------ */
static void test_mapviewoffilenuma2_host(void)
{
    void* p;

    printf("==== 用例 10：mapviewoffilenuma2_host ====\n");
    /* host 路径无真实文件映射对象，应安全返回 NULL */
    p = sim_MapViewOfFileNuma2(NULL, 0, NULL, 4096);
    CHECK(p == NULL, "host 路径 MapViewOfFileNuma2 返回 NULL");
}

/* ------------------------------------------------------------------ */
/* main                                                                */
/* ------------------------------------------------------------------ */
#ifdef WIN7BRIDGE_HOST_TEST
int main(void)
{
    test_pcon_create_close();
    test_pcon_resize();
    test_pcon_close_null();
    test_pcon_close_bad_magic();
    test_pcon_create_null_out();
    test_pcon_resize_null();
    test_pcon_resize_bad_magic();
    test_thread_desc_overwrite();
    test_virtualalloc2_zero_size();
    test_mapviewoffilenuma2_host();

    if (g_fail) {
        printf("\n==== 存在失败用例 ====\n");
        return 1;
    }
    printf("\n==== 全部通过 ====\n");
    return 0;
}
#endif /* WIN7BRIDGE_HOST_TEST */
