/*
 * sim_dpi.c - Win7Bridge L3 DPI 感知 API 回退实现
 *
 * 对应 docs/api-diff.md §2.5：SetProcessDpiAwarenessContext（Win10 1607）
 * 在 Win7 回退为 SetProcessDPIAware（系统级 DPI 感知）；GetDpiForWindow
 * 回退到系统 DPI（Win7 无逐显示器 DPI，常用 96）。
 *
 * host 测试：固定返回成功与系统 DPI 96。
 * Windows：用真实 SetProcessDPIAware / GetDeviceCaps（已在 windows.h 声明）。
 */
#include "win7bridge/sim_dpi.h"

/* 系统默认 DPI（Win7 无逐显示器 DPI，标准值 96）                      */
#define SIM_SYSTEM_DPI 96

/* GetDeviceCaps 索引：LOGPIXELSX = 88（取水平方向每逻辑英寸像素数）    */
#define SIM_LOGPIXELSX 88

BOOL sim_SetProcessDpiAwarenessContext(int value)
{
    (void)value;   /* DPI_AWARENESS_CONTEXT 值在回退路径下忽略            */

#if defined(_WIN32) && !defined(WIN7BRIDGE_HOST_TEST)
    /* Win7 真机：SetProcessDPIAware 已由 windows.h 声明，直接调用       */
    return SetProcessDPIAware() ? TRUE : FALSE;
#else
    /* host：固定成功                                                  */
    return TRUE;
#endif
}

HRESULT sim_SetProcessDpiAwareness(int value)
{
    (void)value;   /* PROCESS_DPI_AWARENESS 值在回退路径下忽略            */

#if defined(_WIN32) && !defined(WIN7BRIDGE_HOST_TEST)
    return SetProcessDPIAware() ? S_OK : E_FAIL;
#else
    /* host：固定成功                                                  */
    return S_OK;
#endif
}

UINT sim_GetDpiForWindow(void* hwnd)
{
    (void)hwnd;

#if defined(_WIN32) && !defined(WIN7BRIDGE_HOST_TEST)
    /* Win7 真机：GetDC/ReleaseDC/GetDeviceCaps 已由 windows.h 声明       */
    HDC hdc = GetDC((HWND)hwnd);
    if (hdc != NULL) {
        int dpi = GetDeviceCaps(hdc, SIM_LOGPIXELSX);
        ReleaseDC((HWND)hwnd, hdc);
        return (UINT)dpi;
    }
    return SIM_SYSTEM_DPI;
#else
    /* host：返回系统 DPI 96                                           */
    return SIM_SYSTEM_DPI;
#endif
}

/* ------------------------------------------------------------------ */
/* SubTask 4.4.2：其他 DPI 新 API no-op / 合理回退                     */
/* ------------------------------------------------------------------ */

UINT sim_GetDpiForSystem(void)
{
#if defined(_WIN32) && !defined(WIN7BRIDGE_HOST_TEST)
    HDC hdc = GetDC(NULL);
    if (hdc != NULL) {
        int dpi = GetDeviceCaps(hdc, SIM_LOGPIXELSX);
        ReleaseDC(NULL, hdc);
        return (UINT)dpi;
    }
    return SIM_SYSTEM_DPI;
#else
    /* host：固定 96                                                   */
    return SIM_SYSTEM_DPI;
#endif
}

HRESULT sim_GetDpiForMonitor(void* hmonitor, int dpi_type,
                              UINT* dpi_x, UINT* dpi_y)
{
    (void)hmonitor;   /* 回退路径无法按监视器区分，统一返回系统 DPI     */
    (void)dpi_type;

    if (dpi_x == NULL || dpi_y == NULL) {
        return E_POINTER;
    }
#if defined(_WIN32) && !defined(WIN7BRIDGE_HOST_TEST)
    HDC hdc = GetDC(NULL);
    if (hdc != NULL) {
        int dpi = GetDeviceCaps(hdc, SIM_LOGPIXELSX);
        ReleaseDC(NULL, hdc);
        *dpi_x = (UINT)dpi;
        *dpi_y = (UINT)dpi;
        return S_OK;
    }
#endif
    *dpi_x = SIM_SYSTEM_DPI;
    *dpi_y = SIM_SYSTEM_DPI;
    return S_OK;
}

int sim_GetSystemMetricsForDpi(int index, UINT dpi)
{
    (void)dpi;   /* 回退实现丢失 DPI 维度，仅按系统度量返回            */

#if defined(_WIN32) && !defined(WIN7BRIDGE_HOST_TEST)
    /* Win7 真机：GetSystemMetrics 已由 windows.h 声明                   */
    return GetSystemMetrics(index);
#else
    /* host：对常见索引返回 0，调用方应容忍语义缺失                    */
    (void)index;
    return 0;
#endif
}

BOOL sim_EnableNonClientDpiScaling(void* hwnd)
{
    (void)hwnd;   /* Win7 无此 API，回退为 no-op 成功                  */
    return TRUE;
}
