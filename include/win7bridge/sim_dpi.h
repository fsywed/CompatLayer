/*
 * sim_dpi.h - Win7Bridge L3 DPI 感知 API 回退接口
 *
 * 对应 docs/api-diff.md §2.5：Win10 1607 引入 SetProcessDpiAwarenessContext，
 * Win7 仅有 SetProcessDPIAware（系统级 DPI 感知）。本模块在新 API 不可用
 * 时回退到 SetProcessDPIAware；GetDpiForWindow 回退到系统 DPI。
 *
 * 不依赖 <windows.h>；类型复用 sim_thread.h（BOOL/HRESULT）。
 */
#ifndef WIN7BRIDGE_SIM_DPI_H
#define WIN7BRIDGE_SIM_DPI_H

#include "win7bridge/sim_thread.h"  /* BOOL, HRESULT */
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef _WIN7BRIDGE_UINT_DEFINED
typedef uint32_t UINT;              /* Win32 UINT                         */
#define _WIN7BRIDGE_UINT_DEFINED
#endif

/* 回退 SetProcessDPIAware；成功返回 TRUE。value 为 DPI_AWARENESS_CONTEXT。*/
BOOL sim_SetProcessDpiAwarenessContext(int value);

/* 回退 SetProcessDPIAware；成功返回 S_OK。value 为 PROCESS_DPI_AWARENESS。*/
HRESULT sim_SetProcessDpiAwareness(int value);

/* 返回窗口 DPI；host 下返回系统 DPI 96。                              */
UINT sim_GetDpiForWindow(void* hwnd);

#ifdef __cplusplus
}
#endif

#endif /* WIN7BRIDGE_SIM_DPI_H */
