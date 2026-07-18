/*
 * windows.h - 垫片，重定向到 fake_windows.h
 *
 * 用法：gcc -D_WIN32 -isystem tools/win_check 时，
 *   #include <windows.h> 会找到本文件，进而包含 fake_windows.h 的桩实现。
 * 真实 Windows 编译时 SDK 的 windows.h 优先级更高（-isystem 最低）。
 */
#ifndef WIN7BRIDGE_FAKE_WINDOWS_SHIM_H
#define WIN7BRIDGE_FAKE_WINDOWS_SHIM_H
#include "fake_windows.h"
#endif
