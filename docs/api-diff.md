# Windows 7 / Windows 10 API 差异文档

> 用途：为 Win7Bridge 兼容层提供 Win7 API 基线、Win10 新增 API、以及两者差异的参考。  
> 信息来源：Microsoft Learn（docs/learn.microsoft.com）、Windows SDK 文档，关键来源见文末。  
> NT 版本：Windows 7 = 6.1（Build 7601 SP1），Windows 10 = 10.0（Build 10240~19045）。

---

## 0. 摘要（TL;DR）

Win10 软件在 Win7 上失败的根本原因可归为三类：

1. **加载期断裂**：UCRT 缺失、API Set 虚拟解析缺失、PE 子系统版本过高、WinRT API set 完全不存在 → 进程根本起不来。
2. **运行期断裂**：单个导出函数缺失（`GetSystemTimePreciseAsFileTime`、`WaitOnAddress`、`SetThreadDescription` 等）→ 启动后调用即崩。
3. **语义差异**：版本查询 API 行为变化、CNG 新算法缺失、DPI 新 API 缺失 → 程序误判环境或功能降级。

**易误判点**（必须纠正）：SRWLock、Condition Variable、`GetTickCount64`、ThreadPool API、D3D11、CNG BCrypt 基础算法 **均自 Vista 起已有，Win7 完整支持**，不是 Win10 新增。

---

## 1. Windows 7 API 基线

### 1.1 版本信息

| 项 | 值 |
|---|---|
| NT 版本 | 6.1 |
| RTM Build | 7600.16385 |
| SP1 Build | 7601.17514 |
| PE 子系统版本 | 6.01 |
| 内核 | `ntoskrnl.exe` |

### 1.2 核心系统 DLL

| DLL | 职责 | 备注 |
|---|---|---|
| `ntdll.dll` | 用户态↔内核，NT API、PE 装载器、堆 | `LdrLoadDll`、`NtCreateFile`、`RtlAllocateHeap` |
| `kernel32.dll` | 经典 Win32 封装 | Win7 起多数转发到 `KernelBase.dll` |
| `KernelBase.dll` | MinWin 实现层 | **Win7 引入**，承载 kernel32 真实实现 |
| `user32.dll` | 窗口/消息/输入 | — |
| `gdi32.dll` | GDI | Win10 拆出 `gdi32full.dll`/`win32u.dll`，Win7 无 |
| `advapi32.dll` | 安全/注册表/服务 | 部分转发到 `sechost.dll` |
| `shell32.dll` | Shell 命名空间 | — |
| `ole32.dll` | COM 运行时 | Win10 引入 `combase.dll`，Win7 无 |
| `comctl32.dll` | 通用控件 v6 | 经 SxS 清单加载 |
| `ws2_32.dll` | Winsock 2 | — |
| `crypt32.dll`/`bcrypt.dll` | CAPI/CNG | CNG 自 Vista 起已有 |

### 1.3 系统调用机制

- **x86**：`ntdll!Nt*` 存根 `mov eax,SSN; mov edx,esp; call fs:[0C0h]` → `KiFastSystemCall` → `sysenter` → 内核 `KiFastCallEntry`。
- **x64**：`mov r10,rcx; mov eax,SSN; syscall` → 内核 `KiSystemCall64`。
- **WoW64**：32 位进程经 `wow64cpu!KiFastSystemCall`（TurboThunk）切到 64 位再 `syscall`。
- SSN（系统服务号）跨版本不同；hook 应针对 `ntdll!Nt*` 函数本身，不硬编码 SSN。

### 1.4 DLL 搜索顺序（SafeDllSearchMode 默认开启）

1. DLL 重定向（`.local`） 2. API Set 3. SxS 清单 4. 已加载模块 5. KnownDLLs 6. EXE 目录 7. System32 8. System 9. Windows 目录 10. 当前目录 11. PATH

### 1.5 句柄上限

| 资源 | 每进程上限 | 系统上限 |
|---|---|---|
| GDI 句柄 | 10,000 | 65,535/session |
| USER 句柄 | 10,000 | 65,535/session |
| 内核句柄 | ~16M | 受分页池制约 |

可通过注册表 `GDIProcessHandleQuota`/`USERProcessHandleQuota` 调到 65536。

### 1.6 Win7 已具备（勿误判为 Win10 新增）

- SRW Lock（`InitializeSRWLock` 等）— Vista 起
- Condition Variable（`InitializeConditionVariable` 等）— Vista 起
- `InitOnceExecuteOnce` — Vista 起
- `GetTickCount64` — Vista 起
- ThreadPool API（`CreateThreadpool`/`SubmitThreadpoolWork` 等）— Vista 起
- Direct3D 11 — Win7 原生
- CNG BCrypt 基础算法（AES、SHA-1/256、RSA、ECDH/ECDSA）— Vista 起
- `VirtualAllocEx`、`MapViewOfFileNuma` — Vista 起

### 1.7 用户态 hook 能力

Win7 无 CFG（Control Flow Guard），用户态 hook 更容易：
- IAT hook、EAT hook、inline hook（trampoline，Detours/MinHook）、VEH hook。
- `apphelp.dll` + SDB shim 机制（ACT）证明用户态 API 转译可行。

### 1.8 运行时库支持

| 运行时 | Win7 RTM | Win7 SP1 |
|---|---|---|
| VC++ 2005~2013 | ✅ | ✅ |
| VC++ 2015~2022（v14.x） | ❌ 需 UCRT | ✅ 需 KB2999226 + KB3118401 |
| .NET 2.0~4.0 | ✅ | ✅ |
| .NET 4.5~4.8 | ❌ | ✅ 需 SP1 |
| .NET Core 3.1 / .NET 5/6 | ❌ | ✅ 需 SP1 + VC++ 2019 + KB3063858 |
| .NET 7+ | ❌ | ❌ 不官方支持 |

---

## 2. Windows 10 相对 Win7 的关键差异

### 2.1 NT 版本与 Build

| 系统 | NT 版本 | Build 范围 |
|---|---|---|
| Win7 / 2008 R2 | 6.1 | 7600~7601 |
| Win8 / 2012 | 6.2 | 9200 |
| Win8.1 / 2012 R2 | 6.3 | 9600 |
| Win10 1507 | 10.0 | 10240 |
| Win10 1607 | 10.0 | 14393 |
| Win10 1809 | 10.0 | 17763 |
| Win10 1903 | 10.0 | 18362 |
| Win10 2004 | 10.0 | 19041 |
| Win10 22H2 | 10.0 | 19045 |
| Win11 22H2 | 10.0 | 22621 |

### 2.2 kernel32 → kernelbase 转发

Win7 起引入 MinWin：`kernel32.dll` 多数导出变为转发器，真实实现在 `KernelBase.dll`。  
**不可把 Win10 的 kernelbase 拷到 Win7**（版本强绑定，结构差异巨大）。hook 应针对 `KernelBase.dll` 而非 `kernel32.dll` 入口。

### 2.3 API Set 虚拟解析（核心断裂）

- API Set 名（`api-ms-win-*`、`ext-ms-win-*`）是虚拟别名，非磁盘文件。
- 加载器查 PEB→`ApiSetMap`（数据来自 `apisetschema.dll`）解析到真实宿主 DLL。
- 名称规范：`api-` 前缀=所有版本存在；`ext-` 前缀=部分版本；`l1-1-N` 后缀=版本号，N 越大越新。

| 维度 | Win7（无 KB） | Win7 SP1+KB2999226 | Win10 |
|---|---|---|---|
| ApiSetSchema 版本 | v2（极小） | v4 左右 | v6+ |
| `api-ms-win-core-*` 数量 | ~50 | ~200 | 数百 |
| `api-ms-win-crt-*` | 不存在 | UCRT 包齐全 | 原生 |
| `api-ms-win-core-winrt-*` | 不存在 | 不存在 | 原生 |
| `api-ms-win-core-memory-l1-1-3+` | 不存在 | 不存在 | 原生 |

**关键**：把 API set DLL 文件复制到 Win7 系统目录无效——Win7 的 `ApiSetMap` 不包含这些条目，加载器仍找不到。必须修改 `apisetschema.dll` 或在加载器层拦截。

### 2.4 PE 子系统版本（加载期硬阻断）

- 现代 VS 默认 `MajorSubsystemVersion`=6.2/6.3/10.0。
- Win7 加载器要求 `MajorSubsystemVersion` ≤ 6.1，否则报"不是有效的 Win32 应用程序"（0xC000007B）。
- 修复：链接器 `/SUBSYSTEM:WINDOWS,6.01`，或运行时改写 PE OptionalHeader。

### 2.5 单函数级缺失 API（可模拟）

| API | 引入版本 | Win7 替代 |
|---|---|---|
| `GetSystemTimePreciseAsFileTime` | Win8 | 回退 `GetSystemTimeAsFileTime`（~15.6ms 精度） |
| `WaitOnAddress`/`WakeByAddressSingle`/`WakeByAddressAll` | Win8 | 事件对象+自旋模拟 |
| `VirtualAlloc2`/`VirtualAlloc2FromApp` | Win10 1607 | 退化为 `VirtualAlloc`（丢失占位符语义） |
| `MapViewOfFileNuma2`/`UnmapViewOfFileEx` | Win10 1703 | 退化为 `MapViewOfFile` |
| `SetThreadDescription`/`GetThreadDescription` | Win10 1607 | TLS 槽存储或 no-op |
| `CreatePseudoConsole`/`ClosePseudoConsole`/`ResizePseudoConsole` | Win10 1809 | 管道+控制台缓冲模拟 |
| `SetProcessDpiAwarenessContext` | Win10 1607 | 回退 `SetProcessDPIAware` |
| `EnableMouseInPointer` | Win8 | 回退到鼠标 |

### 2.6 版本查询 API 行为变化

- Win8.1 起 `GetVersion`/`GetVersionEx` 被弃用，受 manifest 约束：未声明支持 Win8.1+ 则返回 6.2。
- Win10 起 `VerifyVersionInfo` 同样受 manifest 约束。
- Win7 上这些 API 返回真实 6.1。
- `RtlGetVersion` 不受 manifest 影响，始终返回真实版本——hook 需覆盖。
- Win10 程序自检"≥Win10"在 Win7 上会失败并退出。

### 2.7 supportedOS GUID

| GUID | 系统 |
|---|---|
| `{e2011457-1546-43c5-a5fe-008deee3d3f0}` | Vista |
| `{35138b9a-5d96-4fbd-8e2d-a2440225f93a}` | **Win7** |
| `{4a2f28e3-53b9-4441-ba9c-d69d4a4a6e38}` | Win8 |
| `{1f676c76-80e1-4239-95bb-83d0f6d0da78}` | Win8.1 |
| `{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}` | **Win10/11** |

Win11 无独立 GUID，复用 Win10 的。

### 2.8 UCRT 断裂（最常见崩溃源）

- VS2015 起 CRT 重构为 Universal CRT（`ucrtbase.dll` + `api-ms-win-crt-*`）。
- Win10 系统原生；Win7 需 **SP1 + KB2999226**（UCRT 10.0.10240）+ **KB3118401**（10.0.14393）。
- VCRedist 2015-2022 关键 DLL：`vcruntime140.dll`、`vcruntime140_1.dll`（VS2019+，F-Security 栈保护）、`msvcp140.dll`。
- Win10 软件在裸 Win7 失败模式：`ucrtbase.dll not found` / `0xc0000135` / `api-ms-win-crt-runtime-l1-1-0.dll not found`。

### 2.9 CNG 算法差异

Win7 已有：AES、SHA-1/256/384/512、RSA、ECDH/ECDSA（P-256/384/521）、DH、DSA、AES-GCM。  
Win7 缺失（Win10+）：
- `AES-CMAC`（Win8+）
- `ChaCha20-Poly1305`（Win10+）
- `HKDF`（Win10+）
- `BCRYPT_KEY_DERIVATION_FUNCTION` 体系（Win10+）
- SHA-3 系列（CSHAKE/KMAC，Win11 24H2+）

兼容层需自带 ChaCha20-Poly1305 与 HKDF 实现，或回退 AES-GCM。

### 2.10 DirectX / DXGI

| API | 最低系统 | Win7 状态 |
|---|---|---|
| D3D9/9Ex | XP/Vista | ✅ |
| D3D10/10.1 | Vista | ✅ |
| DXGI 1.0/1.1 | Vista | ✅ |
| **D3D11** | **Win7** | **✅ 原生** |
| D3D11.1 / DXGI 1.2 | Win8 | Win7+KB2670838 部分支持 |
| **D3D12** | **Win10** | **❌ 完全不存在**（D3D12On7 仅 Steam 游戏可用） |

### 2.11 WinRT / UWP（不可解）

Win7 完全不存在，加载期即失败：

| API Set / DLL | 关键导出 |
|---|---|
| `api-ms-win-core-winrt-l1-1-0.dll` | `RoInitialize`/`RoActivateInstance`/`RoGetActivationFactory` |
| `api-ms-win-core-winrt-string-l1-1-0.dll` | `WindowsCreateString` 等 HSTRING |
| `combase.dll` | COM/WinRT 实现（Win8 引入） |
| `winrtbase.dll` | WinRT 核心（Win10 引入） |

---

## 3. Win10 软件在 Win7 失败原因汇总

### 3.1 加载期失败（进程起不来）

| 原因 | 表现 | 可否兼容 |
|---|---|---|
| 缺 UCRT | `ucrtbase.dll not found` / 0xc0000135 | ✅ 装 KB2999226 |
| 缺 `api-ms-win-crt-*` | 0xc0000135 | ✅ KB2999226 |
| 缺 `api-ms-win-core-winrt-*` | 找不到 DLL | ❌ 不可解 |
| 缺 `api-ms-win-core-memory-l1-1-3+` | 0xc0000135 | ❌ 需加载器拦截 |
| PE `MajorSubsystemVersion`>6.1 | "不是有效的 Win32 应用程序" 0xC000007B | ✅ 改 PE 头 |
| 缺 `vcruntime140.dll`/`msvcp140.dll` | 启动即崩 | ✅ 装 VCRedist |

### 3.2 运行期失败（启动后崩溃）

| 原因 | 表现 | 可否兼容 |
|---|---|---|
| `GetSystemTimePreciseAsFileTime` 缺失 | "无法定位程序输入点" | ✅ Forwarder/回退 |
| `WaitOnAddress` 缺失 | 调用时崩 | ✅ 事件模拟 |
| `VirtualAlloc2` 缺失 | 返回 NULL 崩 | ⚠ 退化为 VirtualAlloc |
| `SetThreadDescription` 缺失 | 调试信息丢失 | ✅ no-op/TLS |
| BCrypt ChaCha20/HKDF | STATUS_NOT_SUPPORTED | ⚠ 自带实现 |
| `RoActivateInstance`/WinRT | 崩溃 | ❌ 不可解 |
| `VerifyVersionInfo` 检查"≥Win10"失败 | 自检退出 | ✅ 拦截伪装 |
| D3D12 调用 | d3d12.dll 找不到 | ❌ 不可解（除 D3D12On7） |

---

## 4. 兼容层设计启示

1. **必做**：UCRT 兜底（提示装 KB2999226）、PE 头修正、Manifest 改写、版本 API 拦截、关键缺失函数 Forwarder、API Set 虚拟化。
2. **不可解**：WinRT/UWP、D3D12（无 D3D12On7）、VBS/SGX2/TPM2.0 attestation。
3. **难解**：`VirtualAlloc2` 占位符语义、Win10 文件系统新特性、Modern Shell API。

---

## 5. 参考资料

- Windows API sets：https://learn.microsoft.com/en-us/windows/win32/apiindex/windows-apisets
- API set loader operation：https://learn.microsoft.com/en-us/windows/win32/apiindex/api-set-loader-operation
- Windows version check：https://learn.microsoft.com/zh-cn/windows/win32/w8cookbook/windows-version-check
- Application manifests（supportedOS）：https://learn.microsoft.com/en-us/windows/win32/sbscs/application-manifests
- GetSystemTimePreciseAsFileTime：https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/nf-sysinfoapi-getsystemtimepreciseasfiletime
- VirtualAlloc2：https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc2
- MapViewOfFileNuma2：https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-mapviewoffilenuma2
- CreatePseudoConsole：https://learn.microsoft.com/en-us/windows/console/createpseudoconsole
- Universal CRT deployment：https://learn.microsoft.com/zh-cn/cpp/windows/universal-crt-deployment
- KB2999226（UCRT）：https://support.microsoft.com/topic/update-for-universal-c-runtime-in-windows-c0514201-7fe6-95a3-b0a5-287930f3560c
- VC++ Redistributable：https://learn.microsoft.com/en-us/cpp/windows/latest-supported-vc-redist
- CNG Algorithm Identifiers：https://learn.microsoft.com/en-us/windows/win32/seccng/cng-algorithm-identifiers
- PE Format：https://learn.microsoft.com/en-us/windows/win32/debug/pe-format
- D3D12onWin7：https://microsoft.github.io/DirectX-Specs/d3d/D3D12onWin7.html
- Dynamic-link library search order：https://learn.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order
- Slim Reader/Writer Locks：https://learn.microsoft.com/en-us/windows/win32/Sync/slim-reader-writer--srw--locks
- Condition Variables：https://learn.microsoft.com/en-us/windows/win32/Sync/condition-variables
