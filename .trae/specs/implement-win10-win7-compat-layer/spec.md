# Win10→Win7 兼容层软件（暂名 Win7Bridge）Spec

> 本规范基于对 Windows 7 API、Windows 10 API 差异、以及 VxKex 现状缺陷的系统性研究制定。研究结论已内化为本规范的需求与约束。

## Why

VxKex 是当前唯一让 Win10 软件运行于 Win7 的纯用户态兼容层，但实战体验差：机制粗糙（仅整 DLL 重定向、无单函数级 patching、不覆盖 `GetProcAddress` 动态解析路径）、注入路径（IFEO `VerifierDlls`）副作用大（被反调试检测、与沙箱冲突、被杀软误报）、维护断档（原作者删号、单人接力、冒名仓库信任危机）、缺乏测试基线。大量 Qt6/Electron 之外的应用（游戏、浏览器新版、Steam、反作弊程序）跑不起来或残缺。

我们需要一款**在 VxKex 路线之外、纯软件层、可逆、更细粒度**的兼容层，让更多 Win10 软件能在 Win7 SP1 上稳定运行。

## 约束（硬性，不可违反）

- **禁止内核模式**：不写驱动、不改 `ntoskrnl.exe` / `ci.dll` / `winload`。
- **禁止修改操作系统文件**：不替换 `system32`/`syswow64` 下的系统 DLL（不走 Extended Kernel 路线）。
- **仅在软件层面工作**：全部逻辑在目标进程用户态地址空间内运行。
- **完全可逆**：可按程序粒度一键启用/关闭；卸载后系统无残留。
- **开发环境**：本地 Python 3.8 + GCC（C 语言主体可用 GCC/MinGW 编译；Windows API 头与链接库用 MinGW-w64 或 Windows SDK）。
- **目标系统**：Windows 7 SP1（x86 与 x64），含 WoW64。

## 研究基础（关键结论摘要）

### A. Win7 API 基线（NT 6.1，Build 7601）
- 核心系统 DLL：`ntdll`、`kernel32`、`KernelBase`（Win7 引入 MinWin 分层）、`user32`、`gdi32`、`advapi32`、`shell32`、`ole32`、`comctl32`（v6 经 SxS）、`ws2_32`、`crypt32`/`bcrypt`（CNG 自 Vista 起已有）。
- 系统调用：x86 `sysenter`（`KiFastSystemCall`），x64 `syscall`（`KiSystemCall64`）；WoW64 经 `wow64cpu` 转译。SSN 与 Win10 不同。
- 句柄上限：GDI/USER 各 10,000/进程（可调注册表到 65536）。
- 已具备（勿误判为 Win10 新增）：SRWLock、Condition Variable、InitOnceExecuteOnce、GetTickCount64、ThreadPool API（Vista 起）、D3D11、CNG BCrypt 基础算法。
- 用户态 hook 能力齐全：IAT hook、inline hook（Detours/MinHook）、EAT hook、VEH hook，Win7 无 CFG，hook 更易。
- 兼容性框架：`apphelp.dll` + SDB shim 机制（ACT），证明用户态 API 转译可行。

### B. Win10 相对 Win7 的关键断裂（决定兼容层工作量）
1. **UCRT 断裂**：Win10 自带 `ucrtbase.dll` + `api-ms-win-crt-*`；Win7 需 KB2999226（SP1 前置）+ KB3118401。这是 Win10 软件在裸 Win7 上最常见的崩溃源。
2. **API Set（`api-ms-win-*`）虚拟解析**：Win7 仅有 v2 极简 schema；Win10 有 v6+ 数百条目。Win7 加载器不解析新 API set → `STATUS_DLL_NOT_FOUND`。`api-ms-win-core-winrt-*`、`api-ms-win-core-memory-l1-1-3+` 等在 Win7 完全不存在。
3. **PE 子系统版本**：现代 VS 默认 `MajorSubsystemVersion=6.2/6.3/10.0`，Win7 加载器要求 ≤6.1，否则报"不是有效的 Win32 应用程序"。
4. **WinRT/UWP**：`RoInitialize`/`RoActivateInstance`/HSTRING 等，Win7 完全无对应实现，加载期即失败，**不可解**。
5. **单函数级缺失**（可模拟）：
   - `GetSystemTimePreciseAsFileTime`（Win8+）→ 回退 `GetSystemTimeAsFileTime`
   - `WaitOnAddress`/`WakeByAddress*`（Win8+）→ 事件模拟
   - `VirtualAlloc2`/`MapViewOfFileNuma2`（Win10）→ 退化为 `VirtualAlloc`（丢失占位符语义）
   - `SetThreadDescription`/`GetThreadDescription`（Win10）→ TLS 槽或 no-op
   - `CreatePseudoConsole`（ConPTY, Win10 1809）→ 管道+控制台缓冲模拟
   - `WaitOnAddress` 系列、DPI 新 API（`SetProcessDpiAwarenessContext`）→ 回退
6. **版本查询 API 行为变化**：Win8.1+ 起 `GetVersionEx` 受 manifest 约束返回 6.2；Win10 起 `VerifyVersionInfo` 同理。Win7 上这些 API 返回真实 6.1。Win10 程序自检"≥Win10"会失败拒绝运行。
7. **不可解项**：Direct3D 12（无 D3D12On7 包时）、WinRT/UWP 契约、依赖硬件特性（VBS/SGX2/TPM2.0 attestation）。
8. **CNG 算法**：Win7 缺 ChaCha20-Poly1305、HKDF（Win10+），需自带实现或回退 AES-GCM。

### C. VxKex 现状与缺陷（设计对照）
- **机制**：纯用户态，IFEO `VerifierDlls` 注入 `VxKexLdr.dll`，**遍历导入表一次，整 DLL 重定向**到自带扩展 DLL；不触碰内核、不改系统文件、可逆、按程序粒度。
- **缺陷（须规避）**：
  1. 仅整 DLL 重定向，无单函数 patching；不覆盖 `GetProcAddress` 动态解析路径（游戏/反作弊失败根因）。
  2. 不能 patch EXE 本身，不能做便携 EXE，依赖 `HKLM` 注册表。
  3. `VerifierDlls` 注入触发反调试检测（Synthesizer V 等）、与 Sandboxie 冲突、被杀软误报。
  4. 32 位长期不稳定（1.1.2 才修 BEX 崩溃）；环境敏感（`%Path%` 非标准即全失败）。
  5. README 自述不支持游戏；Firefox 需降级、Edge 不可用、Chrome 不能更新、Steam 托盘/黑屏/大屏卡顿。
  6. DX12/WinRT/.NET Core 3.1+ 不支持或有限。
  7. 维护断档、单人接力、冒名仓库信任危机、无可重复构建、无自动化测试矩阵。

## What Changes

构建一款新的 Win10→Win7 兼容层软件 **Win7Bridge**，核心交付：

- **L0 PE 修正器**：扫描目标 PE，修正 `MajorSubsystemVersion`/`MajorOperatingSystemVersion` ≤ 6.1；strip bound import 强制走 IAT 解析；按需改写 manifest（注入 Win7 supportedOS GUID，剥离 Win10-only 元素）。
- **L1 符号级重写引擎（核心创新）**：三层粒度——① 整 DLL 转发；② 单导出替换/forward/stub；③ 运行时 IAT/inline hook（覆盖 `GetProcAddress`/`LdrGetProcedureAddress` 动态路径）。这是相对 VxKex 最大的结构性改进。
- **L2 API Set 虚拟解析层**：维护一张可配置"虚拟名 → 实现源"映射表（借鉴 One-Core-API），而非把每个 `api-ms-win-*` 当独立 DLL；优先 forward 到 Win7 真实 DLL，缺失项由 L3 提供。
- **L3 缺失 API 模拟层**：本地实现 `GetSystemTimePreciseAsFileTime`、`WaitOnAddress` 系列、`SetThreadDescription`、`CreatePseudoConsole`、DPI 回退、CNG 新算法等。
- **L4 版本伪装层**：统一 hook `GetVersionEx`/`GetVersion`/`RtlGetVersion`/`RtlGetNtVersionNumbers`/`VerifyVersionInfo`，返回伪装 Win10 版本号。
- **多注入路径（规避 VerifierDlls）**：默认 **Loader 程序**（创建挂起进程、内存 patch、resume），可选 PE 永久 patch、AppInit_DLLs 兜底；IFEO VerifierDlls 仅作兼容旧路径并显式标注风险。
- **配置与诊断**：按程序粒度配置 GUI + 右键属性页；自动从导入表/manifest 推荐兼容选项；细粒度日志 + 一键诊断报告（依赖缺失树、被拦截 API、反调试触发点）。
- **UCRT 前置检测**：启动时检查 KB2999226/KB3118401/VCRedist，缺失则提示安装（不把 UCRT 责任揽给自己，继承 VxKex 正确做法）。
- **双架构**：同时提供 x86 与 x64 版本，分别注入对应进程。

## Impact

- **新建项目**：无既有代码受影响，全新仓库。
- **依赖前置**：用户须自行安装 Win7 SP1 + KB2999226 + KB3118401 + VCRedist 2015-2022（兼容层仅检测与提示，不分发）。
- **参考研究文档**：Win7/Win10 API 差异与 VxKex 缺陷分析已内化为本规范"研究基础"章节；详细 API 清单见各模块实现任务。
- **不可解边界（须在 UI 显式标注）**：依赖 WinRT/UWP、Direct3D12（无 D3D12On7）、VBS/SGX2/TPM2.0 attestation 的程序不支持。

## ADDED Requirements

### Requirement: 符号级 API 重写引擎
系统 SHALL 提供三层粒度的 API 重写能力：整 DLL 转发、单导出替换/forward/stub、运行时 IAT/inline hook（覆盖 `GetProcAddress` 与 `LdrGetProcedureAddress` 动态解析路径）。

#### Scenario: 程序静态导入 Win7 缺失导出
- **WHEN** 目标程序静态导入 `kernel32!SetThreadDescription`
- **THEN** 重写引擎将该导入指向兼容层的本地实现，程序正常调用，不报"无法定位程序输入点"

#### Scenario: 程序运行时动态解析新 API
- **WHEN** 程序调用 `GetProcAddress(GetModuleHandle("kernel32"), "SetThreadDescription")`
- **THEN** hook 的 `GetProcAddress` 返回兼容层本地实现地址，程序获得非 NULL 指针并可调用

### Requirement: 多注入路径与可逆性
系统 SHALL 提供至少三种注入路径并默认使用不触发反调试检测的 Loader 程序模式；所有模式 MUST 可一键关闭且卸载无残留。

#### Scenario: 默认 Loader 模式不触发反调试
- **WHEN** 用户用 Loader 模式启动一个含反调试检测的 Win10 程序
- **THEN** 程序不检测到 Verifier/Debugger 标志，正常启动运行

#### Scenario: 关闭兼容后无残留
- **WHEN** 用户为某程序关闭兼容层或卸载兼容层
- **THEN** 该程序恢复直接启动，注册表与系统目录无兼容层残留

### Requirement: PE 修正
系统 SHALL 在加载目标 PE 前修正 `MajorSubsystemVersion`/`MajorOperatingSystemVersion` ≤ 6.1，并 strip bound import 强制 IAT 解析。

#### Scenario: 子系统版本过高的程序
- **WHEN** 目标 PE 的 `MajorSubsystemVersion` 为 6.2/6.3/10.0
- **THEN** 加载前修正为 6.1，程序不再报"不是有效的 Win32 应用程序"

### Requirement: API Set 虚拟解析
系统 SHALL 提供可配置的 `api-ms-win-*`/`ext-ms-win-*` 虚拟名到实现源的映射表，优先转发到 Win7 真实 DLL，缺失项由本地模拟层提供。

#### Scenario: 程序导入 Win7 缺失的 API set
- **WHEN** 程序导入 `api-ms-win-core-synch-l1-2-0.dll`（WaitOnAddress 体系）
- **THEN** 映射表将其解析到兼容层提供的 `WaitOnAddress` 等本地实现，程序正常加载

### Requirement: 版本伪装
系统 SHALL 统一 hook `GetVersionEx`/`GetVersion`/`RtlGetVersion`/`RtlGetNtVersionNumbers`/`VerifyVersionInfo`，使目标程序"以为运行在 Win10"。

#### Scenario: 程序自检 Win10 版本
- **WHEN** 程序调用 `VerifyVersionInfo` 检查"≥ Win10"
- **THEN** 返回 TRUE，程序继续运行而非退出

### Requirement: 缺失 API 模拟
系统 SHALL 本地实现以下 Win7 缺失 API 并提供合理回退：`GetSystemTimePreciseAsFileTime`、`WaitOnAddress`/`WakeByAddressSingle`/`WakeByAddressAll`、`SetThreadDescription`/`GetThreadDescription`、`CreatePseudoConsole`/`ClosePseudoConsole`/`ResizePseudoConsole`、DPI 新 API 回退、CNG ChaCha20-Poly1305/HKDF。

#### Scenario: 调用高精度时间 API
- **WHEN** 程序调用 `GetSystemTimePreciseAsFileTime`
- **THEN** 返回当前时间（精度回退至 `GetSystemTimeAsFileTime` 的 ~15.6ms，但函数可用不崩溃）

### Requirement: UCRT 前置检测
系统 SHALL 在启动目标程序前检测 KB2999226/KB3118401/VCRedist 是否已安装，缺失时提示用户安装而非静默失败。

#### Scenario: UCRT 未安装
- **WHEN** Win7 系统未安装 KB2999226
- **THEN** 兼容层提示用户安装 UCRT 更新，不尝试自行注入 UCRT

### Requirement: 不可解项显式标注
系统 SHALL 在配置 UI 中对依赖 WinRT/UWP、Direct3D 12、VBS/SGX2/TPM2.0 attestation 的程序显式标注"不支持"，避免用户无效尝试。

## MODIFIED Requirements

（本项目为全新构建，无既有需求修改。）

## REMOVED Requirements

（无移除项。明确不走 Extended Kernel 路线：不替换系统 `kernel32.dll`/`ntdll.dll` 等系统二进制，不写驱动，不改 `apisetschema.dll`。）
