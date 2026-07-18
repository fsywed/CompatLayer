# Win7Bridge 开发文档

> 本文档遵循"先简洁明了，再分点展开"原则，作为 Win7Bridge 兼容层的开发总纲。  
> 配套文档：[api-diff.md](./api-diff.md)（Win7/Win10 API 差异）、[vxkex-lessons.md](./vxkex-lessons.md)（VxKex 缺陷与规避）。

---

## 1. 目标与范围

### 简述
构建一款纯用户态、可逆的 Win10→Win7 兼容层，让更多 Win10 软件在 Win7 SP1 上运行，规避 VxKex 的结构性缺陷。

### 分点展开
- **目标系统**：Windows 7 SP1（x86 + x64，含 WoW64）。
- **支持范围**：控制台/GUI 应用、Qt6/Electron 系、部分 .NET 应用。
- **不支持（UI 显式标注）**：WinRT/UWP、Direct3D 12（无 D3D12On7）、VBS/SGX2/TPM2.0 attestation、反作弊游戏。
- **硬约束**：禁止内核模式、禁止修改系统文件、仅在软件层、完全可逆。

## 2. 环境前置

### 简述
用户须预装 UCRT 与 VCRedist；开发用 GCC/MinGW-w64 + Python 3.8+。

### 分点展开
- **用户侧**（兼容层仅检测提示，不分发）：
  - Windows 7 SP1
  - KB2999226（UCRT 10.0.10240）+ KB3118401（UCRT 10.0.14393）
  - VCRedist 2015-2022（`vcruntime140.dll`/`msvcp140.dll`）
  - 可选 KB2533623、KB2670838（Platform Update）
- **开发侧**：
  - GCC/MinGW-w64（x86 + x64 交叉编译）
  - Python 3.8+（PE 扫描、配置生成、诊断报告解析等非运行时工具）
  - Windows SDK 头/库（PE 结构、ntdll 内部）最小集

## 3. 架构分层（L0-L4）

### 简述
五层架构：L0 PE 修正 → L1 符号级重写 → L2 API Set 解析 → L3 缺失 API 模拟 → L4 版本伪装。

### 分点展开

#### L0 PE 修正器
- 修正 `MajorSubsystemVersion`/`MajorOperatingSystemVersion` ≤ 6.1。
- strip bound import（`TimeDateStamp` 置 0）强制 IAT 解析。
- manifest 改写：注入 Win7 supportedOS GUID，剥离 `maxversiontested`/`msix` 等 Win10-only 元素。

#### L1 符号级重写引擎（核心创新，对照 VxKex 最大短板）
- 三层粒度：
  1. **整 DLL 转发**：导入表改写，整体指向兼容层转发 DLL。
  2. **单导出粒度**：保留原 DLL 多数导出，仅替换/forward/stub 指定导出。
  3. **运行时 IAT/inline hook**：覆盖 `GetProcAddress`/`LdrGetProcedureAddress` 动态解析路径。
- inline hook trampoline：x86 5 字节 / x64 14 字节，处理指令重定位。

#### L2 API Set 虚拟解析层
- 可配置"虚拟名 → 实现源"映射表（JSON/INI）。
- 优先 forward 到 Win7 真实 DLL，缺失项由 L3 提供。
- `api-ms-win-core-winrt-*` 等标注不可解。

#### L3 缺失 API 模拟层
- 时间：`GetSystemTimePreciseAsFileTime` → 回退 `GetSystemTimeAsFileTime`。
- 同步：`WaitOnAddress` 系列 → 事件对象模拟。
- 线程：`SetThreadDescription` → TLS 槽。
- 控制台：`CreatePseudoConsole` 系列 → 管道+缓冲模拟。
- 内存：`VirtualAlloc2`/`MapViewOfFileNuma2` → 退化为 `VirtualAlloc`/`MapViewOfFile`。
- DPI：`SetProcessDpiAwarenessContext` → 回退 `SetProcessDPIAware`。
- CNG：ChaCha20-Poly1305、HKDF 本地实现。

#### L4 版本伪装层
- 统一 hook `GetVersion`/`GetVersionEx`/`RtlGetVersion`/`RtlGetNtVersionNumbers`/`VerifyVersionInfo`。
- 返回伪装 Win10 版本号，使 `IsWindows10OrGreater` 返回 TRUE。

## 4. 注入路径

### 简述
默认 Loader 程序（不触发反调试），可选 PE 永久 patch、AppInit_DLLs/IFEO 兜底。

### 分点展开
- **默认：Loader 程序** — `CreateProcessW(CREATE_SUSPENDED)` → 注入兼容层 DLL → DLL 内执行 L0-L4 安装 → `ResumeThread`。不触发 Verifier/Debugger 标志。
- **可选：PE 永久 patch** — 离线修改 EXE 导入表后落盘，生成便携 EXE。
- **兜底：AppInit_DLLs / IFEO VerifierDlls** — UI 显式标注"会触发反调试检测/与沙箱冲突"。
- 所有模式一键关闭，卸载无残留。

## 5. API 拦截清单

### 5.1 加载期（L0/L2，导入表/manifest 改写）

| 拦截对象 | 处理 |
|---|---|
| PE `MajorSubsystemVersion`>6.1 | 修正为 6.1 |
| Bound Import | strip 强制 IAT 解析 |
| manifest | 注入 Win7 GUID，剥离 Win10-only 元素 |
| `api-ms-win-core-synch-l1-2-0` 等 | 映射表转发到 L3 实现 |
| `api-ms-win-core-winrt-*` | 标注不可解 |
| 静态导入缺失导出 | 整 DLL 转发或单导出替换 |

### 5.2 运行期（L1/L3/L4，hook）

| 拦截 API | 处理 |
|---|---|
| `GetProcAddress`/`LdrGetProcedureAddress` | 查询新 API 返回本地实现 |
| `GetVersion`/`GetVersionEx`/`RtlGetVersion`/`RtlGetNtVersionNumbers` | 返回伪装 Win10 版本 |
| `VerifyVersionInfo` | "≥Win10"返回 TRUE |
| `GetSystemTimePreciseAsFileTime` | 回退 `GetSystemTimeAsFileTime` |
| `WaitOnAddress`/`WakeByAddress*` | 事件模拟 |
| `SetThreadDescription`/`GetThreadDescription` | TLS 槽 |
| `CreatePseudoConsole` 系列 | 管道+缓冲模拟 |
| `VirtualAlloc2`/`MapViewOfFileNuma2` | 退化为 VirtualAlloc/MapViewOfFile |
| `SetProcessDpiAwarenessContext` | 回退 `SetProcessDPIAware` |
| BCrypt ChaCha20/HKDF | 本地实现 |

## 6. 不可解项清单

- WinRT / UWP（`RoInitialize`/`RoActivateInstance`/HSTRING）
- Direct3D 12（无 D3D12On7 包）
- VBS / SGX2 / TPM2.0 attestation
- `VirtualAlloc2` 占位符/替换语义（仅能退化，语义丢失）

## 7. 回退策略

每个拦截 API 必须有 fallback 与日志：
- 优先 forward 到 Win7 真实实现。
- 次选本地模拟（接受精度/语义损失）。
- 兜底 no-op stub + 日志记录。
- 不可解项返回一致 `E_NOTIMPL` 并 UI 标注。

## 8. 安全约束

- 不写驱动、不改 `ntoskrnl`/`ci.dll`/`winload`。
- 不替换 `system32`/`syswow64` 系统 DLL。
- 不改 `apisetschema.dll`。
- 配置不写 HKLM 系统键（用配置文件）。
- 卸载清理所有注册表条目与目录。
- 代码签名 release，缓解杀软误报。

## 9. 测试矩阵

| 用例 | 期望 |
|---|---|
| `MajorSubsystemVersion=10.0` 的 EXE | 修正后在 Win7 加载，不报 0xC000007B |
| 导入 `api-ms-win-core-synch-l1-2-0.dll` 的 EXE | 解析到本地 `WaitOnAddress` |
| `GetProcAddress("kernel32","SetThreadDescription")` | 返回非 NULL 且可调用 |
| `VerifyVersionInfo` 检查"≥Win10" | 返回 TRUE |
| 含反调试检测的程序（Loader 模式） | 不检测到 Verifier/Debugger |
| `GetSystemTimePreciseAsFileTime` 调用 | 返回时间不崩溃 |
| 卸载后 | 程序恢复直接启动，无残留 |

测试在真实 Win7 SP1 + KB 环境验证；建立"已知可运行/不可运行应用"清单。

## 10. 工程规范

- 主体 C 语言，MinGW-w64 编译，x86/x64 双架构。
- Python 3.8+ 用于非运行时辅助工具（PE 扫描、配置生成、诊断解析）。
- 可重复构建（源码产出与 release 字节一致）。
- 提交前快速语法检查，确保能编译。
- 代码须符合本开发文档要求。
