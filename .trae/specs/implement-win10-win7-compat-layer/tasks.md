# Tasks

> 任务编号约定：T{阶段}.{序号}。阶段：1=基础设施 / 2=核心引擎 / 3=注入与配置 / 4=模拟层 / 5=测试与发布。  
> 标注 [P] 表示可并行，[D:Tx] 表示依赖 Tx。  
> 全部 C 代码须同时构建 x86 与 x64 两版。

## 阶段 1：基础设施与开发文档

- [x] Task 1.1: 编写开发文档骨架 [P]
  - [x] SubTask 1.1.1: 在仓库根创建 `docs/dev-guide.md`，含章节：目标与范围、环境前置、架构分层（L0-L4）、API 拦截清单（加载期/运行期两表）、不可解项清单、回退策略、安全约束、测试矩阵
  - [x] SubTask 1.1.2: 在 `docs/api-diff.md` 固化 Win7/Win10 API 差异表（UCRT、API Set、PE 子系统、WinRT、单函数缺失、版本查询、CNG 算法），来源标注 Microsoft Learn URL
  - [x] SubTask 1.1.3: 在 `docs/vxkex-lessons.md` 固化 VxKex 缺陷与规避策略清单
- [x] Task 1.2: 搭建构建系统 [P]
  - [x] SubTask 1.2.1: 用 GCC/MinGW-w64 建立构建脚本（Makefile 或 CMakeLists），支持 x86/x64 双架构输出
  - [x] SubTask 1.2.2: 配置 Windows SDK 头/库（PE 结构、ntdll 内部）的最小可用集，验证能在 Win7 目标上编译
  - [x] SubTask 1.2.3: 建立 Python 3.8 辅助脚本目录（PE 扫描、配置生成、诊断报告解析等非运行时工具）

## 阶段 2：核心引擎（L0-L2）

- [x] Task 2.1: PE 解析与修正器（L0）[D:1.2]
  - [x] SubTask 2.1.1: 实现 PE 解析器：OptionalHeader、Import Directory、Bound Import、Delay-Load、Export Directory、Resource（RT_MANIFEST）
  - [x] SubTask 2.1.2: 实现子系统版本修正：`MajorSubsystemVersion`/`MajorOperatingSystemVersion` > 6.1 时改为 6.1
  - [x] SubTask 2.1.3: 实现 bound import strip：将 `IMAGE_BOUND_IMPORT_DESCRIPTOR` 的 `TimeDateStamp` 置 0，强制 IAT 解析
  - [x] SubTask 2.1.4: 实现 manifest 改写：注入 Win7 supportedOS GUID `{35138b9a-...}`，剥离 `maxversiontested`/`msix` 等 Win10-only 元素
  - [x] SubTask 2.1.5: 验证：用一个 `MajorSubsystemVersion=10.0` 的测试 EXE，修正后能在 Win7 加载器下不再报 0xC000007B
- [x] Task 2.2: 符号级重写引擎（L1，核心）[D:2.1]
  - [x] SubTask 2.2.1: 实现整 DLL 转发层：导入表改写，把对指定 DLL 的整体导入指向兼容层转发 DLL
  - [x] SubTask 2.2.2: 实现单导出粒度：保留原 DLL 多数导出，仅替换/forward/stub 指定导出
  - [x] SubTask 2.2.3: 实现运行时 IAT hook：对已加载模块的 IAT 做延迟改写
  - [x] SubTask 2.2.4: 实现 inline hook 基础设施（trampoline，x86 5 字节 / x64 14 字节，处理指令重定位）
  - [x] SubTask 2.2.5: hook `GetProcAddress` 与 `LdrGetProcedureAddress`，对查询 Win10 新 API 的请求返回兼容层实现（覆盖 VxKex 最大短板）
  - [x] SubTask 2.2.6: 验证：测试程序通过 `GetProcAddress` 拿到 `SetThreadDescription` 并调用成功
- [ ] Task 2.3: API Set 虚拟解析层（L2）[D:2.2]
  - [x] SubTask 2.3.1: 设计并实现"虚拟名 → 实现源"映射表配置格式（JSON 或 INI），覆盖 `api-ms-win-core-*`、`api-ms-win-crt-*`、`ext-ms-win-*`
  - [x] SubTask 2.3.2: 实现解析逻辑：导入表出现 `api-ms-win-*` 名时查表，转发到 Win7 真实 DLL 或本地模拟层
  - [x] SubTask 2.3.3: 预置映射表初版：含 `api-ms-win-core-synch-l1-2-0`、`api-ms-win-core-timezone-l1-1-0`、`api-ms-win-core-memory-l1-1-3+`、`api-ms-win-core-winrt-*`（标注不可解）等
  - [x] SubTask 2.3.4: 验证：测试程序导入 `api-ms-win-core-synch-l1-2-0.dll` 能正常解析到 `WaitOnAddress` 本地实现

## 阶段 3：注入路径与配置

- [ ] Task 3.1: Loader 程序注入（默认路径）[D:2.2]
  - [ ] SubTask 3.1.1: 实现 `CreateProcessW` 以 `CREATE_SUSPENDED` 创建挂起进程
  - [ ] SubTask 3.1.2: 实现注入兼容层 DLL 到挂起进程（`VirtualAllocEx`+`WriteProcessMemory`+`QueueUserAPC`/`CreateRemoteThread` 调 `LoadLibrary`）
  - [ ] SubTask 3.1.3: 兼容层 DLL 在注入后执行：PE 修正、IAT 改写、hook 安装，然后 `ResumeThread`
  - [ ] SubTask 3.1.4: 验证：Loader 启动的进程不被反调试检测（`IsDebuggerPresent`/`NtQueryInformationProcess(ProcessDebugPort)` 返回正常值）
- [ ] Task 3.2: PE 永久 patch 模式（可选路径）[P,D:2.1]
  - [ ] SubTask 3.2.1: 实现离线 PE patch 工具：修改目标 EXE 导入表后落盘，生成"已 patch EXE"
  - [ ] SubTask 3.2.2: 验证：patch 后的 EXE 在 Win7 上直接双击运行（携带兼容层 DLL）
- [ ] Task 3.3: AppInit_DLLs 与 IFEO VerifierDlls 兜底（可选路径，标注风险）[P]
  - [ ] SubTask 3.3.1: 实现注册表注入路径，UI 显式标注"会触发反调试检测/与沙箱冲突"
  - [ ] SubTask 3.3.2: 实现卸载时清理注册表条目，保证可逆
- [ ] Task 3.4: 配置 GUI 与右键属性页 [D:3.1]
  - [x] SubTask 3.4.1: 实现按程序粒度配置存储（配置文件，不写 HKLM 系统键）
  - [ ] SubTask 3.4.2: 实现资源管理器右键属性页 Shell 扩展（启用/关闭、选择注入路径、版本伪装选项）
  - [x] SubTask 3.4.3: 实现自动推荐：扫描目标 EXE 导入表/manifest，自动推断需要的兼容选项
  - [ ] SubTask 3.4.4: 在 UI 对 WinRT/UWP/D3D12/VBS/TPM2.0 依赖程序显式标注"不支持"

## 阶段 4：模拟层（L3-L4）

- [ ] Task 4.1: 版本伪装层（L4）[P,D:2.2]
  - [ ] SubTask 4.1.1: hook `GetVersion`/`GetVersionEx`/`RtlGetVersion`/`RtlGetNtVersionNumbers` 返回伪装 Win10 版本号
  - [ ] SubTask 4.1.2: hook `VerifyVersionInfo` 对"≥ Win10"查询返回 TRUE
  - [ ] SubTask 4.1.3: 验证：`IsWindows10OrGreater` 类 helper 返回 TRUE
- [ ] Task 4.2: 时间与同步 API 模拟 [P,D:2.2]
  - [ ] SubTask 4.2.1: 实现 `GetSystemTimePreciseAsFileTime` 回退 `GetSystemTimeAsFileTime`
  - [ ] SubTask 4.2.2: 实现 `WaitOnAddress`/`WakeByAddressSingle`/`WakeByAddressAll` 用事件对象模拟
  - [ ] SubTask 4.2.3: 验证：无锁代码（如自旋等待）在 Win7 上工作
- [ ] Task 4.3: 线程与控制台 API 模拟 [P,D:2.2]
  - [ ] SubTask 4.3.1: 实现 `SetThreadDescription`/`GetThreadDescription` 用 TLS 槽存储
  - [ ] SubTask 4.3.2: 实现 `CreatePseudoConsole`/`ClosePseudoConsole`/`ResizePseudoConsole` 用管道+控制台缓冲模拟
  - [ ] SubTask 4.3.3: 实现 `VirtualAlloc2`/`MapViewOfFileNuma2` 退化为 `VirtualAlloc`/`MapViewOfFile`（接受占位符语义丢失）
- [ ] Task 4.4: DPI 与 Shell API 回退 [P,D:2.2]
  - [ ] SubTask 4.4.1: `SetProcessDpiAwarenessContext` 回退到 `SetProcessDPIAware`
  - [ ] SubTask 4.4.2: 其他 DPI 新 API 提供 no-op 或合理回退
- [x] Task 4.5: CNG 新算法本地实现 [P,D:2.2]
  - [x] SubTask 4.5.1: 本地实现 ChaCha20-Poly1305（或集成可用开源实现，注意许可证）
  - [x] SubTask 4.5.2: 本地实现 HKDF
  - [x] SubTask 4.5.3: 在 BCrypt provider 层暴露这些算法，使 `BCryptOpenAlgorithmProvider("CHACHA20_POLY1305")` 可用
- [ ] Task 4.6: UCRT 前置检测 [P,D:3.4]
  - [ ] SubTask 4.6.1: 检测 `ucrtbase.dll` 是否存在于系统目录（KB2999226）
  - [ ] SubTask 4.6.2: 检测 `vcruntime140.dll`/`msvcp140.dll`（VCRedist）
  - [ ] SubTask 4.6.3: 缺失时弹窗提示用户安装对应 KB/VCRedist，不尝试自行注入 UCRT

## 阶段 5：测试、诊断与发布

- [ ] Task 5.1: 细粒度日志与诊断报告 [D:4.*]
  - [x] SubTask 5.1.1: 实现日志记录：被拦截的 API、缺失导出查询、反调试触发点、版本伪装命中
  - [x] SubTask 5.1.2: 实现"一键导出诊断报告"（依赖缺失树、调用流摘要）
- [ ] Task 5.2: 兼容性测试矩阵 [D:5.1]
  - [x] SubTask 5.2.1: 建立测试用例集：含高子系统版本 EXE、导入 `api-ms-win-core-synch-l1-2-0` 的 EXE、`GetProcAddress` 动态解析新 API 的 EXE、自检 Win10 版本的 EXE
  - [ ] SubTask 5.2.2: 在真实 Win7 SP1 + KB 环境验证每个用例
  - [ ] SubTask 5.2.3: 建立"已知可运行/不可运行应用"清单（参考 VxKex 的 Application Compatibility List）
- [ ] Task 5.3: 可重复构建与签名 [D:5.2]
  - [ ] SubTask 5.3.1: 确保源码可产出与 release 字节一致的二进制（消除冒名仓库风险）
  - [ ] SubTask 5.3.2: 用代码签名证书签署 release（缓解杀软误报）
  - [ ] SubTask 5.3.3: 撰写用户安装与使用文档

# Task Dependencies
- Task 1.1, 1.2 无依赖，可并行启动
- Task 2.1 依赖 1.2（构建系统）
- Task 2.2 依赖 2.1（PE 解析）
- Task 2.3 依赖 2.2（重写引擎）
- Task 3.1 依赖 2.2；3.2、3.3 可与 3.1 并行
- Task 3.4 依赖 3.1
- Task 4.1-4.6 均依赖 2.2，彼此可并行
- Task 5.1 依赖阶段 4；5.2 依赖 5.1；5.3 依赖 5.2
