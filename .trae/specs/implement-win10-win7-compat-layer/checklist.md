# Checklist

## 约束合规性
- [ ] 全部代码不使用内核模式（无驱动、不改 ntoskrnl/ci.dll/winload）
- [ ] 不替换 system32/syswow64 下任何系统 DLL
- [ ] 全部逻辑在目标进程用户态地址空间运行
- [ ] 所有注入路径可一键关闭，卸载后注册表与系统目录无残留
- [ ] 同时提供 x86 与 x64 构建产物
- [ ] 主体 C 代码可用本地 GCC/MinGW-w64 编译通过

## 研究文档（Task 1.1）
- [x] docs/dev-guide.md 含规定章节（目标/前置/分层/拦截清单/不可解项/回退/安全/测试矩阵）
- [x] docs/api-diff.md 固化 Win7/Win10 差异表并标注 Microsoft Learn 来源 URL
- [x] docs/vxkex-lessons.md 固化 VxKex 缺陷与规避策略清单

## PE 修正器（L0，Task 2.1）
- [x] PE 解析器能正确读取 Import/Bound Import/Delay-Load/Export/Resource 目录
- [x] `MajorSubsystemVersion`=6.2/6.3/10.0 的 EXE 修正为 6.1 后能在 Win7 加载
- [x] bound import strip 后强制走 IAT 解析（不报绑定导入错误）
- [x] manifest 改写注入 Win7 GUID 且剥离 Win10-only 元素

## 符号级重写引擎（L1，Task 2.2）
- [x] 整 DLL 转发层工作正常
- [x] 单导出粒度替换/forward/stub 工作正常
- [x] 运行时 IAT hook 工作
- [x] inline hook trampoline 在 x86/x64 均正确（含指令重定位）
- [x] hook `GetProcAddress`/`LdrGetProcedureAddress` 覆盖动态解析路径
- [x] 测试程序通过 `GetProcAddress("kernel32","SetThreadDescription")` 拿到非 NULL 且可调用

## API Set 虚拟解析（L2，Task 2.3）
- [ ] "虚拟名 → 实现源"映射表可配置
- [ ] 导入 `api-ms-win-core-synch-l1-2-0.dll` 解析到本地 `WaitOnAddress` 实现
- [ ] `api-ms-win-core-winrt-*` 在映射表中标注不可解

## 注入路径（Task 3.1-3.3）
- [ ] Loader 程序默认路径：CREATE_SUSPENDED + 注入 + Resume
- [ ] Loader 模式启动的进程不触发反调试检测（IsDebuggerPresent/NtQueryInformationProcess 正常）
- [ ] PE 永久 patch 模式生成的 EXE 可在 Win7 双击运行
- [ ] AppInit_DLLs/IFEO 路径 UI 显式标注风险，卸载时清理注册表

## 配置与诊断（Task 3.4, 5.1）
- [ ] 配置按程序粒度存储，不写 HKLM 系统键
- [ ] 右键属性页 Shell 扩展可用
- [ ] 自动从导入表/manifest 推荐兼容选项
- [ ] UI 对 WinRT/UWP/D3D12/VBS/TPM2.0 依赖程序标注"不支持"
- [ ] 日志记录被拦截 API/缺失导出/反调试触发/版本伪装命中
- [ ] 一键导出诊断报告含依赖缺失树

## 模拟层（L3-L4，Task 4.*）
- [ ] `GetSystemTimePreciseAsFileTime` 回退可用不崩溃
- [ ] `WaitOnAddress` 系列事件模拟工作
- [ ] `SetThreadDescription` 用 TLS 槽存储工作
- [ ] `CreatePseudoConsole` 系列管道模拟工作
- [ ] `VirtualAlloc2` 退化为 `VirtualAlloc`（接受语义丢失）
- [ ] DPI 新 API 回退到 `SetProcessDPIAware`
- [ ] CNG ChaCha20-Poly1305 本地实现可被 `BCryptOpenAlgorithmProvider` 调用
- [ ] CNG HKDF 本地实现可用
- [ ] UCRT 前置检测：缺 KB2999226 时提示安装而非静默失败

## 版本伪装（Task 4.1）
- [ ] `GetVersionEx` 返回伪装 Win10 版本号
- [ ] `RtlGetVersion`/`RtlGetNtVersionNumbers` 返回伪装值
- [ ] `VerifyVersionInfo` 对"≥Win10"返回 TRUE
- [ ] `IsWindows10OrGreater` 类 helper 返回 TRUE

## 测试与发布（Task 5.2-5.3）
- [ ] 测试用例集覆盖：高子系统版本、API set 导入、GetProcAddress 动态解析、版本自检
- [ ] 真实 Win7 SP1 + KB 环境验证全部用例通过
- [ ] 已知可运行/不可运行应用清单建立
- [ ] 可重复构建（源码产出与 release 字节一致）
- [ ] release 经代码签名
- [ ] 用户安装与使用文档完成
