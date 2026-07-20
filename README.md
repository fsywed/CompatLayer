# Win7Bridge

> 纯用户态、可逆的 Win10 → Win7 SP1 兼容层。
> 让现代 Windows 10/11 软件（PE 子系统版本 ≤ 10、依赖 Win10 单函数 API）能直接在裸 Win7 SP1 上运行，不依赖 Win7 系统补丁以外的系统改造。

## 项目目标

1. **可逆**：所有改动可一键卸载，不修改系统 DLL、不写 HKLM 系统键
2. **多路径注入**：默认 Loader（创建挂起进程注入）；可选 PE 永久 patch、AppInit_DLLs 兜底
3. **可检测**：UCRT 缺失前置检测 + 自动推荐兼容选项 + 一键诊断报告
4. **不可解边界显式标注**：WinRT/UWP / D3D12 / VBS / TPM2.0 程序不支持，UI 直接显示
5. **双架构**：x86 + x64 同时提供，分别注入对应进程

## 系统要求

| 项 | 要求 |
|---|---|
| 目标系统 | Windows 7 SP1（x86 / x64）|
| 必装前置 | KB2999226（UCRT）、KB3118401（VCRedist 2015+）、VCRedist 2015-2022 |
| 构建系统 | Linux + MinGW-w64（i686-w64-mingw32-gcc / x86_64-w64-mingw32-gcc）|
| 构建验证 | gcc（host syntax-check）、python3（工具自检）|

> Win7Bridge 仅检测并提示 UCRT/VCRedist 缺失，**不分发**这些组件。请从 Microsoft 官方下载安装。

## 安装

### 方式 A：使用 release 包（推荐最终用户）

1. 下载 `win7bridge-x.y.z.zip` 并解压到任意目录（如 `C:\Win7Bridge\`）
2. 以管理员身份运行 `install.bat`：
   - 注册 Shell 属性页扩展（HKCR\exefile\shellex\PropertySheetHandlers\Win7Bridge）
   - 复制 `win7bridge.dll` / `win7bridge_x64.dll` 到 `%ProgramFiles%\Win7Bridge\`
3. 重新登录或重启资源管理器使 Shell 扩展生效

### 方式 B：从源码构建（开发者）

```bash
# 1. 克隆仓库
git clone <repo-url> win7bridge
cd win7bridge

# 2. 构建 x86 + x64 对象（需 MinGW-w64）
make            # 等价于 make x86 x64

# 3. host 语法检查 + Python 工具自检
make check

# 4. host 测试（无需 Windows）
make test

# 5. （可选）可重复构建验证
make verify-reproducible
```

构建产物位于 `build/x86/` 与 `build/x64/`，每个源文件对应一个 `.o`。
后续 5.3.2 阶段会用代码签名证书签署 release DLL。

## 使用

### 方式 1：右键属性页（推荐）

1. 在资源管理器中右键点击目标 `.exe` → "属性"
2. 切换到 "Win7Bridge" 标签页
3. 勾选 "启用 Win7Bridge"
4. 选择注入路径：
   - **loader**（默认）：通过 Loader 程序启动，不修改 EXE 本身
   - **pe_patch**：离线 patch EXE，生成"已 patch EXE"，可双击运行
   - **appinit**：通过 AppInit_DLLs 全局注入（**有反调试检测/沙箱冲突风险**）
5. 调整版本伪装参数（默认伪装 Win10 10.0.19041）
6. 点击 "应用" / "确定"，配置保存到 `%APPDATA%\Win7Bridge\configs\<exe_basename>.json`

### 方式 2：命令行 PE patch 工具

```bash
# L0 修正（子系统版本降级 + 剥离 bound import）
pe_patch input.exe output.exe

# 注入 win7bridge.dll 导入项到 .w7b 节
pe_patch input.exe output.exe --inject

# 自定义注入 DLL 与函数名
pe_patch input.exe output.exe --inject=mydll.dll,MyInit
```

### 方式 3：Loader 程序（适合快捷方式启动）

```bash
# 默认 LoadLibrary 注入
win7bridge_loader.exe target.exe [args...]

# 指定 APC 注入方法（避免 CreateRemoteThread 被拦截）
win7bridge_loader.exe --method apc target.exe [args...]

# 指定工作目录与 DLL 路径
win7bridge_loader.exe --dll C:\path\to\win7bridge.dll --cwd C:\app target.exe
```

## 不可解应用类型

下列应用**无法通过 Win7Bridge 运行**，UI 会显式标注：

| 类型 | 不可解原因 |
|---|---|
| WinRT / UWP | `RoInitialize`/`RoActivateInstance`/HSTRING 在 Win7 无对应实现 |
| Direct3D 12 | Win7 无 D3D12On7，`d3d12.dll`/`dxgi.dll` 加载期即失败 |
| VBS / SGX2 attestation | 依赖 Win10 HVCI，`vgauth.dll`/`vmcompute.dll` 不存在 |
| TPM2.0 attestation | TBS 依赖 Win8+，`tbs.dll` 缺失 `Tbsi_Context_Create` |

## 配置文件

每个目标 EXE 一份 JSON 配置，位于 `%APPDATA%\Win7Bridge\configs\<exe_basename>.json`：

```json
{
  "exe_path": "C:\\app\\target.exe",
  "exe_basename": "target.exe",
  "enabled": 1,
  "injection_path": "loader",
  "version_spoof_enabled": 1,
  "spoof_major": 10,
  "spoof_minor": 0,
  "spoof_build": 19041,
  "fix_subsystem_version": 1,
  "strip_bound_imports": 1,
  "log_level": 1
}
```

也可用 `scripts/config_gen.py` 从 PE 扫描结果自动生成：

```bash
python3 scripts/pe_scan.py target.exe > scan.json
python3 scripts/config_gen.py scan.json > %APPDATA%/Win7Bridge/configs/target.exe.json
```

## 卸载

1. 以管理员身份运行 `uninstall.bat`：
   - 反注册 Shell 扩展（删除 HKCR 下相关键）
   - 删除 `%ProgramFiles%\Win7Bridge\`
2. 删除 `%APPDATA%\Win7Bridge\`（用户配置目录）
3. 删除通过 `pe_patch --inject` 生成的 "已 patch EXE"（手动）

> Loader / pe_patch 模式天然可逆：移除兼容层 DLL 后，目标 EXE 恢复原始行为。
> AppInit_DLLs 模式需 `uninstall.bat` 清理注册表 `HKLM\...\AppInit_DLLs` 条目。

## 兼容性清单

[data/compat_list.json](file:///workspace/data/compat_list.json) 维护已知可运行/不可运行应用列表，参考 VxKex Application Compatibility List 格式。每条记录含 `status`（works / limited / broken / unknown）、`known_issues`、`tested_with` 等字段。

UI 与诊断报告会读取该清单，对已知应用直接显示状态；未知应用走推荐引擎自动推断。

## 诊断报告

应用启动失败时，可一键导出诊断报告：

```bash
win7bridge_diag.exe --target target.exe --out report.txt
```

报告含：
- PE 解析结果（子系统版本、bound import、导入表）
- 依赖缺失树（不可解 Win10 DLL 列表 + 原因）
- 被拦截 API 调用统计
- 反调试触发点
- 版本伪装命中次数

`scripts/diag_parse.py` 可将报告转为 Markdown 摘要：

```bash
python3 scripts/diag_parse.py report.txt > report.md
```

## 架构分层

| 层 | 职责 | 模块 |
|---|---|---|
| L0 | PE 修正（子系统版本降级 / bound import strip / manifest 改写） | `src/pe/` |
| L1 | 符号级重写（整 DLL 转发 / 单导出替换 / IAT hook / inline hook / GetProcAddress hook） | `src/engine/` |
| L2 | API Set 虚拟解析（api-ms-win-* 映射表） | `src/engine/apiset.c` |
| L3 | 缺失 API 模拟（WaitOnAddress / SetThreadDescription / PseudoConsole / ChaCha20-Poly1305 / HKDF / DPI 回退 ...） | `src/sim/` |
| L4 | 版本伪装（GetVersion/GetVersionEx/RtlGetVersion/VerifyVersionInfo hook） | `src/sim/spoof.c` |

## 开发文档

- [docs/dev-guide.md](file:///workspace/docs/dev-guide.md) — 开发指南
- [docs/api-diff.md](file:///workspace/docs/api-diff.md) — Win7/Win10 API 差异表
- [docs/vxkex-lessons.md](file:///workspace/docs/vxkex-lessons.md) — VxKex 缺陷与规避
- [docs/per-program-config.md](file:///workspace/docs/per-program-config.md) — 按程序粒度配置
- [docs/recommend-engine.md](file:///workspace/docs/recommend-engine.md) — 推荐引擎
- [docs/logging-framework.md](file:///workspace/docs/logging-framework.md) — 日志框架
- [docs/diag-report.md](file:///workspace/docs/diag-report.md) — 诊断报告格式
- [docs/apiset-json-config.md](file:///workspace/docs/apiset-json-config.md) — API Set 映射表

## 构建 / 测试

```bash
make            # 构建 x86 + x64
make check      # 语法检查 + Python 工具自检
make test       # host 测试（gcc + 测试用例）
make verify-reproducible   # 可重复构建验证
make clean      # 清理
make help       # 帮助
```

## 许可证

待定（release 阶段确定）。

## 已知限制

1. **UCRT 不分发**：用户须自行安装 KB2999226 + VCRedist
2. **D3D12 / WinRT / VBS / TPM2.0 不可解**
3. **AppInit_DLLs 路径有反调试检测风险**
4. **Inline hook 在 CFG 启用进程上可能失败**（Win7 无 CFG，问题不大；目标进程若显式启用 CFG 则需用 IAT hook 替代）
5. **PseudoConsole 模拟在快速 resize 时可能丢行**
