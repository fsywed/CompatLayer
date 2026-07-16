# VxKex 现状分析与缺陷规避策略

> 用途：为 Win7Bridge 兼容层提供 VxKex 工作原理分析与规避其缺陷的设计依据。  
> 来源：VxKex 仓库（github.com/i486/VxKex）、GitHub Issues、MSFN / GBAtemp / audiosex.pro / Xanasoft 论坛、CSDN 实测博客。关键 URL 见文末。

---

## 0. TL;DR

VxKex 是**纯用户态**兼容层，通过 IFEO `VerifierDlls` 注入 `VxKexLdr.dll`，**遍历导入表一次，整 DLL 重定向**到自带扩展 DLL。不触碰内核、不改系统文件、可逆、按程序粒度。但实战差：机制粗糙、注入副作用大、维护断档。Win7Bridge 须逐条规避其结构性缺陷。

---

## 1. VxKex 工作原理

### 1.1 注入：IFEO `VerifierDlls`
- 用户在 EXE 属性页启用后，写 `HKLM\...\Image File Execution Options\<程序>.exe\VerifierDlls = VxKexLdr.dll`。
- Windows 加载器在主镜像初始化前加载该"验证器 DLL"（本为 Application Verifier 设计）。
- `VxKexLdr.dll` 在导入表被 ntdll 解析前运行，有机会改写导入表。
- **历史**：1.0 之前用 IFEO `Debugger`（侵入性更强），1.0 重写改用 `VerifierDlls`。

### 1.2 实现：整 DLL 重定向
- 遍历目标 PE 导入表一次，把对 Win8/10 DLL 的整体导入改名指向 VxKex 扩展 DLL。
- 扩展 DLL（`01-Extended DLLs`）本地实现新版 API，翻译为 Win7 等价机制或模拟。
- **关键限制**（kernel22 作者 kuba2k2 原话）：*"VxKex only allows to redirect entire DLL files... goes through the import table once, just to change the DLL names and then lets ntdll do the rest."* —— 仅整 DLL 粒度，无单函数 patching，不覆盖运行时 `GetProcAddress` 动态解析。

### 1.3 其他处理
- **API Set**：沿用整 DLL 重定向，把 `api-ms-win-*` 导入指向自带扩展 DLL。
- **UCRT**：不揽责，靠用户预装 KB2999226（正确做法，应继承）。
- **版本检查**：属性页提供"Report other version of Windows"（version lie shim），hook `GetVersionEx` 等返回伪装版本。
- **可逆**：取消勾选删 IFEO 值；卸载自动清理；按程序粒度；1.0 引入 IFEO filter 解决同名 EXE 冲突。

---

## 2. VxKex 缺陷清单（须规避）

### 2.1 结构性缺陷（最高优先级）

| # | 缺陷 | 根因 | Win7Bridge 规避策略 |
|---|---|---|---|
| 1 | 仅整 DLL 重定向，无单函数 patching | 导入表只改 DLL 名 | **符号级三层粒度**：整 DLL 转发 + 单导出替换/forward/stub + 运行时 IAT/inline hook |
| 2 | 不覆盖 `GetProcAddress` 动态解析 | 仅导入期改名 | **hook `GetProcAddress`/`LdrGetProcedureAddress`**，对查询新 API 返回本地实现 |
| 3 | 不能 patch EXE，不能便携 EXE | 依赖 IFEO 注册表 | **Loader 程序**（CREATE_SUSPENDED+注入+resume）+ **PE 永久 patch** 模式 |
| 4 | IFEO `VerifierDlls` 触发反调试 | 借用调试基础设施 | **默认 Loader 路径**，VerifierDlls 仅作兜底并标注风险 |

### 2.2 兼容性缺口

| 领域 | VxKex 表现 | Win7Bridge 策略 |
|---|---|---|
| 游戏 | README 自述不支持；CS2/Limbus/osu!lazer/Godot4/TF2 失败 | 初版不主打游戏；标注边界 |
| 浏览器 | Firefox 需降级、Edge 不可用、Chrome 不能更新 | 标注而非强支持 |
| Steam | 托盘菜单/黑屏/大屏卡顿 | — |
| DX12/WinRT/.NET Core 3.1+ | 不支持或有限 | UI 显式标注"不支持" |
| Win7 x86 | 长期 BEX 崩溃，1.1.2 才修 | 双架构同等优先级测试 |

### 2.3 稳定性问题

- 环境敏感：`%Path%` 非标准即全失败（1.1.2 才修）；Temp 目录在 FAT32/非 C 盘安装失败。
- Chromium/Electron 竞态（1.1.2 才修）。
- 与 Sandboxie-Plus 冲突（`SBIE2181`，双方 detour 互破）。

### 2.4 维护与信任危机

- 原作者 `vxiiduu` 2024-07 删号；现 `i486` 接力。
- 冒名仓库事件（`vxiiduu1`/`VxKex/VxKex`），含诈骗叙事与 BTC 捐款地址。
- 无可重复构建、无自动化测试矩阵、单人维护。

### 2.5 性能开销

- 注入额外内存约 10–30MB。
- 图形/游戏类间接开销显著（8K 视频无法硬解、Steam 大屏卡顿）。

---

## 3. VxKex 缺陷总览表

| 维度 | VxKex | Win7Bridge 目标 |
|---|---|---|
| 内核侵入 | 无 | 无 |
| 注入机制 | IFEO VerifierDlls（副作用大） | Loader 默认（不触发反调试） |
| 粒度 | 整 DLL 重定向 | 符号级三层粒度 |
| EXE patching | 不支持 | 支持（永久 patch + 便携） |
| GetProcAddress 覆盖 | ❌ | ✅ |
| 便携化 | ❌ | ✅ |
| 游戏支持 | README 自述不支持 | 标注边界，不主打 |
| Win7 x86 | 长期 BEX | 双架构同等优先级 |
| DX12/WinRT/.NET Core 3.1+ | 不支持 | UI 显式标注不支持 |
| 沙箱共存 | 与 Sandboxie 冲突 | Loader 路径不冲突 |
| 反调试程序 | 触发"debugger found" | Loader 不触发 |
| 杀软误报 | Panda/Firefox 标记 | 代码签名 + 申诉 |
| 维护 | 单人接力，冒名危机 | 可重复构建 + 多维护者 |
| 可逆性 | 良好 | 良好（继承） |

---

## 4. 替代方案对比（技术路线）

| 路线 | 代表 | 改系统文件 | 内核 | 粒度 | 可逆 | 风险 |
|---|---|---|---|---|---|---|
| 用户态 API 重定向 | VxKex | 否 | 否 | 整 DLL | 良好 | 注入副作用 |
| 用户态符号级重写 | **kernel22** | 否 | 否 | 单函数 | 良好（可便携） | 仍在打磨 |
| 系统二进制替换 | Extended Kernel | **是** | 半 | 全局 | 差 | 高 |
| API set 桥接 | One-Core-API | 是（wrapper） | 否 | 整 DLL+schema | 中 | 中 |
| 源码级重建 | Supermium | 否 | 否 | — | — | 维护成本极高 |

**借鉴**：
- kernel22 的符号级重写 + 自定义 loader + 便携 EXE → 几乎逐条对应 VxKex 缺陷，最值得借鉴。
- One-Core-API 的显式 API-SET schema 解析层 → VxKex 缺的，作为 L2 设计参考。
- VxKex 的可逆性 + 按程序粒度 + 日志（`.vxl`）→ 正确做法，继承。

---

## 5. Win7Bridge 规避要点（设计对照）

1. **默认 Loader 注入**，不触发 Verifier/Debugger 标志 → 解决反调试检测、沙箱冲突、杀软误报三大副作用。
2. **符号级三层粒度**（整 DLL / 单导出 / 运行时 hook）→ 解决"整 DLL 重定向"粗糙问题。
3. **hook `GetProcAddress`/`LdrGetProcedureAddress`** → 覆盖动态解析路径（VxKex 最大短板，游戏/反作弊失败根因）。
4. **支持 PE 永久 patch + 便携 EXE** → 不强依赖注册表。
5. **显式 API Set schema 映射表** → 而非把每个 api-ms-win-* 当独立 DLL。
6. **双架构同等优先级** → 避免 VxKex 的 x86 二等公民问题。
7. **可重复构建 + 代码签名** → 消除冒名仓库风险、缓解杀软误报。
8. **自动化兼容性矩阵** → 治理"又坏了"的反复回归。
9. **不可解项 UI 显式标注** → 避免用户无效尝试。
10. **UCRT 前置检测** → 继承 VxKex 正确做法，不揽责。

---

## 6. 关键来源

- VxKex 仓库：https://github.com/i486/VxKex
- README：https://raw.githubusercontent.com/i486/VxKex/main/README.md
- Issues：https://github.com/i486/VxKex/issues
- Release 1.0.0.999（重写说明）：https://newreleases.io/project/github/i486/VxKex/release/Version1.0.0.999
- Release 1.1.2.1428：https://newreleases.io/project/github/i486/VxKex/release/Version1.1.2.1428
- VxKex NEXT：https://descargatic.com/en/vxkex-next/
- MSFN Win7 Extended Kernel：https://msfn.org/board/topic/183465-windows-7-extended-kernel/
- MSFN VxKex 项目消失：https://msfn.org/board/topic/186333-vxkex-extended-kernel-project-dissapeared/
- Sandboxie 冲突：https://forum.xanasoft.com/threads/770/
- GBAtemp（冒名告警）：https://gbatemp.net/threads/667406/
- audiosex.pro（kernel22 对比）：https://audiosex.pro/threads/win7-list-of-programs-and-plugins-not-working-anymore.64385/page-8
- kernel22：https://github.com/kuba2k2/kernel22
- One-Core-API 开发指南：https://deepwiki.com/shorthorn-project/One-Core-API-Binaries/6-developer-guide
- Supermium：https://handwiki.org/wiki/Software:Supermium
- CSDN 实测：https://blog.csdn.net/q951250246/article/details/157612803
