# Win7Bridge Win7 验证套件

## 用法

### Linux 开发机预检（语法）
```bash
bash scripts/win7_verify/host_simulate.sh
```

### Win7 真机验证
```bat
cd scripts\win7_verify
build_all.bat
run_all.bat
type results\win7_verify.log
```

## 用例清单（SubTask 5.2.1 测试用例集）

> spec SubTask 5.2.1 要求的 4 类 EXE 全部覆盖，并扩展至 10 个用例，
> 涵盖 L0-L4 各层与运行时关键路径。

### spec 必备用例（4 类）

| spec 要求 | 用例 | 模式 | 期望 |
|---|---|---|---|
| 高子系统版本 EXE | test_3_2_2_high_subsystem + case_01_high_subsystem | patched_subsystem | PASS（pe_patch 修正子系统版本 10.0 -> 6.1） |
| 导入 api-ms-win-core-synch-l1-2-0 的 EXE | case_02_apiset_import | loader | PASS（L2 API Set 重定向到本地实现） |
| GetProcAddress 动态解析新 API 的 EXE | case_03_get_proc_address | loader | PASS（L1 hook 返回 SetThreadDescription 等） |
| 自检 Win10 版本的 EXE | case_04_version_spoof | loader | PASS（L4 GetVersionExW 伪装为 10.0.19045） |

### 扩展用例（覆盖 L3 模拟层 + 反调试 + UCRT）

| 名称 | 模式 | 期望 | 覆盖层 |
|------|------|------|--------|
| test_3_1_4_anti_debug | direct | PASS（无调试器附加） | 注入路径不触发反调试 |
| case_05_pseudo_console | loader | PASS（CreatePseudoConsole hook） | L3 ConPTY 模拟 |
| case_06_wait_on_address | loader | PASS（WaitOnAddress hook） | L3 同步原语模拟 |
| case_07_bcrypt_chacha20 | loader | PASS（CHACHA20_POLY1305 伪句柄） | L3 CNG 新算法 |
| case_08_ucrt_check | loader | PASS（ucrt_check 可调用） | UCRT 前置检测 |

## 执行模式

| 模式 | 含义 | 工具链 |
|------|------|--------|
| `direct` | 直接运行 EXE（无注入） | — |
| `patched_subsystem` | 先 pe_patch 设子系统为 10.0（坏 EXE），再 fix 回 6.1，loader 启动 | pe_patch.exe + win7bridge_loader.exe |
| `loader` | win7bridge_loader.exe 注入 win7bridge.dll 后启动 | win7bridge_loader.exe |

## 测试矩阵（L0-L4 覆盖）

| 层 | 用例 | 验证点 |
|----|------|--------|
| L0 PE 修正 | test_3_2_2_high_subsystem, case_01_high_subsystem | MajorSubsystemVersion 10.0 -> 6.1，Win7 加载器不再返回 0xC000007B |
| L1 符号级重写 | case_03_get_proc_address | GetProcAddress(kernel32, "SetThreadDescription") 返回非 NULL |
| L2 API Set 虚拟化 | case_02_apiset_import | api-ms-win-core-synch-l1-2-0.dll 重定向到 win7bridge_local |
| L3 缺失 API 模拟 | case_05_pseudo_console, case_06_wait_on_address, case_07_bcrypt_chacha20 | ConPTY / WaitOnAddress / ChaCha20-Poly1305 本地实现可调用 |
| L4 版本伪装 | case_04_version_spoof | GetVersionExW 返回 dwMajorVersion >= 10 |
| 注入路径 | test_3_1_4_anti_debug | Loader 注入不触发反调试 API（IsDebuggerPresent 等） |
| 前置检测 | case_08_ucrt_check | UCRT 缺失时给出可读提示，不崩溃 |

## 文件清单

```
scripts/win7_verify/
├── README.md                    本文档
├── build_all.bat                Win7 真机编译入口
├── run_all.bat                  Win7 真机执行入口（输出 results\win7_verify.log）
├── host_simulate.sh             Linux 开发机语法预检
├── pe_patch_cli.c               pe_patch.exe 命令行包装器
├── test_3_1_4_anti_debug.c      反调试检测用例
├── test_3_2_2_high_subsystem.c  高子系统版本用例
└── cases/
    ├── case_01_high_subsystem.c   高子系统版本
    ├── case_02_apiset_import.c    API Set 导入
    ├── case_03_get_proc_address.c GetProcAddress 动态解析
    ├── case_04_version_spoof.c    版本伪装
    ├── case_05_pseudo_console.c   ConPTY
    ├── case_06_wait_on_address.c  WaitOnAddress
    ├── case_07_bcrypt_chacha20.c  CNG ChaCha20
    └── case_08_ucrt_check.c       UCRT 检测
```
