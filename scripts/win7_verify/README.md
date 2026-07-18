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

## 用例清单

| 名称 | 模式 | 期望 |
|------|------|------|
| test_3_1_4_anti_debug | direct | PASS（无调试器附加） |
| test_3_2_2_high_subsystem | patched_subsystem | PASS（pe_patch 修正子系统版本） |
| case_01_high_subsystem | patched_subsystem | PASS |
| case_02_apiset_import | loader | PASS（api-ms-* 重定向） |
| case_03_get_proc_address | loader | PASS（Win10 新 API 通过 hook 返回） |
| case_04_version_spoof | loader | PASS（GetVersionExW 伪装为 10.0.19045） |
| case_05_pseudo_console | loader | PASS（CreatePseudoConsole hook） |
| case_06_wait_on_address | loader | PASS（WaitOnAddress hook） |
| case_07_bcrypt_chacha20 | loader | PASS（CHACHA20_POLY1305 伪句柄） |
| case_08_ucrt_check | loader | PASS（ucrt_check 可调用） |
