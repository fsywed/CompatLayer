# Win7Bridge 自动推荐引擎（SubTask 3.4.3）开发文档

> Spec 要求（tasks.md SubTask 3.4.3）："实现自动推荐：扫描目标 EXE 导入表/
> manifest，自动推断需要的兼容选项"。本任务在 `scripts/config_gen.py` 已有
> 知识库基础上，提供 C 层纯函数 API，把扫描结果直接填充到
> `W7bProgramConfig`，供 GUI（3.4.2）与 loader 集成使用。
>
> 设计原则：
> - **纯函数**：不读文件、不分配堆内存（结果存调用方栈/堆），便于 host 测试。
> - **复用现有解析**：PE 解析用 `pe_parse`；manifest 提取用 `manifest_get_from_pe`；
>   API Set 虚拟名识别用 `apiset_is_virtual_name`。
> - **不修改 PE**：仅扫描，不改写。改写由调用方按 cfg 触发。
> - **不可解项单独标注**：WinRT/UWP/D3D12/VBS/TPM2.0 等依赖明确返回，便于
>   UI（3.4.4）标注"不支持"。

## 1. 目标

- 输入：已 `pe_parse` 的 PeInfo（导入表 + 子系统版本）+ 可选 manifest XML。
- 输出：`W7bRecommendResult`，含：
  - PE 子系统版本是否需要修复（>6.1）+ 当前值
  - manifest 是否含 Win7 / Win10 supportedOS GUID
  - manifest 是否含 Win10-only 元素（maxversiontested / msix / catalog）
  - 是否依赖 UCRT（`api-ms-win-crt-*` / `ucrtbase.dll`）
  - 是否依赖 WinRT（`api-ms-win-core-winrt-*` / `combase.dll` / `winrtbase.dll`）
  - 是否依赖 D3D12（`d3d12.dll`）
  - 命中的可模拟 API 列表（GetSystemTimePreciseAsFileTime / WaitOnAddress 等）
  - 命中的不可解依赖列表
- `w7b_recommend_apply` 把结果应用到 `W7bProgramConfig`（覆盖相关字段）。

## 2. 接口

新增头 `include/win7bridge/w7b_recommend.h`：

```c
#define W7B_REC_EMULATED_MAX   32
#define W7B_REC_EMULATED_NAME  64
#define W7B_REC_UNSOLV_MAX     16
#define W7B_REC_UNSOLV_TEXT    128

typedef struct {
    /* PE 子系统版本 */
    int  needs_subsystem_fix;     /* 1 表示 > 6.1 需降级              */
    int  current_major_subsystem;
    int  current_minor_subsystem;

    /* manifest 分析 */
    int  manifest_present;
    int  manifest_has_win7_guid;
    int  manifest_has_win10_guid;
    int  manifest_needs_inject_win7;    /* 1 表示需注入 Win7 GUID     */
    int  manifest_win10_only_count;     /* Win10-only 元素个数        */

    /* 依赖分类 */
    int  has_ucrt_dependency;
    int  has_winrt_dependency;
    int  has_d3d12_dependency;

    /* 可模拟 API 命中列表（函数名） */
    char emulated_apis[W7B_REC_EMULATED_MAX][W7B_REC_EMULATED_NAME];
    size_t emulated_apis_count;

    /* 不可解依赖列表（DLL 名 + 简短原因） */
    char unresolvable[W7B_REC_UNSOLV_MAX][W7B_REC_UNSOLV_TEXT];
    size_t unresolvable_count;

    /* 是否整体不可支持（has_winrt || has_d3d12 等） */
    int  unsupported_overall;
} W7bRecommendResult;

/* 扫描 PE + manifest，填充 rec。
 *   pe          ：已 pe_parse 的 PE 信息（导入表必须可读）
 *   manifest_xml：可为 NULL（无 manifest）；NUL 结尾
 *   rec         ：接收结果；调用前可 memset 0
 * 返回：0 成功；-1 入参非法。 */
int w7b_recommend_from_pe(const PeInfo* pe,
                          const char* manifest_xml,
                          W7bRecommendResult* rec);

/* 把推荐结果应用到 cfg（覆盖相关字段）：
 *   - fix_subsystem_version / strip_bound_imports 按 rec 设置
 *   - version_spoof_enabled 默认 1（除非 unsupported_overall）
 *   - enabled = !unsupported_overall
 *   - 不动 injection_path / log_level / overlays（用户偏好） */
void w7b_recommend_apply(W7bProgramConfig* cfg,
                         const W7bRecommendResult* rec);
```

## 3. 知识库

复用 `docs/api-diff.md` 与 `scripts/config_gen.py` 已有规则：

| 信号 | 来源 | 推荐动作 |
|---|---|---|
| 子系统版本 > 6.1 | OptionalHeader | fix_subsystem_version=1 |
| api-ms-win-crt-* / ucrtbase.dll | 导入表 | has_ucrt_dependency=1（提示装 KB） |
| api-ms-win-core-winrt-* / combase.dll / winrtbase.dll | 导入表 | has_winrt_dependency=1, unsupported=1 |
| d3d12.dll | 导入表 | has_d3d12_dependency=1, unsupported=1 |
| GetSystemTimePreciseAsFileTime 等 | 导入函数名 | 加入 emulated_apis |
| manifest 含 Win10 GUID 但无 Win7 GUID | manifest XML | manifest_needs_inject_win7=1 |
| manifest 含 maxversiontested/msix/catalog | manifest XML | manifest_win10_only_count |

可模拟 API 列表（与 config_gen.py `EMULATABLE_APIS` 对齐）：
GetSystemTimePreciseAsFileTime, WaitOnAddress, WakeByAddressSingle,
WakeByAddressAll, VirtualAlloc2, VirtualAlloc2FromApp, MapViewOfFileNuma2,
UnmapViewOfFileEx, SetThreadDescription, GetThreadDescription,
CreatePseudoConsole, ClosePseudoConsole, ResizePseudoConsole,
SetProcessDpiAwarenessContext, EnableMouseInPointer。

## 4. 实现要点

- **遍历导入表**：复用 apiset.c `apiset_resolve_imports` 的遍历模式，
  对每个 DLL 名做分类；对每个导入函数名查可模拟 API 表。
- **manifest 扫描**：简单字符串匹配（与 manifest.c 风格一致），不依赖
  完整 XML 解析器：
  - `<supportedOS Id="...">` 提取 GUID 与 Win7/Win10 常量比较（大小写不敏感）
  - `<maxversiontested` / `<msix` / `<catalog` 子串扫描
- **去重**：emulated_apis 与 unresolvable 列表内同名条目只入一次。
- **零堆分配**：所有结果存调用方传入的固定数组；超出上限则截断（不报错）。

## 5. 平台隔离

- 不依赖 `<windows.h>`；PE 类型来自 `pe_types.h`。
- host 测试可直接构造内存中的 PE 镜像（与 test_engine.c 风格一致）。

## 6. 集成点

- `dllmain.c` 在 `DLL_PROCESS_ATTACH` 时：
  1. `pe_parse(GetModuleHandle(NULL))` 拿到自身/目标 PE
  2. `manifest_get_from_pe` 拿 manifest
  3. `w7b_recommend_from_pe` + `w7b_recommend_apply` 得到运行期 cfg
  4. 按 cfg 配置 engine / apiset / spoof / log
- GUI（3.4.2）"自动推荐"按钮：同样调用，结果展示给用户确认。

## 7. 测试用例（tests/test_recommend.c）

1. **空 PE**：import_dir 为 NULL -> rec 全 0，返回 0。
2. **子系统版本**：合成 PE 子系统 10.0 -> needs_subsystem_fix=1。
3. **UCRT 依赖**：导入 ucrtbase.dll -> has_ucrt_dependency=1。
4. **WinRT 依赖**：导入 api-ms-win-core-winrt-l1-1-0.dll ->
   has_winrt_dependency=1, unsupported_overall=1。
5. **D3D12 依赖**：导入 d3d12.dll -> has_d3d12_dependency=1, unsupported=1。
6. **可模拟 API 命中**：导入 kernel32!SetThreadDescription ->
   emulated_apis 含 "SetThreadDescription"。
7. **manifest Win7 GUID**：XML 含 Win7 GUID -> manifest_has_win7_guid=1,
   manifest_needs_inject_win7=0。
8. **manifest 仅 Win10 GUID**：XML 含 Win10 GUID 不含 Win7 ->
   manifest_needs_inject_win7=1。
9. **manifest Win10-only 元素**：XML 含 maxversiontested ->
   manifest_win10_only_count >= 1。
10. **apply 覆盖 cfg**：unsupported=1 时 cfg.enabled=0；
    needs_subsystem_fix=1 时 cfg.fix_subsystem_version=1。
11. **去重**：同函数名导入两次，emulated_apis_count 只 +1。
12. **不可解列表截断**：导入 > W7B_REC_UNSOLV_MAX 个不可解 DLL，
    unresolvable_count == W7B_REC_UNSOLV_MAX。
