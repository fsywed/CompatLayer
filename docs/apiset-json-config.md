# API Set JSON 配置加载器开发文档（Task 2.3.1 / 2.3.2）

## 简洁概要

为 `apiset.c` 增加 JSON 格式的"虚拟名 → 实现源"映射表加载器，使映射表可在不重编译的前提下扩充与定制。新增 `apiset_load_from_json` 与 `apiset_load_from_file` 两个接口；解析器为极简递归下降、纯 C、零外部依赖。预置硬编码表 `apiset_load_default` 保留作兜底，用户配置可叠加于其上。

## 分点展开

### 1. JSON 格式设计

```json
{
  "schema": "win7bridge.apiset/v1",
  "entries": [
    {
      "virtual_name": "api-ms-win-core-synch-l1-2-0",
      "kind": "to_local",
      "host_dll": "win7bridge_local",
      "note": "WaitOnAddress 体系，本地事件对象模拟"
    },
    {
      "virtual_name": "api-ms-win-core-winrt-l1-1-0",
      "kind": "unsolvable",
      "note": "WinRT，不可解"
    }
  ]
}
```

- 顶层为对象，`schema` 必须等于 `"win7bridge.apiset/v1"`
- `entries` 为数组，每条含 4 个字段：
  - `virtual_name`（字符串，必填）：`api-ms-win-*` / `ext-ms-win-*`，无 `.dll` 后缀
  - `kind`（字符串，必填）：`to_real_dll` / `to_local` / `unsolvable`
  - `host_dll`（字符串，可选）：`to_real_dll` 与 `to_local` 必填，`unsolvable` 时忽略
  - `note`（字符串，可选）：备注

### 2. JSON 解析器实现策略

- 极简递归下降解析器，纯 C，无外部依赖
- 支持的 JSON 子集：对象、数组、字符串、键值对、字面 null/true/false（被忽略）
- **不支持**数字与浮点（本格式不需要）
- 字符串支持基本转义：`\"` `\\` `\/` `\n` `\t` `\r` `\b` `\f`
- 跳过注释：`//` 行注释、`/* ... */` 块注释（非标准但便于人工编辑）
- 解析状态用一个 `JsonParser` 结构体维护：`buf`、`pos`、`len`、`arena`（字符串 arena）

### 3. 字符串生命周期

- JSON 解析时，所有字符串字段复制到一块 malloc 的 arena 中
- arena 起始记录元数据（总长、已用偏移），arena_out 返回给调用方
- 映射表 entries 中的 `virtual_name`/`host_dll`/`note` 指针指向 arena 内偏移
- 调用方负责通过 `apiset_free_arena(arena)` 释放（通常在映射表销毁时）

### 4. 新增 API

```c
/* 加载 JSON 字符串到映射表；arena_out 接收字符串 arena 指针 */
int apiset_load_from_json(ApiSetMap* m, const char* json_text,
                          void** arena_out);

/* 加载 JSON 文件到映射表；arena_out 接收字符串 arena 指针 */
int apiset_load_from_file(ApiSetMap* m, const char* path,
                          void** arena_out);

/* 释放 JSON arena（不释放 ApiSetMap.entries，那由 apiset_free 负责） */
void apiset_free_arena(void* arena);

/* 释放映射表本身（与 apiset_init 对应） */
void apiset_free(ApiSetMap* m);
```

### 5. 错误码扩展

在 `apiset.h` 现有 `APISET_ERR_INVALID_ARG`、`APISET_ERR_NOMEM` 之上新增：

```c
#define APISET_ERR_PARSE   (-3)  /* JSON 语法错误            */
#define APISET_ERR_IO      (-4)  /* 文件 IO 错误             */
#define APISET_ERR_SCHEMA  (-5)  /* schema 字段不匹配        */
```

解析失败时 **不修改** `ApiSetMap` 状态，arena 在出错路径中已释放并置 NULL。

### 6. 平台隔离

- `apiset.c` 不引入 `<windows.h>`，文件 IO 用标准 C `fopen/fread/fclose`
- 与 host 测试（`-DWIN7BRIDGE_HOST_TEST`）与 Win7 目标编译均兼容
- 已有 `apiset.c` 头部注释约定保持不变

### 7. 与现有代码的整合

- `apiset_load_default` 不变，仍作为兜底预置表
- 调用顺序建议：
  1. `apiset_init(&m)`
  2. `apiset_load_default(&m)` — 加载硬编码 21 条
  3. `apiset_load_from_file(&m, "Win7Bridge.apiset.json", &arena)` — 可选，叠加用户配置
  4. 使用 `apiset_lookup` / `apiset_resolve_imports`
  5. `apiset_free_arena(arena)` + `apiset_free(&m)`
- 后续 `dllmain.c` 的 `LoadLibraryA` hook 改为查 `ApiSetMap`，而非硬编码 `api-ms-win-core-synch`/`api-ms-win-core-crt` 子串

### 8. 测试用例（test_apiset_json.c）

| # | 名称 | 验证点 |
|---|------|--------|
| 1 | 基本加载 | 单条 to_real_dll 条目，lookup 命中、字段正确 |
| 2 | 多类型混合 | to_real_dll + to_local + unsolvable 各一条 |
| 3 | 注释跳过 | JSON 含 `//` 行注释和 `/* */` 块注释 |
| 4 | 字符串转义 | note 含 `\n`、`\"`、`\\`，原样恢复 |
| 5 | 缺 host_dll | to_real_dll 缺 host_dll → 返回 `APISET_ERR_PARSE` |
| 6 | 非法 kind | kind="foo" → 返回 `APISET_ERR_PARSE` |
| 7 | schema 不匹配 | schema="wrong" → 返回 `APISET_ERR_SCHEMA` |
| 8 | 文件加载 | 写临时文件后 `apiset_load_from_file` 命中 |

### 9. 与开发文档要求的对照

- `docs/dev-guide.md` §3 L2："可配置映射表（JSON/INI）" — ✓ 实现 JSON 格式
- `docs/dev-guide.md` §10："提交前快速语法检查，确保能编译" — ✓ 走 `make check` 与 `make test`
- `docs/dev-guide.md` §10："代码须符合本开发文档要求" — ✓ 实现后逐项核对
- 用户约束 "搜索更多win10的API，不依赖win7补丁" — ✓ JSON 配置允许按需扩充 Win10 API set 映射而无需打 Win7 补丁；`to_local` 路径完全由兼容层提供本地实现
