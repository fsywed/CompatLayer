/*
 * w7b_recommend.h - Win7Bridge 自动推荐引擎接口（SubTask 3.4.3）
 *
 * 扫描目标 EXE 的 PE 导入表与 manifest XML，自动推断需要的兼容选项，
 * 把结果填充到 W7bRecommendResult，再由 w7b_recommend_apply 应用到
 * W7bProgramConfig。供 GUI（3.4.2）与 loader 集成使用。
 *
 * 设计要点：
 *   - 纯函数：不读文件、不分配堆内存；结果存调用方传入的固定数组。
 *   - 复用现有解析：PE 解析用 pe_parse；虚拟名识别用 apiset_is_virtual_name。
 *   - 不修改 PE：仅扫描，不改写。改写由调用方按 cfg 触发。
 *   - 不可解项单独标注：WinRT/UWP/D3D12 等依赖明确返回，便于 UI 标注"不支持"。
 *
 * 详细设计见 docs/recommend-engine.md。不依赖 <windows.h>。
 */
#ifndef WIN7BRIDGE_W7B_RECOMMEND_H
#define WIN7BRIDGE_W7B_RECOMMEND_H

#include <stddef.h>
#include "win7bridge/pe_types.h"
#include "win7bridge/pe.h"
#include "win7bridge/w7b_config.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------ */
/* 常量                                                                */
/* ------------------------------------------------------------------ */
#define W7B_REC_EMULATED_MAX   32    /* 可模拟 API 命中列表上限         */
#define W7B_REC_EMULATED_NAME  64    /* 单个 API 名最大长度（含 NUL）   */
#define W7B_REC_UNSOLV_MAX     16    /* 不可解依赖列表上限              */
#define W7B_REC_UNSOLV_TEXT    128   /* 单条不可解描述最大长度（含 NUL）*/

/* ------------------------------------------------------------------ */
/* 推荐结果                                                            */
/* ------------------------------------------------------------------ */
typedef struct {
    /* PE 子系统版本 */
    int  needs_subsystem_fix;          /* 1 表示 > 6.1 需降级            */
    int  current_major_subsystem;      /* 当前 MajorSubsystemVersion     */
    int  current_minor_subsystem;      /* 当前 MinorSubsystemVersion     */

    /* manifest 分析 */
    int  manifest_present;             /* 1 表示传入的 manifest XML 非空  */
    int  manifest_has_win7_guid;       /* manifest 已含 Win7 supportedOS  */
    int  manifest_has_win10_guid;      /* manifest 已含 Win10 supportedOS */
    int  manifest_needs_inject_win7;   /* 1 表示需注入 Win7 GUID         */
    int  manifest_win10_only_count;    /* Win10-only 元素个数            */

    /* 依赖分类 */
    int  has_ucrt_dependency;          /* UCRT（api-ms-win-crt-* / ucrtbase.dll）*/
    int  has_winrt_dependency;         /* WinRT（api-ms-win-core-winrt-* 等）    */
    int  has_d3d12_dependency;         /* D3D12（d3d12.dll）                     */

    /* 可模拟 API 命中列表（函数名） */
    char emulated_apis[W7B_REC_EMULATED_MAX][W7B_REC_EMULATED_NAME];
    size_t emulated_apis_count;

    /* 不可解依赖列表（DLL 名 + 简短原因） */
    char unresolvable[W7B_REC_UNSOLV_MAX][W7B_REC_UNSOLV_TEXT];
    size_t unresolvable_count;

    /* 是否整体不可支持（has_winrt || has_d3d12 等） */
    int  unsupported_overall;
} W7bRecommendResult;

/* ------------------------------------------------------------------ */
/* API                                                                 */
/* ------------------------------------------------------------------ */

/*
 * w7b_recommend_from_pe - 扫描 PE + manifest，填充 rec
 *   pe          ：已 pe_parse 的 PE 信息（导入表必须可读）
 *   manifest_xml：可为 NULL（无 manifest）；NUL 结尾
 *   rec         ：接收结果；调用前可 memset 0
 * 返回：0 成功；-1 入参非法。
 */
int w7b_recommend_from_pe(const PeInfo* pe,
                          const char* manifest_xml,
                          W7bRecommendResult* rec);

/*
 * w7b_recommend_apply - 把推荐结果应用到 cfg（覆盖相关字段）
 *   - fix_subsystem_version / strip_bound_imports 按 rec 设置
 *   - version_spoof_enabled 默认 1（除非 unsupported_overall）
 *   - enabled = !unsupported_overall
 *   - 不动 injection_path / log_level / overlays（用户偏好）
 */
void w7b_recommend_apply(W7bProgramConfig* cfg,
                         const W7bRecommendResult* rec);

#ifdef __cplusplus
}
#endif

#endif /* WIN7BRIDGE_W7B_RECOMMEND_H */
