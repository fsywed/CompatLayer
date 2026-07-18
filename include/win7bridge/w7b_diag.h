/*
 * w7b_diag.h - Win7Bridge 一键诊断报告接口
 *
 * 把分散在 engine / apiset / ucrt_check / inline_hook / w7b_log 的运行期
 * 状态聚合到一份 Markdown 风格文本，便于排障与上报。设计目标见
 * docs/diag-report.md。
 *
 * 不依赖 <windows.h>。
 */
#ifndef WIN7BRIDGE_W7B_DIAG_H
#define WIN7BRIDGE_W7B_DIAG_H

#include <stddef.h>

#include "win7bridge/version.h"
#include "win7bridge/ucrt_check.h"
#include "win7bridge/apiset.h"
#include "win7bridge/engine.h"
#include "win7bridge/inline_hook.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------ */
/* 报告输入                                                            */
/* ------------------------------------------------------------------ */
typedef struct {
    const char*          target_exe;       /* 可空：目标 EXE 路径           */
    const char*          target_arch;      /* 可空："x86" / "x64"           */
    UcrtStatus           ucrt_status;      /* UCRT_OK 表示未检测            */
    const ApiSetMap*     apiset;           /* 可空                          */
    const RewriteEngine* engine;           /* 可空                          */
    const InlineHook*    hooks;            /* 可空数组                      */
    size_t               hooks_count;
} W7bDiagInput;

/*
 * w7b_diag_export_report - 一键导出诊断报告
 *   path ：输出文件路径（UTF-8 / ASCII）
 *   input：聚合输入；各字段可空（NULL / 0），对应 section 写"(unset)"或跳过
 * 返回：0 成功；-1 文件打开失败或写入失败；-2 入参非法。
 *   注意：不负责初始化日志框架；调用方应先 w7b_log_init。
 *   日志缓冲区为全局状态，本函数直接读取。
 */
int w7b_diag_export_report(const char* path, const W7bDiagInput* input);

#ifdef __cplusplus
}
#endif

#endif /* WIN7BRIDGE_W7B_DIAG_H */
