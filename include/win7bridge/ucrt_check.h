/*
 * ucrt_check.h - Win7Bridge UCRT 前置检测接口
 *
 * 对应 docs/api-diff.md §2.8：启动前检测 UCRT/VCRedist 关键 DLL 是否存在，
 * 缺失时给出可读提示，引导用户安装 KB2999226 与 VCRedist 2015-2022。
 *
 * host 下用 access() 检查模拟路径（/tmp/ucrtbase.dll 等）；Windows 下用
 * GetSystemDirectory + GetFileAttributes 检查系统目录。
 *
 * 本头文件无 Windows 类型依赖，可独立编译。
 */
#ifndef WIN7BRIDGE_UCRT_CHECK_H
#define WIN7BRIDGE_UCRT_CHECK_H

#ifdef __cplusplus
extern "C" {
#endif

/* UCRT 检测结果                                                       */
typedef enum {
    UCRT_OK = 0,                /* 全部就绪                            */
    UCRT_MISSING_UCRTBASE,      /* 缺 ucrtbase.dll（KB2999226）         */
    UCRT_MISSING_VCRUNTIME,     /* 缺 vcruntime140.dll                  */
    UCRT_MISSING_MSVCPP         /* 缺 msvcp140.dll                      */
} UcrtStatus;

/* 检测 UCRT/VCRedist 关键 DLL；结果写入 *out，返回 0 表示检测完成，
 * 非 0 表示入参非法（out == NULL）。                                  */
int ucrt_check(UcrtStatus* out);

/* 返回状态对应的可读提示（永不为 NULL）。                             */
const char* ucrt_status_message(UcrtStatus s);

#ifdef __cplusplus
}
#endif

#endif /* WIN7BRIDGE_UCRT_CHECK_H */
