/*
 * compat_list.h - Win7Bridge SubTask 5.2.3 兼容性清单
 *
 * 【开发文档】
 *
 * 目的：维护"已知可运行/不可运行应用"清单，参考 VxKex Application
 *   Compatibility List 格式。作为 UI 显示、诊断报告、推荐引擎的输入。
 *
 * 分点展开：
 *   1. 文件格式
 *      data/compat_list.json：JSON 数组，每项为对象，字段：
 *        exe_basename   string   必填，不含路径，含 .exe
 *        publisher      string   可选
 *        status         string   必填，"works"|"limited"|"broken"|"unknown"
 *        tested_with    string   可选，例如 "win7sp1+x64+kb2999226"
 *        known_issues   array    可选，字符串数组
 *        notes          string   可选，单行说明
 *
 *   2. 数据结构
 *      CompatListEntry：单条记录，字段用固定缓冲（避免动态分配）
 *      CompatList：数组容器，count + entries 指针
 *
 *   3. API
 *      w7b_compat_list_load(path, &list)  - 加载并解析 JSON
 *      w7b_compat_list_lookup(list, name) - 大小写不敏感基名查询
 *      w7b_compat_list_free(list)         - 释放
 *      w7b_compat_status_to_str(enum)     - 状态转可读字符串
 *
 *   4. 平台隔离
 *      全部纯 C 文件 IO，无 <windows.h> 依赖，host gcc 可测。
 *
 *   5. 健壮性
 *      损坏 JSON 返回 -1，list 置空；未知字段跳过；status 未知归 unknown。
 */
#ifndef WIN7BRIDGE_COMPAT_LIST_H
#define WIN7BRIDGE_COMPAT_LIST_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------ */
/* 常量                                                                */
/* ------------------------------------------------------------------ */
#define W7B_COMPAT_BASENAME_MAX  256
#define W7B_COMPAT_PUBLISHER_MAX 128
#define W7B_COMPAT_NOTES_MAX     512
#define W7B_COMPAT_TESTED_MAX    128
#define W7B_COMPAT_ISSUES_MAX    8
#define W7B_COMPAT_ISSUE_LEN_MAX 256

/* 状态枚举 */
typedef enum {
    W7B_COMPAT_STATUS_UNKNOWN = 0,
    W7B_COMPAT_STATUS_WORKS   = 1,
    W7B_COMPAT_STATUS_LIMITED = 2,
    W7B_COMPAT_STATUS_BROKEN  = 3
} W7bCompatStatus;

/* 单条记录 */
typedef struct {
    char             exe_basename[W7B_COMPAT_BASENAME_MAX];
    char             publisher[W7B_COMPAT_PUBLISHER_MAX];
    W7bCompatStatus  status;
    char             tested_with[W7B_COMPAT_TESTED_MAX];
    char             notes[W7B_COMPAT_NOTES_MAX];
    char             known_issues[W7B_COMPAT_ISSUES_MAX][W7B_COMPAT_ISSUE_LEN_MAX];
    size_t           known_issues_count;
} W7bCompatListEntry;

/* 容器 */
typedef struct {
    W7bCompatListEntry* entries;
    size_t              count;
    size_t              capacity;
} W7bCompatList;

/* ------------------------------------------------------------------ */
/* API                                                                 */
/* ------------------------------------------------------------------ */

/*
 * w7b_compat_list_load - 加载并解析 JSON 清单
 *   path：JSON 文件路径
 *   list ：接收容器；调用前应清零；调用者最终需调 free 释放
 *   返回：0 成功；1 文件不存在/空（list 置空，不算错误）；-1 解析失败
 */
int w7b_compat_list_load(const char* path, W7bCompatList* list);

/*
 * w7b_compat_list_lookup - 大小写不敏感按基名查找
 *   返回匹配条目指针（所有权归 list，不可释放）；未找到返回 NULL
 */
const W7bCompatListEntry* w7b_compat_list_lookup(const W7bCompatList* list,
                                                  const char* exe_basename);

/*
 * w7b_compat_list_free - 释放 list 中动态分配的内存
 *   list->entries 置 NULL，count/capacity 归零
 */
void w7b_compat_list_free(W7bCompatList* list);

/*
 * w7b_compat_status_to_str - 状态枚举 -> 静态字符串
 *   未知值返回 "unknown"
 */
const char* w7b_compat_status_to_str(W7bCompatStatus s);

/*
 * w7b_compat_status_from_str - 字符串 -> 状态枚举
 *   "works"/"limited"/"broken" 不区分大小写；其余归 unknown
 */
W7bCompatStatus w7b_compat_status_from_str(const char* s);

#ifdef __cplusplus
}
#endif

#endif /* WIN7BRIDGE_COMPAT_LIST_H */
