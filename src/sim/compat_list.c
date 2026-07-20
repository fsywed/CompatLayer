/*
 * compat_list.c - Win7Bridge SubTask 5.2.3 兼容性清单实现
 *
 * 【开发文档】
 *
 * 目的：极简递归下降 JSON 解析器，仅支持 compat_list.json 的 schema
 *   （顶层为对象数组）。无外部依赖，host gcc 可测。
 *
 * 分点展开：
 *   1. 解析流程
 *      fopen/fread 整文件 -> 内存中扫描 -> 顶层 [ -> 循环 { ... } -> ]
 *      每个对象内：key: value 形式，value 为 string 或 array of string
 *
 *   2. 内存模型
 *      W7bCompatListEntry 用固定缓冲，避免每字段 malloc
 *      W7bCompatList.entries 用 realloc 增长（capacity 翻倍策略）
 *
 *   3. 健壮性
 *      损坏 JSON 立即返回 -1，已分配的 entries 在 free 中释放
 *      未知字段一律跳过；status 字符串未知归 unknown
 *      字段值过长截断并保证 NUL 结尾
 *
 *   4. 大小写不敏感查找
 *      _stricmp 风格手写实现（不依赖 <strings.h>），host/Win 通用
 */
#include "win7bridge/compat_list.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------ */
/* 内部辅助                                                            */
/* ------------------------------------------------------------------ */
static int _str_ieq(const char* a, const char* b)
{
    while (*a && *b) {
        char ca = *a, cb = *b;
        if (ca >= 'A' && ca <= 'Z') ca = (char)(ca - 'A' + 'a');
        if (cb >= 'A' && cb <= 'Z') cb = (char)(cb - 'A' + 'a');
        if (ca != cb) return 0;
        ++a; ++b;
    }
    return (*a == 0 && *b == 0);
}

static void _copy_trunc(char* dst, size_t cap, const char* src)
{
    size_t n;
    if (dst == NULL || cap == 0) return;
    if (src == NULL) { dst[0] = 0; return; }
    n = strlen(src);
    if (n >= cap) n = cap - 1;
    memcpy(dst, src, n);
    dst[n] = 0;
}

/* 跳过空白与注释（不支持嵌套注释，简化版） */
static const char* _skip_ws(const char* p, const char* end)
{
    while (p < end) {
        if (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') {
            ++p;
        } else {
            break;
        }
    }
    return p;
}

/* 解析双引号字符串到 out（截断到 cap-1）；返回指向闭合 " 之后的指针 */
static const char* _parse_string(const char* p, const char* end,
                                 char* out, size_t cap)
{
    if (p >= end || *p != '"') return NULL;
    ++p;
    if (cap > 0) out[0] = 0;
    {
        size_t pos = 0;
        while (p < end && *p != '"') {
            char c = *p;
            if (c == '\\' && p + 1 < end) {
                /* 仅处理常见转义；其他保持原样 */
                char nxt = p[1];
                char emit = c;
                switch (nxt) {
                    case '"':  emit = '"';  break;
                    case '\\': emit = '\\'; break;
                    case '/':  emit = '/';  break;
                    case 'b':  emit = '\b'; break;
                    case 'f':  emit = '\f'; break;
                    case 'n':  emit = '\n'; break;
                    case 'r':  emit = '\r'; break;
                    case 't':  emit = '\t'; break;
                    default:   emit = nxt;  break;
                }
                if (pos + 1 < cap) out[pos++] = emit;
                p += 2;
                continue;
            }
            if (pos + 1 < cap) out[pos++] = c;
            ++p;
        }
        if (p >= end || *p != '"') return NULL;
        ++p;
        if (cap > 0) out[pos < cap ? pos : cap - 1] = 0;
    }
    return p;
}

/* 解析字符串数组到已知 issues 二维数组 */
static const char* _parse_string_array(const char* p, const char* end,
                                       W7bCompatListEntry* e)
{
    if (p >= end || *p != '[') return NULL;
    ++p;
    e->known_issues_count = 0;
    p = _skip_ws(p, end);
    if (p < end && *p == ']') return p + 1;  /* 空数组 */

    while (p < end) {
        char issue[W7B_COMPAT_ISSUE_LEN_MAX];
        p = _skip_ws(p, end);
        if (p >= end) return NULL;
        p = _parse_string(p, end, issue, sizeof(issue));
        if (p == NULL) return NULL;
        if (e->known_issues_count < W7B_COMPAT_ISSUES_MAX) {
            _copy_trunc(e->known_issues[e->known_issues_count],
                        W7B_COMPAT_ISSUE_LEN_MAX, issue);
            ++e->known_issues_count;
        }
        p = _skip_ws(p, end);
        if (p < end && *p == ',') { ++p; continue; }
        if (p < end && *p == ']') return p + 1;
        return NULL;
    }
    return NULL;
}

/* 解析单个对象 {} 到 entry */
static const char* _parse_object(const char* p, const char* end,
                                 W7bCompatListEntry* e)
{
    char key[W7B_COMPAT_BASENAME_MAX];
    p = _skip_ws(p, end);
    if (p >= end || *p != '{') return NULL;
    ++p;

    /* 清零 entry */
    memset(e, 0, sizeof(*e));
    e->status = W7B_COMPAT_STATUS_UNKNOWN;

    p = _skip_ws(p, end);
    if (p < end && *p == '}') return p + 1;  /* 空对象 */

    while (p < end) {
        p = _skip_ws(p, end);
        p = _parse_string(p, end, key, sizeof(key));
        if (p == NULL) return NULL;
        p = _skip_ws(p, end);
        if (p >= end || *p != ':') return NULL;
        ++p;
        p = _skip_ws(p, end);

        if (_str_ieq(key, "exe_basename")) {
            p = _parse_string(p, end, e->exe_basename, W7B_COMPAT_BASENAME_MAX);
        } else if (_str_ieq(key, "publisher")) {
            p = _parse_string(p, end, e->publisher, W7B_COMPAT_PUBLISHER_MAX);
        } else if (_str_ieq(key, "status")) {
            char sval[32];
            p = _parse_string(p, end, sval, sizeof(sval));
            if (p == NULL) return NULL;
            e->status = w7b_compat_status_from_str(sval);
        } else if (_str_ieq(key, "tested_with")) {
            p = _parse_string(p, end, e->tested_with, W7B_COMPAT_TESTED_MAX);
        } else if (_str_ieq(key, "notes")) {
            p = _parse_string(p, end, e->notes, W7B_COMPAT_NOTES_MAX);
        } else if (_str_ieq(key, "known_issues")) {
            p = _parse_string_array(p, end, e);
        } else {
            /* 未知字段：跳过对应值（仅支持 string / array） */
            if (p < end && *p == '"') {
                char dummy[16];
                p = _parse_string(p, end, dummy, sizeof(dummy));
            } else if (p < end && *p == '[') {
                int depth = 0;
                while (p < end) {
                    if (*p == '[') ++depth;
                    else if (*p == ']') { --depth; if (depth == 0) { ++p; break; } }
                    ++p;
                }
            } else if (p < end && *p == '{') {
                int depth = 0;
                while (p < end) {
                    if (*p == '{') ++depth;
                    else if (*p == '}') { --depth; if (depth == 0) { ++p; break; } }
                    ++p;
                }
            } else {
                /* 数字/true/false/null：扫到下一个分隔符 */
                while (p < end && *p != ',' && *p != '}') ++p;
            }
        }
        if (p == NULL) return NULL;

        p = _skip_ws(p, end);
        if (p < end && *p == ',') { ++p; continue; }
        if (p < end && *p == '}') return p + 1;
        return NULL;
    }
    return NULL;
}

/* ------------------------------------------------------------------ */
/* 公共 API                                                            */
/* ------------------------------------------------------------------ */
int w7b_compat_list_load(const char* path, W7bCompatList* list)
{
    FILE* fp;
    long  fsize;
    char* buf;
    const char* p;
    const char* end;
    size_t cap = 0;

    if (list == NULL) return -1;
    list->entries  = NULL;
    list->count    = 0;
    list->capacity = 0;
    if (path == NULL) return -1;

    fp = fopen(path, "rb");
    if (fp == NULL) return 1;  /* 文件不存在：不算错误 */
    fseek(fp, 0, SEEK_END);
    fsize = ftell(fp);
    rewind(fp);
    if (fsize <= 0) { fclose(fp); return 1; }
    buf = (char*)malloc((size_t)fsize + 1);
    if (buf == NULL) { fclose(fp); return -1; }
    if (fread(buf, 1, (size_t)fsize, fp) != (size_t)fsize) {
        free(buf); fclose(fp); return -1;
    }
    fclose(fp);
    buf[fsize] = 0;

    p   = buf;
    end = buf + fsize;

    p = _skip_ws(p, end);
    if (p >= end || *p != '[') { free(buf); return -1; }
    ++p;
    p = _skip_ws(p, end);
    if (p < end && *p == ']') { free(buf); return 0; }  /* 空数组 */

    cap = 8;
    list->entries = (W7bCompatListEntry*)malloc(cap * sizeof(W7bCompatListEntry));
    if (list->entries == NULL) { free(buf); return -1; }
    list->capacity = cap;

    while (p < end) {
        W7bCompatListEntry e;
        p = _skip_ws(p, end);
        if (p < end && *p == ']') { ++p; break; }
        p = _parse_object(p, end, &e);
        if (p == NULL) {
            free(buf);
            w7b_compat_list_free(list);
            return -1;
        }
        if (list->count >= list->capacity) {
            size_t   new_cap = list->capacity * 2;
            W7bCompatListEntry* new_arr =
                (W7bCompatListEntry*)realloc(list->entries,
                                              new_cap * sizeof(W7bCompatListEntry));
            if (new_arr == NULL) {
                free(buf);
                w7b_compat_list_free(list);
                return -1;
            }
            list->entries  = new_arr;
            list->capacity = new_cap;
        }
        list->entries[list->count++] = e;
        p = _skip_ws(p, end);
        if (p < end && *p == ',') { ++p; continue; }
        if (p < end && *p == ']') { ++p; break; }
    }

    free(buf);
    return 0;
}

const W7bCompatListEntry* w7b_compat_list_lookup(
    const W7bCompatList* list, const char* exe_basename)
{
    size_t i;
    if (list == NULL || exe_basename == NULL) return NULL;
    for (i = 0; i < list->count; ++i) {
        if (_str_ieq(list->entries[i].exe_basename, exe_basename)) {
            return &list->entries[i];
        }
    }
    return NULL;
}

void w7b_compat_list_free(W7bCompatList* list)
{
    if (list == NULL) return;
    if (list->entries) free(list->entries);
    list->entries  = NULL;
    list->count    = 0;
    list->capacity = 0;
}

const char* w7b_compat_status_to_str(W7bCompatStatus s)
{
    switch (s) {
        case W7B_COMPAT_STATUS_WORKS:   return "works";
        case W7B_COMPAT_STATUS_LIMITED: return "limited";
        case W7B_COMPAT_STATUS_BROKEN:  return "broken";
        default:                        return "unknown";
    }
}

W7bCompatStatus w7b_compat_status_from_str(const char* s)
{
    if (s == NULL) return W7B_COMPAT_STATUS_UNKNOWN;
    if (_str_ieq(s, "works"))   return W7B_COMPAT_STATUS_WORKS;
    if (_str_ieq(s, "limited")) return W7B_COMPAT_STATUS_LIMITED;
    if (_str_ieq(s, "broken"))  return W7B_COMPAT_STATUS_BROKEN;
    return W7B_COMPAT_STATUS_UNKNOWN;
}
