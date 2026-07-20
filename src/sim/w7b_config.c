/*
 * w7b_config.c - Win7Bridge 按程序粒度配置存储实现
 *
 * 设计目标见 docs/per-program-config.md：
 *   - 每个目标 EXE 一份 JSON 配置文件，存于 per-user 目录（不写 HKLM）
 *   - 极简递归下降 JSON 解析器，纯 C，零外部依赖
 *   - schema 与 scripts/config_gen.py 输出兼容；未知字段一律跳过
 *   - 平台隔离：Win7 GetEnvironmentVariableA("APPDATA")；host getenv
 */
#include "win7bridge/w7b_config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------ */
/* 平台隔离：默认配置目录                                               */
/* ------------------------------------------------------------------ */
#if defined(_WIN32) && !defined(WIN7BRIDGE_HOST_TEST)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#define W7B_CFG_GETENV(name, buf, cap) \
    GetEnvironmentVariableA((name), (buf), (unsigned long)(cap))
#define W7B_CFG_PATH_SEP '\\'
#else
#include <stdlib.h>
#define W7B_CFG_GETENV(name, buf, cap)  \
    (((getenv(name) != NULL) &&                         \
      (strlen(getenv(name)) < (cap)))                   \
        ? (strncpy((buf), getenv(name), (cap) - 1),     \
           (buf)[(cap) - 1] = 0,                        \
           (unsigned long)strlen(buf))                  \
        : 0u)
#define W7B_CFG_PATH_SEP '/'
#endif

/* ------------------------------------------------------------------ */
/* 内部辅助：basename / 路径拼接                                       */
/* ------------------------------------------------------------------ */

/* 从路径中提取基名（最后一个 \ 或 / 之后的部分；不含则返回原串） */
static const char* path_basename(const char* p)
{
    const char* base = p;
    if (p == NULL) return "";
    while (*p) {
        if (*p == '\\' || *p == '/') {
            base = p + 1;
        }
        ++p;
    }
    return base;
}

/* 把单个字符安全追加到 dst（带容量检查） */
static int buf_append_char(char* dst, size_t dst_cap, size_t* pos, char c)
{
    if (*pos + 1 >= dst_cap) return -1;
    dst[*pos] = c;
    ++(*pos);
    return 0;
}

/* 把 NUL 结尾字符串追加到 dst（带容量检查） */
static int buf_append_str(char* dst, size_t dst_cap, size_t* pos,
                          const char* s)
{
    size_t n = strlen(s);
    if (*pos + n + 1 >= dst_cap) return -1;
    memcpy(dst + *pos, s, n);
    *pos += n;
    return 0;
}

/* ------------------------------------------------------------------ */
/* w7b_config_default_dir                                              */
/* ------------------------------------------------------------------ */
int w7b_config_default_dir(char* out, size_t out_cap)
{
    char   env_buf[512];
    size_t env_len;
    size_t pos = 0;
    const char* suffix_dir = "Win7Bridge";
    const char* suffix_cfg = "configs";

    if (out == NULL || out_cap == 0) return -1;
    out[0] = 0;

    env_buf[0] = 0;
    env_buf[sizeof(env_buf) - 1] = 0;
    if (W7B_CFG_GETENV("APPDATA", env_buf, sizeof(env_buf) - 1) == 0) {
        /* APPDATA 取不到：host 下回退 HOME，再不行用 . */
        env_buf[0] = 0;
        if (W7B_CFG_GETENV("HOME", env_buf, sizeof(env_buf) - 1) == 0) {
            env_buf[0] = 0;
        }
    }
    env_len = strlen(env_buf);

    if (env_len > 0) {
        if (buf_append_str(out, out_cap, &pos, env_buf) != 0) return -1;
        /* 末尾补分隔符 */
        if (out[pos - 1] != '\\' && out[pos - 1] != '/') {
            if (buf_append_char(out, out_cap, &pos,
                                (char)W7B_CFG_PATH_SEP) != 0) return -1;
        }
    } else {
        /* 都没拿到：用 ./win7bridge_configs */
        if (buf_append_str(out, out_cap, &pos, ".") != 0) return -1;
        if (buf_append_char(out, out_cap, &pos,
                            (char)W7B_CFG_PATH_SEP) != 0) return -1;
    }

    if (buf_append_str(out, out_cap, &pos, suffix_dir) != 0) return -1;
    if (buf_append_char(out, out_cap, &pos, (char)W7B_CFG_PATH_SEP) != 0) return -1;
    if (buf_append_str(out, out_cap, &pos, suffix_cfg) != 0) return -1;
    if (buf_append_char(out, out_cap, &pos, (char)W7B_CFG_PATH_SEP) != 0) return -1;

    if (pos + 1 > out_cap) return -1;
    out[pos] = 0;
    return 0;
}

/* ------------------------------------------------------------------ */
/* w7b_config_path_for                                                 */
/* ------------------------------------------------------------------ */
int w7b_config_path_for(const char* exe_path,
                        const char* config_dir,
                        char* out, size_t out_cap)
{
    char   dir_buf[512];
    size_t pos = 0;
    const char* base;

    if (out == NULL || out_cap == 0) return -1;
    out[0] = 0;

    if (config_dir == NULL) {
        if (w7b_config_default_dir(dir_buf, sizeof(dir_buf)) != 0) return -1;
        config_dir = dir_buf;
    }

    if (buf_append_str(out, out_cap, &pos, config_dir) != 0) return -1;
    /* 末尾补分隔符 */
    if (pos > 0 && out[pos - 1] != '\\' && out[pos - 1] != '/') {
        if (buf_append_char(out, out_cap, &pos,
                            (char)W7B_CFG_PATH_SEP) != 0) return -1;
    }

    base = path_basename(exe_path);
    if (base[0] == 0) {
        /* exe_path 为 NULL 或空：用 "default" 占位 */
        base = "default.exe";
    }
    if (buf_append_str(out, out_cap, &pos, base) != 0) return -1;
    if (buf_append_str(out, out_cap, &pos, ".json") != 0) return -1;

    out[pos] = 0;
    return 0;
}

/* ------------------------------------------------------------------ */
/* w7b_config_set_defaults                                             */
/* ------------------------------------------------------------------ */
void w7b_config_set_defaults(W7bProgramConfig* cfg, const char* exe_path)
{
    const char* base;
    if (cfg == NULL) return;

    memset(cfg, 0, sizeof(*cfg));

    cfg->enabled                 = 1;
    cfg->version_spoof_enabled   = 1;
    cfg->spoof_major             = 10;
    cfg->spoof_minor             = 0;
    cfg->spoof_build             = 19041;
    cfg->fix_subsystem_version   = 1;
    cfg->strip_bound_imports     = 1;
    cfg->log_level               = 1;   /* INFO */
    cfg->diag_report_on_exit     = 0;
    strcpy(cfg->injection_path, "loader");

    if (exe_path != NULL) {
        size_t n = strlen(exe_path);
        if (n >= W7B_CONFIG_EXE_PATH_MAX) n = W7B_CONFIG_EXE_PATH_MAX - 1;
        memcpy(cfg->exe_path, exe_path, n);
        cfg->exe_path[n] = 0;

        base = path_basename(exe_path);
        n = strlen(base);
        if (n >= W7B_CONFIG_BASENAME_MAX) n = W7B_CONFIG_BASENAME_MAX - 1;
        memcpy(cfg->exe_basename, base, n);
        cfg->exe_basename[n] = 0;
    }
}

/* ------------------------------------------------------------------ */
/* JSON 解析器（极简递归下降，与 apiset.c 风格一致）                     */
/* ------------------------------------------------------------------ */
typedef struct {
    const char* buf;
    size_t      pos;
    size_t      len;
    int         error;   /* 非 0 表示出错 */
} CfgParser;

static void cfg_skip_ws(CfgParser* p)
{
    while (p->pos < p->len) {
        char c = p->buf[p->pos];
        if (c == ' ' || c == '\t' || c == '\r' || c == '\n') {
            ++p->pos;
            continue;
        }
        /* 行注释 // */
        if (c == '/' && p->pos + 1 < p->len && p->buf[p->pos + 1] == '/') {
            p->pos += 2;
            while (p->pos < p->len && p->buf[p->pos] != '\n') ++p->pos;
            continue;
        }
        /* 块注释 块注释开始 */
        if (c == '/' && p->pos + 1 < p->len && p->buf[p->pos + 1] == '*') {
            p->pos += 2;
            while (p->pos + 1 < p->len &&
                   !(p->buf[p->pos] == '*' && p->buf[p->pos + 1] == '/')) {
                ++p->pos;
            }
            if (p->pos + 1 < p->len) p->pos += 2;
            else p->pos = p->len;
            continue;
        }
        break;
    }
}

/* 解析 JSON 字符串到 out（带容量截断）；成功返回 0 */
static int cfg_parse_string(CfgParser* p, char* out, size_t out_cap)
{
    size_t pos = 0;
    if (out_cap == 0) { p->error = 1; return -1; }
    cfg_skip_ws(p);
    if (p->pos >= p->len || p->buf[p->pos] != '"') { p->error = 1; return -1; }
    ++p->pos;
    while (p->pos < p->len) {
        char c = p->buf[p->pos++];
        if (c == '"') {
            out[pos] = 0;
            return 0;
        }
        if (c == '\\' && p->pos < p->len) {
            char e = p->buf[p->pos++];
            switch (e) {
                case '"':  c = '"';  break;
                case '\\': c = '\\'; break;
                case '/':  c = '/';  break;
                case 'n':  c = '\n'; break;
                case 't':  c = '\t'; break;
                case 'r':  c = '\r'; break;
                case 'b':  c = '\b'; break;
                case 'f':  c = '\f'; break;
                default:   c = e;    break;
            }
        }
        if (pos + 1 < out_cap) {
            out[pos++] = c;
        }
        /* 超出容量则截断，但继续解析到结束引号 */
    }
    p->error = 1;
    out[pos < out_cap ? pos : out_cap - 1] = 0;
    return -1;
}

/* 解析整数 */
static int cfg_parse_int(CfgParser* p, int* out)
{
    int sign = 1;
    long val = 0;
    int has_digit = 0;
    cfg_skip_ws(p);
    if (p->pos < p->len && p->buf[p->pos] == '-') {
        sign = -1;
        ++p->pos;
    }
    while (p->pos < p->len &&
           p->buf[p->pos] >= '0' && p->buf[p->pos] <= '9') {
        val = val * 10 + (p->buf[p->pos] - '0');
        ++p->pos;
        has_digit = 1;
    }
    if (!has_digit) { p->error = 1; return -1; }
    *out = (int)(sign * val);
    return 0;
}

/* 解析 true / false */
static int cfg_parse_bool(CfgParser* p, int* out)
{
    cfg_skip_ws(p);
    if (p->pos + 4 <= p->len &&
        memcmp(p->buf + p->pos, "true", 4) == 0) {
        *out = 1; p->pos += 4; return 0;
    }
    if (p->pos + 5 <= p->len &&
        memcmp(p->buf + p->pos, "false", 5) == 0) {
        *out = 0; p->pos += 5; return 0;
    }
    p->error = 1;
    return -1;
}

/* 跳过任意 JSON 值（对象/数组/字符串/数字/字面量），用于未知字段 */
static void cfg_skip_value(CfgParser* p)
{
    int depth;
    cfg_skip_ws(p);
    if (p->pos >= p->len) { p->error = 1; return; }

    switch (p->buf[p->pos]) {
        case '"': {
            char tmp[4];
            cfg_parse_string(p, tmp, sizeof(tmp));
            return;
        }
        case '{':
        case '[': {
            char close = (p->buf[p->pos] == '{') ? '}' : ']';
            char open  = p->buf[p->pos];
            depth = 1;
            ++p->pos;
            while (p->pos < p->len && depth > 0) {
                char c = p->buf[p->pos];
                if (c == '"') {
                    char tmp[4];
                    cfg_parse_string(p, tmp, sizeof(tmp));
                    if (p->error) return;
                    continue;
                }
                if (c == open) ++depth;
                else if (c == close) --depth;
                ++p->pos;
            }
            return;
        }
        default:
            /* 数字或字面量（true/false/null）：扫到下一个分隔符 */
            while (p->pos < p->len) {
                char c = p->buf[p->pos];
                if (c == ',' || c == '}' || c == ']' ||
                    c == ' ' || c == '\t' || c == '\n' || c == '\r') {
                    break;
                }
                ++p->pos;
            }
            return;
    }
}

/* 期待一个字符 */
static int cfg_expect(CfgParser* p, char c)
{
    cfg_skip_ws(p);
    if (p->pos >= p->len || p->buf[p->pos] != c) {
        p->error = 1;
        return -1;
    }
    ++p->pos;
    return 0;
}

/* log_level 字符串 -> 整数；默认 INFO */
static int parse_log_level(const char* s)
{
    if (strcmp(s, "debug") == 0) return 0;
    if (strcmp(s, "info")  == 0) return 1;
    if (strcmp(s, "warn")  == 0) return 2;
    if (strcmp(s, "error") == 0) return 3;
    return 1;
}

/* log_level 整数 -> 字符串 */
static const char* log_level_name(int lvl)
{
    switch (lvl) {
        case 0:  return "debug";
        case 1:  return "info";
        case 2:  return "warn";
        case 3:  return "error";
        default: return "info";
    }
}

/* 解析 version_spoof 子对象 */
static void parse_version_spoof(CfgParser* p, W7bProgramConfig* cfg)
{
    if (cfg_expect(p, '{') != 0) return;
    cfg_skip_ws(p);
    while (p->pos < p->len && p->buf[p->pos] != '}' && !p->error) {
        char key[64];
        if (cfg_parse_string(p, key, sizeof(key)) != 0) return;
        if (cfg_expect(p, ':') != 0) return;
        cfg_skip_ws(p);
        if (strcmp(key, "enabled") == 0) {
            cfg_parse_bool(p, &cfg->version_spoof_enabled);
        } else if (strcmp(key, "major") == 0) {
            cfg_parse_int(p, &cfg->spoof_major);
        } else if (strcmp(key, "minor") == 0) {
            cfg_parse_int(p, &cfg->spoof_minor);
        } else if (strcmp(key, "build") == 0) {
            cfg_parse_int(p, &cfg->spoof_build);
        } else {
            cfg_skip_value(p);
        }
        if (p->error) return;
        cfg_skip_ws(p);
        if (p->pos < p->len && p->buf[p->pos] == ',') {
            ++p->pos; cfg_skip_ws(p);
        }
    }
    cfg_expect(p, '}');
}

/* 解析 pe_fixes 子对象 */
static void parse_pe_fixes(CfgParser* p, W7bProgramConfig* cfg)
{
    if (cfg_expect(p, '{') != 0) return;
    cfg_skip_ws(p);
    while (p->pos < p->len && p->buf[p->pos] != '}' && !p->error) {
        char key[64];
        if (cfg_parse_string(p, key, sizeof(key)) != 0) return;
        if (cfg_expect(p, ':') != 0) return;
        cfg_skip_ws(p);
        if (strcmp(key, "fix_subsystem_version") == 0) {
            cfg_parse_bool(p, &cfg->fix_subsystem_version);
        } else if (strcmp(key, "strip_bound_imports") == 0) {
            cfg_parse_bool(p, &cfg->strip_bound_imports);
        } else {
            cfg_skip_value(p);
        }
        if (p->error) return;
        cfg_skip_ws(p);
        if (p->pos < p->len && p->buf[p->pos] == ',') {
            ++p->pos; cfg_skip_ws(p);
        }
    }
    cfg_expect(p, '}');
}

/* 解析 diag_report 子对象 */
static void parse_diag_report(CfgParser* p, W7bProgramConfig* cfg)
{
    if (cfg_expect(p, '{') != 0) return;
    cfg_skip_ws(p);
    while (p->pos < p->len && p->buf[p->pos] != '}' && !p->error) {
        char key[64];
        if (cfg_parse_string(p, key, sizeof(key)) != 0) return;
        if (cfg_expect(p, ':') != 0) return;
        cfg_skip_ws(p);
        if (strcmp(key, "on_exit") == 0) {
            cfg_parse_bool(p, &cfg->diag_report_on_exit);
        } else if (strcmp(key, "path") == 0) {
            cfg_parse_string(p, cfg->diag_report_path,
                             sizeof(cfg->diag_report_path));
        } else {
            cfg_skip_value(p);
        }
        if (p->error) return;
        cfg_skip_ws(p);
        if (p->pos < p->len && p->buf[p->pos] == ',') {
            ++p->pos; cfg_skip_ws(p);
        }
    }
    cfg_expect(p, '}');
}

/* 解析 apiset_overlays 数组（字符串数组） */
static void parse_apiset_overlays(CfgParser* p, W7bProgramConfig* cfg)
{
    if (cfg_expect(p, '[') != 0) return;
    cfg_skip_ws(p);
    cfg->apiset_overlays_count = 0;
    while (p->pos < p->len && p->buf[p->pos] != ']' && !p->error) {
        if (cfg->apiset_overlays_count >= W7B_CONFIG_OVERLAY_MAX) {
            /* 超出上限：跳过剩余元素 */
            char tmp[4];
            cfg_parse_string(p, tmp, sizeof(tmp));
            if (p->error) return;
            cfg_skip_ws(p);
            if (p->pos < p->len && p->buf[p->pos] == ',') {
                ++p->pos; cfg_skip_ws(p);
            }
            continue;
        }
        if (cfg_parse_string(p,
                cfg->apiset_overlays[cfg->apiset_overlays_count],
                W7B_CONFIG_OVERLAY_PATH_MAX) != 0) {
            return;
        }
        ++cfg->apiset_overlays_count;
        cfg_skip_ws(p);
        if (p->pos < p->len && p->buf[p->pos] == ',') {
            ++p->pos; cfg_skip_ws(p);
        }
    }
    cfg_expect(p, ']');
}

/* 解析顶层对象 */
static void parse_top_object(CfgParser* p, W7bProgramConfig* cfg)
{
    if (cfg_expect(p, '{') != 0) return;
    cfg_skip_ws(p);
    while (p->pos < p->len && p->buf[p->pos] != '}' && !p->error) {
        char key[64];
        if (cfg_parse_string(p, key, sizeof(key)) != 0) return;
        if (cfg_expect(p, ':') != 0) return;
        cfg_skip_ws(p);

        if (strcmp(key, "schema") == 0) {
            char tmp[64];
            cfg_parse_string(p, tmp, sizeof(tmp));
            /* 不严格校验 schema 值，向前兼容 */
        } else if (strcmp(key, "exe_path") == 0) {
            cfg_parse_string(p, cfg->exe_path, sizeof(cfg->exe_path));
        } else if (strcmp(key, "exe_basename") == 0) {
            cfg_parse_string(p, cfg->exe_basename, sizeof(cfg->exe_basename));
        } else if (strcmp(key, "enabled") == 0) {
            cfg_parse_bool(p, &cfg->enabled);
        } else if (strcmp(key, "injection_path") == 0) {
            cfg_parse_string(p, cfg->injection_path,
                             sizeof(cfg->injection_path));
        } else if (strcmp(key, "version_spoof") == 0) {
            parse_version_spoof(p, cfg);
        } else if (strcmp(key, "pe_fixes") == 0) {
            parse_pe_fixes(p, cfg);
        } else if (strcmp(key, "log_level") == 0) {
            char tmp[16];
            if (cfg_parse_string(p, tmp, sizeof(tmp)) == 0) {
                cfg->log_level = parse_log_level(tmp);
            }
        } else if (strcmp(key, "diag_report") == 0) {
            parse_diag_report(p, cfg);
        } else if (strcmp(key, "apiset_overlays") == 0) {
            parse_apiset_overlays(p, cfg);
        } else {
            cfg_skip_value(p);
        }

        if (p->error) return;
        cfg_skip_ws(p);
        if (p->pos < p->len && p->buf[p->pos] == ',') {
            ++p->pos; cfg_skip_ws(p);
        }
    }
    cfg_expect(p, '}');
}

/* ------------------------------------------------------------------ */
/* w7b_config_load                                                     */
/* ------------------------------------------------------------------ */
int w7b_config_load(const char* path, W7bProgramConfig* cfg)
{
    FILE*       fp;
    long        sz;
    char*       buf;
    CfgParser   p;
    int         rc = 0;

    if (path == NULL || cfg == NULL) return -1;

    /* 先填默认值：解析失败也保证 cfg 可用 */
    w7b_config_set_defaults(cfg, NULL);

    fp = fopen(path, "rb");
    if (fp == NULL) {
        return 1;  /* 文件不存在 */
    }
    fseek(fp, 0, SEEK_END);
    sz = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    if (sz < 0) {
        fclose(fp);
        return -1;
    }
    buf = (char*)malloc((size_t)sz + 1);
    if (buf == NULL) {
        fclose(fp);
        return -1;
    }
    if (fread(buf, 1, (size_t)sz, fp) != (size_t)sz) {
        free(buf);
        fclose(fp);
        return -1;
    }
    buf[sz] = 0;
    fclose(fp);

    p.buf   = buf;
    p.pos   = 0;
    p.len   = (size_t)sz;
    p.error = 0;

    parse_top_object(&p, cfg);

    if (p.error) {
        /* 解析失败：cfg 已被部分修改，重置为默认值 */
        w7b_config_set_defaults(cfg, NULL);
        rc = -1;
    }

    free(buf);
    return rc;
}

/* ------------------------------------------------------------------ */
/* w7b_config_save                                                     */
/* ------------------------------------------------------------------ */

/* 把字符串以 JSON 转义形式写入 fp（处理 " 与 \） */
static int json_write_string(FILE* fp, const char* s)
{
    if (fputc('"', fp) == EOF) return -1;
    while (*s) {
        char c = *s++;
        if (c == '"' || c == '\\') {
            if (fputc('\\', fp) == EOF) return -1;
            if (fputc(c,   fp) == EOF) return -1;
        } else if (c == '\n') {
            if (fputs("\\n", fp) == EOF) return -1;
        } else if (c == '\r') {
            if (fputs("\\r", fp) == EOF) return -1;
        } else if (c == '\t') {
            if (fputs("\\t", fp) == EOF) return -1;
        } else if ((unsigned char)c < 0x20) {
            if (fprintf(fp, "\\u%04x", (unsigned char)c) < 0) return -1;
        } else {
            if (fputc(c, fp) == EOF) return -1;
        }
    }
    if (fputc('"', fp) == EOF) return -1;
    return 0;
}

int w7b_config_save(const char* path, const W7bProgramConfig* cfg)
{
    FILE*    fp;
    size_t   i;
    int      err = 0;

    if (path == NULL || cfg == NULL) return -1;

    fp = fopen(path, "wb");
    if (fp == NULL) return -1;

    if (fputs("{\n", fp) == EOF) { err = -1; goto done; }
    if (fputs("  \"schema\": \"win7bridge.config/v1\",\n", fp) == EOF) { err = -1; goto done; }

    if (fputs("  \"exe_path\": ", fp) == EOF) { err = -1; goto done; }
    if (json_write_string(fp, cfg->exe_path) != 0) { err = -1; goto done; }
    if (fputs(",\n", fp) == EOF) { err = -1; goto done; }

    if (fputs("  \"exe_basename\": ", fp) == EOF) { err = -1; goto done; }
    if (json_write_string(fp, cfg->exe_basename) != 0) { err = -1; goto done; }
    if (fputs(",\n", fp) == EOF) { err = -1; goto done; }

    if (fprintf(fp, "  \"enabled\": %s,\n",
                cfg->enabled ? "true" : "false") < 0) { err = -1; goto done; }

    if (fputs("  \"injection_path\": ", fp) == EOF) { err = -1; goto done; }
    if (json_write_string(fp, cfg->injection_path) != 0) { err = -1; goto done; }
    if (fputs(",\n", fp) == EOF) { err = -1; goto done; }

    /* version_spoof 子对象 */
    if (fputs("  \"version_spoof\": {\n", fp) == EOF) { err = -1; goto done; }
    if (fprintf(fp, "    \"enabled\": %s,\n",
                cfg->version_spoof_enabled ? "true" : "false") < 0) { err = -1; goto done; }
    if (fprintf(fp, "    \"major\": %d,\n", cfg->spoof_major) < 0) { err = -1; goto done; }
    if (fprintf(fp, "    \"minor\": %d,\n", cfg->spoof_minor) < 0) { err = -1; goto done; }
    if (fprintf(fp, "    \"build\": %d\n",  cfg->spoof_build) < 0) { err = -1; goto done; }
    if (fputs("  },\n", fp) == EOF) { err = -1; goto done; }

    /* pe_fixes 子对象 */
    if (fputs("  \"pe_fixes\": {\n", fp) == EOF) { err = -1; goto done; }
    if (fprintf(fp, "    \"fix_subsystem_version\": %s,\n",
                cfg->fix_subsystem_version ? "true" : "false") < 0) { err = -1; goto done; }
    if (fprintf(fp, "    \"strip_bound_imports\": %s\n",
                cfg->strip_bound_imports ? "true" : "false") < 0) { err = -1; goto done; }
    if (fputs("  },\n", fp) == EOF) { err = -1; goto done; }

    /* log_level */
    if (fputs("  \"log_level\": ", fp) == EOF) { err = -1; goto done; }
    if (json_write_string(fp, log_level_name(cfg->log_level)) != 0) { err = -1; goto done; }
    if (fputs(",\n", fp) == EOF) { err = -1; goto done; }

    /* diag_report 子对象 */
    if (fputs("  \"diag_report\": {\n", fp) == EOF) { err = -1; goto done; }
    if (fprintf(fp, "    \"on_exit\": %s,\n",
                cfg->diag_report_on_exit ? "true" : "false") < 0) { err = -1; goto done; }
    if (fputs("    \"path\": ", fp) == EOF) { err = -1; goto done; }
    if (json_write_string(fp, cfg->diag_report_path) != 0) { err = -1; goto done; }
    if (fputs("\n  },\n", fp) == EOF) { err = -1; goto done; }

    /* apiset_overlays 数组 */
    if (fputs("  \"apiset_overlays\": [", fp) == EOF) { err = -1; goto done; }
    for (i = 0; i < cfg->apiset_overlays_count; ++i) {
        if (i > 0) {
            if (fputs(",", fp) == EOF) { err = -1; goto done; }
        }
        if (fputs("\n    ", fp) == EOF) { err = -1; goto done; }
        if (json_write_string(fp, cfg->apiset_overlays[i]) != 0) { err = -1; goto done; }
    }
    if (cfg->apiset_overlays_count > 0) {
        if (fputs("\n  ", fp) == EOF) { err = -1; goto done; }
    }
    if (fputs("]\n", fp) == EOF) { err = -1; goto done; }

    if (fputs("}\n", fp) == EOF) { err = -1; goto done; }

done:
    fclose(fp);
    return err;
}
