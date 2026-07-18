/*
 * pe_patch_cli.c - pe_patch.exe 的命令行包装器
 *
 * 调用 Win7Bridge 的 PE 解析与修正功能：
 *   - pe_parse 解析 PE 文件
 *   - pe_fix_subsystem 修正子系统版本（10.0 -> 6.1）
 *   - pe_strip_bound_imports 剥离绑定导入
 *   - pe_set_subsystem_version 主动设置子系统版本（测试用）
 *
 * 纯文件 I/O，不依赖 windows.h，host 和 Win7 均可编译运行。
 *
 * 用法：
 *   pe_patch.exe <input.exe> <output.exe> [options]
 *     --fix-subsystem       修正子系统版本 > 6.1 为 6.1
 *     --strip-bound         剥离绑定导入
 *     --default             两者都做（默认）
 *     --set-subsystem M.N   主动设置子系统版本为 M.N（测试用，制造坏 EXE）
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "win7bridge/pe.h"

static void usage(const char* prog)
{
    printf("Usage: %s <input.exe> <output.exe> [options]\n", prog);
    printf("Options:\n");
    printf("  --fix-subsystem       Fix MajorSubsystemVersion > 6.1 to 6.1\n");
    printf("  --strip-bound         Strip bound imports (set TimeDateStamp=0)\n");
    printf("  --default             Both (default if no option given)\n");
    printf("  --set-subsystem M.N   Set subsystem version to M.N (e.g. 10.0)\n");
}

int main(int argc, char** argv)
{
    const char* in_path = NULL;
    const char* out_path = NULL;
    int do_fix = 0;
    int do_strip = 0;
    int do_set = 0;
    WORD set_major = 0, set_minor = 0;
    int i;
    FILE* fin = NULL;
    FILE* fout = NULL;
    long sz;
    void* buf = NULL;
    PeInfo pe;
    int rc;
    WORD orig_major = 0, orig_minor = 0;
    int changed = 0;

    if (argc < 3) {
        usage(argv[0]);
        return 1;
    }

    in_path = argv[1];
    out_path = argv[2];

    for (i = 3; i < argc; ++i) {
        if (strcmp(argv[i], "--fix-subsystem") == 0) {
            do_fix = 1;
        } else if (strcmp(argv[i], "--strip-bound") == 0) {
            do_strip = 1;
        } else if (strcmp(argv[i], "--default") == 0) {
            do_fix = 1; do_strip = 1;
        } else if (strcmp(argv[i], "--set-subsystem") == 0) {
            if (i + 1 >= argc) { fprintf(stderr, "--set-subsystem needs M.N\n"); return 1; }
            ++i;
            if (sscanf(argv[i], "%hu.%hu", &set_major, &set_minor) != 2) {
                fprintf(stderr, "Invalid version: %s (expected M.N)\n", argv[i]);
                return 1;
            }
            do_set = 1;
        } else {
            fprintf(stderr, "Unknown option: %s\n", argv[i]);
            return 1;
        }
    }
    if (!do_fix && !do_strip && !do_set) {
        do_fix = 1; do_strip = 1;
    }

    /* 读输入文件 */
    fin = fopen(in_path, "rb");
    if (!fin) { fprintf(stderr, "Cannot open input: %s\n", in_path); return 2; }
    fseek(fin, 0, SEEK_END);
    sz = ftell(fin);
    fseek(fin, 0, SEEK_SET);
    buf = malloc((size_t)sz);
    if (!buf) { fclose(fin); return 2; }
    if (fread(buf, 1, (size_t)sz, fin) != (size_t)sz) {
        fclose(fin); free(buf); return 2;
    }
    fclose(fin);

    /* 解析 PE */
    rc = pe_parse(buf, (size_t)sz, &pe);
    if (rc != PE_OK) {
        fprintf(stderr, "pe_parse failed: %d\n", rc);
        free(buf);
        return 2;
    }

    pe_get_subsystem_version(&pe, &orig_major, &orig_minor);
    printf("Original subsystem: %u.%u\n", orig_major, orig_minor);
    printf("Is PE32+: %s\n", pe.is64 ? "yes" : "no");

    /* 主动设置子系统版本（测试用，制造"坏"EXE） */
    if (do_set) {
        if (pe.major_subsystem && pe.minor_subsystem) {
            *pe.major_subsystem = set_major;
            *pe.minor_subsystem = set_minor;
        }
        if (pe.major_os && pe.minor_os) {
            *pe.major_os = set_major;
            *pe.minor_os = set_minor;
        }
        printf("subsystem_set: %u.%u -> %u.%u\n",
               orig_major, orig_minor, set_major, set_minor);
        changed = 1;
    }

    /* 修正子系统版本 */
    if (do_fix) {
        rc = pe_fix_subsystem(&pe);
        if (rc > 0) {
            printf("subsystem_fixed: 1 (%u.%u -> 6.1)\n", orig_major, orig_minor);
            changed = 1;
        } else if (rc == 0) {
            printf("subsystem_fixed: 0 (already 6.1 or lower)\n");
        } else {
            fprintf(stderr, "pe_fix_subsystem error: %d\n", rc);
            free(buf);
            return 2;
        }
    }

    /* 剥离 bound import */
    if (do_strip) {
        rc = pe_strip_bound_imports(&pe);
        if (rc > 0) {
            printf("bound_stripped: 1 (%d descriptors zeroed)\n", rc);
            changed = 1;
        } else if (rc == 0) {
            printf("bound_stripped: 0 (no bound imports)\n");
        } else {
            fprintf(stderr, "pe_strip_bound_imports error: %d\n", rc);
            free(buf);
            return 2;
        }
    }

    /* 写输出文件：始终写，即使无变更也复制一份 */
    fout = fopen(out_path, "wb");
    if (!fout) { fprintf(stderr, "Cannot open output: %s\n", out_path); free(buf); return 2; }
    if (fwrite(buf, 1, (size_t)sz, fout) != (size_t)sz) {
        fclose(fout); free(buf); return 2;
    }
    fclose(fout);

    if (changed) {
        printf("RESULT: PASS (patched -> %s)\n", out_path);
    } else {
        printf("RESULT: PASS (no change needed, copied -> %s)\n", out_path);
    }

    free(buf);
    return 0;
}
