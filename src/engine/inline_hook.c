/*
 * inline_hook.c - Win7Bridge L1 inline hook 与 x86/x64 指令长度解码器
 *
 * 实现 inline_hook.h 中的接口：
 *   - inline_hook_length_decode：最小但正确的 x86/x64 指令长度解码器，
 *     覆盖常见 prologue 指令（REX 前缀、MOV、SUB/ADD rsp,imm、
 *     JMP/CALL rel32、push/pop/inc/dec/nop/ret 等）
 *   - inline_hook_install：解码 target 前 N 字节，拷贝到 trampoline，
 *     追加跳回 target+N 的 jmp；Windows 下额外写 target 处 jmp detour
 *   - inline_hook_remove：释放 trampoline
 *
 * host 测试模式下因代码段不可写，install 仅做解码与 trampoline 构造，
 * 不实际 patch target，故可被 host 测试覆盖验证。
 */
#include "win7bridge/inline_hook.h"

#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* ------------------------------------------------------------------ */
/* 平台判定：是否为 64 位目标                                          */
/* ------------------------------------------------------------------ */
#if defined(_WIN64) || defined(__x86_64__) || defined(__LP64__) || \
    defined(__amd64__) || defined(__aarch64__)
#define IH_IS64 1
#else
#define IH_IS64 0
#endif

/* ------------------------------------------------------------------ */
/* 内部辅助：未对齐安全的小端整数写入                                  */
/* ------------------------------------------------------------------ */
static void ih_put32(unsigned char* p, int32_t v)
{
    memcpy(p, &v, sizeof(v));
}

static void ih_put64(unsigned char* p, uint64_t v)
{
    memcpy(p, &v, sizeof(v));
}

/* ------------------------------------------------------------------ */
/* ModR/M + SIB + 位移 长度解析                                        */
/* ------------------------------------------------------------------ */

/*
 * 解析从 ModR/M 字节起到位移结束的总长度（含 ModR/M 自身，不含操作码
 * 与立即数）。调用方需保证 p 至少指向足够字节（信任调用方保证可读）。
 *
 * ModR/M 字节：mod(7-6) reg(5-3) rm(2-0)
 *   mod==3：寄存器直接寻址，无后续
 *   mod!=3 且 rm==4：SIB 跟随
 *       SIB.base==5 且 mod==0：再跟 disp32
 *   mod==0 且 rm==5：disp32（32 位为 [disp32]，64 位为 [RIP+disp32]）
 *   mod==1：disp8
 *   mod==2：disp32
 */
static size_t ih_decode_modrm_len(const BYTE* p)
{
    BYTE modrm, mod, rm;
    size_t len = 1;  /* ModR/M 本身 */

    modrm = p[0];
    mod = (BYTE)((modrm >> 6) & 0x3);
    rm  = (BYTE)(modrm & 0x7);

    if (mod == 3) {
        return len;  /* 寄存器直接寻址 */
    }

    /* 内存操作数 */
    if (rm == 4) {
        /* SIB 跟随 */
        BYTE sib  = p[len];
        BYTE base = (BYTE)(sib & 0x7);
        len++;  /* SIB */
        if (mod == 0 && base == 5) {
            len += 4;  /* disp32 */
        }
    } else if (mod == 0 && rm == 5) {
        len += 4;  /* disp32 / RIP+disp32 */
    }

    if (mod == 1) {
        len += 1;  /* disp8 */
    } else if (mod == 2) {
        len += 4;  /* disp32 */
    }

    return len;
}

/* ------------------------------------------------------------------ */
/* inline_hook_length_decode                                           */
/* ------------------------------------------------------------------ */
int inline_hook_length_decode(const void* code, size_t min_len, size_t* out_len)
{
    const BYTE* p = (const BYTE*)code;
    size_t total = 0;

    if (code == NULL || out_len == NULL || min_len == 0) {
        return INLINE_HOOK_ERR_INVALID_ARG;
    }

    while (total < min_len) {
        BYTE op = p[total];

        /* REX 前缀（仅 64 位：0x40-0x4F） */
        if (IH_IS64 && op >= 0x40 && op <= 0x4F) {
            total++;
            continue;
        }

        /* 32 位下 0x40-0x4F 为 inc/dec reg（单字节） */
        if (!IH_IS64 && op >= 0x40 && op <= 0x4F) {
            total++;
            continue;
        }

        /* push reg (0x50-0x57) / pop reg (0x58-0x5F)：单字节 */
        if (op >= 0x50 && op <= 0x5F) {
            total++;
            continue;
        }

        /* nop (0x90) / ret (0xC3)：单字节 */
        if (op == 0x90 || op == 0xC3) {
            total++;
            continue;
        }

        /* MOV r/m,r / r,r/m (0x88-0x8B)：操作码 + ModR/M(+SIB+disp) */
        if (op >= 0x88 && op <= 0x8B) {
            size_t mlen = ih_decode_modrm_len(p + total + 1);
            total += 1 + mlen;
            continue;
        }

        /* 0x81 /n r/m, imm32（含 SUB/ADD rsp, imm32） */
        if (op == 0x81) {
            size_t mlen = ih_decode_modrm_len(p + total + 1);
            total += 1 + mlen + 4;
            continue;
        }

        /* 0x83 /n r/m, imm8（含 SUB/ADD rsp, imm8） */
        if (op == 0x83) {
            size_t mlen = ih_decode_modrm_len(p + total + 1);
            total += 1 + mlen + 1;
            continue;
        }

        /* JMP rel32 (0xE9) / CALL rel32 (0xE8)：5 字节 */
        if (op == 0xE9 || op == 0xE8) {
            total += 5;
            continue;
        }

        /* 未识别的操作码 */
        return INLINE_HOOK_ERR_UNKNOWN_OPCODE;
    }

    *out_len = total;
    return INLINE_HOOK_OK;
}

/* ------------------------------------------------------------------ */
/* Windows 下 VirtualProtect 外部声明（不 include windows.h）          */
/* ------------------------------------------------------------------ */
#if defined(_WIN32) && !defined(WIN7BRIDGE_HOST_TEST) && !defined(WIN7BRIDGE_SYNTAX_CHECK)
extern __declspec(dllimport) int __stdcall
VirtualProtect(void* lpAddress, size_t dwSize,
               unsigned long flNewProtect, unsigned long* lpflOldProtect);
#define IH_PAGE_EXECUTE_READWRITE 0x40U
#endif

/* ------------------------------------------------------------------ */
/* inline_hook_install                                                 */
/* ------------------------------------------------------------------ */
int inline_hook_install(InlineHook* h, void* target, void* detour)
{
    size_t min_len = INLINE_HOOK_JMP_LEN;  /* x86=5, x64=14 */
    size_t patch_len = 0;
    int rc;
    unsigned char* tramp;
    unsigned char* jmp;

    if (h == NULL || target == NULL || detour == NULL) {
        return INLINE_HOOK_ERR_INVALID_ARG;
    }

    /* 1) 解码 target 前 N 字节，得到需拷贝的完整指令序列长度 */
    rc = inline_hook_length_decode(target, min_len, &patch_len);
    if (rc != INLINE_HOOK_OK) {
        return rc;
    }
    if (patch_len < min_len ||
        patch_len > INLINE_HOOK_TRAMPOLINE_MAX - INLINE_HOOK_JMP_LEN) {
        return INLINE_HOOK_ERR_DECODE;
    }

    /* 2) 分配 trampoline 缓冲区 */
    tramp = (unsigned char*)malloc(INLINE_HOOK_TRAMPOLINE_MAX);
    if (tramp == NULL) {
        return INLINE_HOOK_ERR_ALLOC;
    }

    /* 3) 拷贝 target 处的原始指令到 trampoline */
    memcpy(tramp, target, patch_len);

    /* 4) 在 trampoline 末尾追加跳回 target+patch_len 的 jmp */
    jmp = tramp + patch_len;
#if INLINE_HOOK_JMP_LEN == 5
    /* x86: E9 rel32  （rel = dst - (jmp+5)） */
    {
        int32_t rel = (int32_t)((const unsigned char*)target + patch_len - (jmp + 5));
        jmp[0] = 0xE9;
        ih_put32(jmp + 1, rel);
    }
#else
    /* x64: FF 25 00 00 00 00 <abs64>  （jmp qword ptr [rip+0]） */
    jmp[0] = 0xFF;
    jmp[1] = 0x25;
    ih_put32(jmp + 2, 0);
    ih_put64(jmp + 6, (uint64_t)(uintptr_t)((const unsigned char*)target + patch_len));
#endif

    h->target     = target;
    h->detour     = detour;
    h->trampoline = tramp;
    h->patch_size = patch_len;

    /* 5) 在 target 处写入跳往 detour 的 jmp
     *    host/syntax-check 下代码段不可写，跳过实际 patch；调用方仅通过
     *    trampoline 与 length_decode 的成功返回判断构造是否成功。 */
#if defined(_WIN32) && !defined(WIN7BRIDGE_HOST_TEST) && !defined(WIN7BRIDGE_SYNTAX_CHECK)
    {
        unsigned long old_prot = 0;
        unsigned char* t = (unsigned char*)target;
        if (VirtualProtect(target, patch_len,
                           IH_PAGE_EXECUTE_READWRITE, &old_prot) == 0) {
            free(tramp);
            h->trampoline = NULL;
            return INLINE_HOOK_ERR_PROTECT;
        }
#if INLINE_HOOK_JMP_LEN == 5
        {
            int32_t rel = (int32_t)((const unsigned char*)detour - (t + 5));
            t[0] = 0xE9;
            ih_put32(t + 1, rel);
        }
#else
        t[0] = 0xFF;
        t[1] = 0x25;
        ih_put32(t + 2, 0);
        ih_put64(t + 6, (uint64_t)(uintptr_t)detour);
#endif
        {
            unsigned long tmp = 0;
            VirtualProtect(target, patch_len, old_prot, &tmp);
        }
    }
#endif

    return INLINE_HOOK_OK;
}

/* ------------------------------------------------------------------ */
/* inline_hook_remove                                                  */
/* ------------------------------------------------------------------ */
int inline_hook_remove(InlineHook* h)
{
    if (h == NULL) {
        return INLINE_HOOK_ERR_INVALID_ARG;
    }
    if (h->trampoline != NULL) {
        free(h->trampoline);
    }
    h->target     = NULL;
    h->detour     = NULL;
    h->trampoline = NULL;
    h->patch_size = 0;
    return INLINE_HOOK_OK;
}
