/*
 * cng_chacha20.c - Win7Bridge CNG ChaCha20-Poly1305 AEAD 算法实现
 *
 * 实现 cng_chacha20.h 中的接口：
 *   - ChaCha20 流密码（RFC 8439 §2.3）：20 轮 ARX，64 字节块
 *   - Poly1305 MAC（RFC 8439 §2.4）：130 位模运算，5×26 位肢
 *   - AEAD 组合（RFC 8439 §2.8）：counter=0 生成 Poly1305 密钥，
 *     counter=1 加密明文，MAC 输入 = pad16(AAD) || pad16(CT) || le64(len)
 *
 * 纯算法无平台依赖，不使用任何 Windows 专有 API；不引用
 * <windows.h>。可在原生 gcc 下 host 测试。
 *
 * 所有多字节整数按小端序处理（ChaCha20/Poly1305 规范要求）。
 */
#include "win7bridge/cng_chacha20.h"

#include <stdint.h>
#include <stddef.h>
#include <string.h>

/* ================================================================== */
/* 辅助：小端加载/存储                                                 */
/* ================================================================== */

static uint32_t le32_load(const uint8_t* p)
{
    return ((uint32_t)p[0])       |
           ((uint32_t)p[1] <<  8) |
           ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

static void le32_store(uint8_t* p, uint32_t v)
{
    p[0] = (uint8_t)(v);
    p[1] = (uint8_t)(v >>  8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

static void le64_store(uint8_t* p, uint64_t v)
{
    p[0] = (uint8_t)(v);
    p[1] = (uint8_t)(v >>  8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
    p[4] = (uint8_t)(v >> 32);
    p[5] = (uint8_t)(v >> 40);
    p[6] = (uint8_t)(v >> 48);
    p[7] = (uint8_t)(v >> 56);
}

/* 32 位循环左移 */
#define ROTL32(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

/* ================================================================== */
/* ChaCha20 流密码（RFC 8439 §2.3）                                   */
/* ================================================================== */

/* ChaCha20 常量 "expand 32-byte k" */
static const uint32_t CHACHA20_SIGMA[4] = {
    0x61707865u, 0x3320646eu, 0x79622d32u, 0x6b206574u
};

/* quarter round */
#define QR(a, b, c, d)                  \
    do {                                \
        a += b; d ^= a; d = ROTL32(d, 16); \
        c += d; b ^= c; b = ROTL32(b, 12); \
        a += b; d ^= a; d = ROTL32(d,  8); \
        c += d; b ^= c; b = ROTL32(b,  7); \
    } while (0)

/*
 * chacha20_block - 生成一个 64 字节密钥流块
 *   key[32]    ：密钥
 *   counter    ：块计数器
 *   nonce[12]  ：nonce
 *   out[64]    ：输出密钥流
 */
static void chacha20_block(const uint8_t key[32], uint32_t counter,
                           const uint8_t nonce[12], uint8_t out[64])
{
    uint32_t s[16];
    uint32_t x[16];
    int i;

    /* 初始化状态（RFC 8439 §2.3） */
    s[ 0] = CHACHA20_SIGMA[0];
    s[ 1] = CHACHA20_SIGMA[1];
    s[ 2] = CHACHA20_SIGMA[2];
    s[ 3] = CHACHA20_SIGMA[3];
    s[ 4] = le32_load(key +  0);
    s[ 5] = le32_load(key +  4);
    s[ 6] = le32_load(key +  8);
    s[ 7] = le32_load(key + 12);
    s[ 8] = le32_load(key + 16);
    s[ 9] = le32_load(key + 20);
    s[10] = le32_load(key + 24);
    s[11] = le32_load(key + 28);
    s[12] = counter;
    s[13] = le32_load(nonce + 0);
    s[14] = le32_load(nonce + 4);
    s[15] = le32_load(nonce + 8);

    memcpy(x, s, sizeof(s));

    /* 20 轮 = 10 次双轮 */
    for (i = 0; i < 10; ++i) {
        /* 列轮 */
        QR(x[0], x[4], x[ 8], x[12]);
        QR(x[1], x[5], x[ 9], x[13]);
        QR(x[2], x[6], x[10], x[14]);
        QR(x[3], x[7], x[11], x[15]);
        /* 对角线轮 */
        QR(x[0], x[5], x[10], x[15]);
        QR(x[1], x[6], x[11], x[12]);
        QR(x[2], x[7], x[ 8], x[13]);
        QR(x[3], x[4], x[ 9], x[14]);
    }

    /* 加上原始状态并输出 */
    for (i = 0; i < 16; ++i) {
        le32_store(out + (size_t)i * 4, x[i] + s[i]);
    }
}

/* ------------------------------------------------------------------ */
/* 公开接口：cng_chacha20_xor                                          */
/* ------------------------------------------------------------------ */
void cng_chacha20_xor(const uint8_t key[32], uint32_t counter,
                      const uint8_t nonce[12],
                      const uint8_t* in, uint8_t* out, size_t length)
{
    uint8_t block[CNG_CHACHA20_BLOCK_SIZE];
    size_t offset = 0;

    if (key == NULL || nonce == NULL || (in == NULL && length > 0) ||
        (out == NULL && length > 0)) {
        return;
    }

    while (offset < length) {
        size_t chunk = length - offset;
        size_t i;
        if (chunk > CNG_CHACHA20_BLOCK_SIZE) {
            chunk = CNG_CHACHA20_BLOCK_SIZE;
        }
        chacha20_block(key, counter, nonce, block);
        for (i = 0; i < chunk; ++i) {
            out[offset + i] = in[offset + i] ^ block[i];
        }
        offset += chunk;
        counter++;
    }
}

/* ================================================================== */
/* Poly1305 MAC（RFC 8439 §2.4）                                      */
/* ================================================================== */
/*
 * Poly1305 使用 130 位模运算，模数 p = 2^130 - 5。
 * 累加器 h 和密钥 r 用 5 个 26 位肢表示：h = h[0] + h[1]*2^26 + ... + h[4]*2^104
 */

#define POLY1305_BLOCK_SIZE 16
#define MASK26              0x3ffffffu

/* Poly1305 内部状态 */
typedef struct {
    uint32_t h[5];    /* 累加器（5×26 位）                 */
    uint32_t r[5];    /* 密钥 r（5×26 位，已 clamp）       */
    uint32_t s[4];    /* 密钥 s（4×32 位，小端）           */
    uint8_t  buf[POLY1305_BLOCK_SIZE];
    size_t   buf_len;
} poly1305_state;

/* 将 16 字节小端块加载为 5×26 位肢 + 高位 1 */
static void poly1305_load_block(uint32_t h[5], const uint8_t m[16])
{
    uint64_t t0 = (uint64_t)le32_load(m + 0);
    uint64_t t1 = (uint64_t)le32_load(m + 4);
    uint64_t t2 = (uint64_t)le32_load(m + 8);
    uint64_t t3 = (uint64_t)le32_load(m + 12);

    /* 拼成 128 位整数再加 2^128 */
    /* h = m[0..15] 作为小端整数，再添加第 17 个字节 0x01 */
    /* 用 5×26 位肢表示 */
    uint64_t h0_64 = t0;
    uint64_t h1_64 = (t0 >> 26) | (t1 << 6);
    uint64_t h2_64 = (t1 >> 20) | (t2 << 12);
    uint64_t h3_64 = (t2 >> 14) | (t3 << 18);
    uint64_t h4_64 = (t3 >> 8) | ((uint64_t)1 << 24);  /* 高位 1 在 bit 128 */

    h[0] = (uint32_t)(h0_64 & MASK26);
    h[1] = (uint32_t)(h1_64 & MASK26);
    h[2] = (uint32_t)(h2_64 & MASK26);
    h[3] = (uint32_t)(h3_64 & MASK26);
    h[4] = (uint32_t)(h4_64 & MASK26);
}

/* 初始化 Poly1305 状态 */
static void poly1305_init(poly1305_state* st, const uint8_t key[32])
{
    uint64_t t0, t1;

    /* 加载 r（key[0..15]）并 clamp */
    t0 = (uint64_t)le32_load(key + 0) | ((uint64_t)le32_load(key + 4) << 32);
    t1 = (uint64_t)le32_load(key + 8) | ((uint64_t)le32_load(key + 12) << 32);

    /* clamp: r &= 0x0ffffffc0ffffffc0ffffffc0fffffff */
    t0 &= 0x0ffffffc0fffffffULL;
    t1 &= 0x0ffffffc0ffffffcULL;

    /* 转换为 5×26 位肢 */
    st->r[0] = (uint32_t)(t0 & MASK26);
    st->r[1] = (uint32_t)((t0 >> 26) & MASK26);
    st->r[2] = (uint32_t)(((t0 >> 52) | (t1 << 12)) & MASK26);
    st->r[3] = (uint32_t)((t1 >> 14) & MASK26);
    st->r[4] = (uint32_t)((t1 >> 40) & MASK26);

    /* 加载 s（key[16..31]） */
    st->s[0] = le32_load(key + 16);
    st->s[1] = le32_load(key + 20);
    st->s[2] = le32_load(key + 24);
    st->s[3] = le32_load(key + 28);

    /* 累加器归零 */
    st->h[0] = st->h[1] = st->h[2] = st->h[3] = st->h[4] = 0;
    st->buf_len = 0;
}

/* 处理一个 16 字节完整块（含高位 1） */
static void poly1305_process_block(poly1305_state* st, const uint8_t m[16])
{
    uint32_t h0, h1, h2, h3, h4;
    uint32_t r0, r1, r2, r3, r4;
    uint32_t s1, s2, s3, s4;   /* r[i] * 5，用于模约减         */
    uint64_t d0, d1, d2, d3, d4;
    uint32_t c;
    uint32_t m_h[5];

    r0 = st->r[0]; r1 = st->r[1]; r2 = st->r[2]; r3 = st->r[3]; r4 = st->r[4];
    s1 = r1 * 5; s2 = r2 * 5; s3 = r3 * 5; s4 = r4 * 5;

    h0 = st->h[0]; h1 = st->h[1]; h2 = st->h[2]; h3 = st->h[3]; h4 = st->h[4];

    /* 加载消息块（含高位 1） */
    poly1305_load_block(m_h, m);
    h0 += m_h[0]; h1 += m_h[1]; h2 += m_h[2]; h3 += m_h[3]; h4 += m_h[4];

    /* h = h * r（schoolbook 乘法，利用 2^130 ≡ 5 mod p 约减） */
    d0 = (uint64_t)h0 * r0 + (uint64_t)h1 * s4 + (uint64_t)h2 * s3 + (uint64_t)h3 * s2 + (uint64_t)h4 * s1;
    d1 = (uint64_t)h0 * r1 + (uint64_t)h1 * r0 + (uint64_t)h2 * s4 + (uint64_t)h3 * s3 + (uint64_t)h4 * s2;
    d2 = (uint64_t)h0 * r2 + (uint64_t)h1 * r1 + (uint64_t)h2 * r0 + (uint64_t)h3 * s4 + (uint64_t)h4 * s3;
    d3 = (uint64_t)h0 * r3 + (uint64_t)h1 * r2 + (uint64_t)h2 * r1 + (uint64_t)h3 * r0 + (uint64_t)h4 * s4;
    d4 = (uint64_t)h0 * r4 + (uint64_t)h1 * r3 + (uint64_t)h2 * r2 + (uint64_t)h3 * r1 + (uint64_t)h4 * r0;

    /* 进位传播 */
    c = (uint32_t)(d0 >> 26); h0 = (uint32_t)d0 & MASK26;
    d1 += c; c = (uint32_t)(d1 >> 26); h1 = (uint32_t)d1 & MASK26;
    d2 += c; c = (uint32_t)(d2 >> 26); h2 = (uint32_t)d2 & MASK26;
    d3 += c; c = (uint32_t)(d3 >> 26); h3 = (uint32_t)d3 & MASK26;
    d4 += c; c = (uint32_t)(d4 >> 26); h4 = (uint32_t)d4 & MASK26;
    h0 += c * 5; c = (h0 >> 26); h0 = h0 & MASK26;
    h1 += c;

    st->h[0] = h0; st->h[1] = h1; st->h[2] = h2; st->h[3] = h3; st->h[4] = h4;
}

/* 处理最后一个不完整块（补零，高位 1 在实际字节处） */
static void poly1305_process_partial(poly1305_state* st,
                                     const uint8_t* m, size_t len)
{
    uint8_t block[POLY1305_BLOCK_SIZE];
    size_t i;

    memset(block, 0, POLY1305_BLOCK_SIZE);
    for (i = 0; i < len; ++i) {
        block[i] = m[i];
    }
    block[len] = 1;  /* 高位 1 */

    /* 对不完整块，高位 1 在 len 字节处而非第 16 字节处。
     * 上面 poly1305_load_block 硬编码了高位 1 在 bit 128（第 16 字节），
     * 所以这里需要手动处理。我们直接构造肢。 */
    {
        uint32_t h0, h1, h2, h3, h4;
        uint32_t r0, r1, r2, r3, r4;
        uint32_t s1, s2, s3, s4;
        uint64_t d0, d1, d2, d3, d4;
        uint32_t c;
        uint32_t m_h[5];
        uint64_t t0, t1, t2, t3;

        /* 将 len+1 字节的小端整数加载为 5×26 位肢 */
        /* block[0..len] = 消息字节 || 0x01，其余为 0 */
        t0 = (uint64_t)le32_load(block + 0);
        t1 = (len >= 4) ? (uint64_t)le32_load(block + 4) : 0;
        t2 = (len >= 8) ? (uint64_t)le32_load(block + 8) : 0;
        t3 = (len >= 12) ? (uint64_t)le32_load(block + 12) : 0;

        /* 对于不完整块，高位 1 已在 block[len] 中 */
        /* 重新计算肢（不加 2^128，因为高位 1 在不同位置） */
        {
            uint64_t h0_64 = t0;
            uint64_t h1_64 = (t0 >> 26) | (t1 << 6);
            uint64_t h2_64 = (t1 >> 20) | (t2 << 12);
            uint64_t h3_64 = (t2 >> 14) | (t3 << 18);
            uint64_t h4_64 = (t3 >> 8);

            m_h[0] = (uint32_t)(h0_64 & MASK26);
            m_h[1] = (uint32_t)(h1_64 & MASK26);
            m_h[2] = (uint32_t)(h2_64 & MASK26);
            m_h[3] = (uint32_t)(h3_64 & MASK26);
            m_h[4] = (uint32_t)(h4_64 & MASK26);
        }

        r0 = st->r[0]; r1 = st->r[1]; r2 = st->r[2]; r3 = st->r[3]; r4 = st->r[4];
        s1 = r1 * 5; s2 = r2 * 5; s3 = r3 * 5; s4 = r4 * 5;

        h0 = st->h[0] + m_h[0];
        h1 = st->h[1] + m_h[1];
        h2 = st->h[2] + m_h[2];
        h3 = st->h[3] + m_h[3];
        h4 = st->h[4] + m_h[4];

        d0 = (uint64_t)h0 * r0 + (uint64_t)h1 * s4 + (uint64_t)h2 * s3 + (uint64_t)h3 * s2 + (uint64_t)h4 * s1;
        d1 = (uint64_t)h0 * r1 + (uint64_t)h1 * r0 + (uint64_t)h2 * s4 + (uint64_t)h3 * s3 + (uint64_t)h4 * s2;
        d2 = (uint64_t)h0 * r2 + (uint64_t)h1 * r1 + (uint64_t)h2 * r0 + (uint64_t)h3 * s4 + (uint64_t)h4 * s3;
        d3 = (uint64_t)h0 * r3 + (uint64_t)h1 * r2 + (uint64_t)h2 * r1 + (uint64_t)h3 * r0 + (uint64_t)h4 * s4;
        d4 = (uint64_t)h0 * r4 + (uint64_t)h1 * r3 + (uint64_t)h2 * r2 + (uint64_t)h3 * r1 + (uint64_t)h4 * r0;

        c = (uint32_t)(d0 >> 26); h0 = (uint32_t)d0 & MASK26;
        d1 += c; c = (uint32_t)(d1 >> 26); h1 = (uint32_t)d1 & MASK26;
        d2 += c; c = (uint32_t)(d2 >> 26); h2 = (uint32_t)d2 & MASK26;
        d3 += c; c = (uint32_t)(d3 >> 26); h3 = (uint32_t)d3 & MASK26;
        d4 += c; c = (uint32_t)(d4 >> 26); h4 = (uint32_t)d4 & MASK26;
        h0 += c * 5; c = (h0 >> 26); h0 = h0 & MASK26;
        h1 += c;

        st->h[0] = h0; st->h[1] = h1; st->h[2] = h2; st->h[3] = h3; st->h[4] = h4;
    }
}

/* 最终化：完全约减，加 s，输出 16 字节标签 */
static void poly1305_final(poly1305_state* st, uint8_t tag[16])
{
    uint32_t h0, h1, h2, h3, h4;
    uint32_t g0, g1, g2, g3, g4;
    uint32_t c, mask;
    uint32_t t0, t1, t2, t3;
    uint64_t f, sum;

    h0 = st->h[0]; h1 = st->h[1]; h2 = st->h[2]; h3 = st->h[3]; h4 = st->h[4];

    /* 完全约减 h mod (2^130 - 5)：先做一次进位传播保证 h < 2^130      */
    c = h1 >> 26; h1 &= MASK26;
    h2 += c; c = h2 >> 26; h2 &= MASK26;
    h3 += c; c = h3 >> 26; h3 &= MASK26;
    h4 += c; c = h4 >> 26; h4 &= MASK26;
    h0 += c * 5; c = h0 >> 26; h0 &= MASK26;
    h1 += c;

    /* 计算 g = h + 5 - 2^130 = h - p                                  */
    /* 若 g >= 0（即 h >= p）则取 g；否则保留 h                         */
    g0 = h0 + 5; c = g0 >> 26; g0 &= MASK26;
    g1 = h1 + c; c = g1 >> 26; g1 &= MASK26;
    g2 = h2 + c; c = g2 >> 26; g2 &= MASK26;
    g3 = h3 + c; c = g3 >> 26; g3 &= MASK26;
    g4 = h4 + c - (1u << 26);  /* 减 2^130（h4 位于 2^104，bit26 对应 2^130） */

    /* g4 < 0 时（最高位为 1）mask=0，取 h；否则 mask=0xffffffff，取 g */
    mask = (g4 >> 31) - 1u;
    h0 = (h0 & ~mask) | (g0 & mask);
    h1 = (h1 & ~mask) | (g1 & mask);
    h2 = (h2 & ~mask) | (g2 & mask);
    h3 = (h3 & ~mask) | (g3 & mask);
    h4 = (h4 & ~mask) | (g4 & mask);

    /* 将 5×26 位肢转回 4×32 位小端整数 */
    f = ((uint64_t)h0)       |
        ((uint64_t)h1 << 26) |
        ((uint64_t)h2 << 52);
    t0 = (uint32_t)f;
    t1 = (uint32_t)(f >> 32);

    f = ((uint64_t)(h2 >> 12)) |
        ((uint64_t)h3 << 14)   |
        ((uint64_t)h4 << 40);
    t2 = (uint32_t)f;
    t3 = (uint32_t)(f >> 32);

    /* 加 s（128 位小端加法） */
    sum = (uint64_t)t0 + st->s[0];
    t0 = (uint32_t)sum;
    c  = (uint32_t)(sum >> 32);

    sum = (uint64_t)t1 + st->s[1] + c;
    t1 = (uint32_t)sum;
    c  = (uint32_t)(sum >> 32);

    sum = (uint64_t)t2 + st->s[2] + c;
    t2 = (uint32_t)sum;
    c  = (uint32_t)(sum >> 32);

    sum = (uint64_t)t3 + st->s[3] + c;
    t3 = (uint32_t)sum;

    le32_store(tag +  0, t0);
    le32_store(tag +  4, t1);
    le32_store(tag +  8, t2);
    le32_store(tag + 12, t3);
}

/* ------------------------------------------------------------------ */
/* 公开接口：cng_poly1305_mac                                          */
/* ------------------------------------------------------------------ */
void cng_poly1305_mac(const uint8_t key[32],
                      const uint8_t* msg, size_t msg_len,
                      uint8_t tag[16])
{
    poly1305_state st;
    size_t offset = 0;

    if (key == NULL || tag == NULL) {
        return;
    }
    poly1305_init(&st, key);

    /* 处理完整块 */
    while (offset + POLY1305_BLOCK_SIZE <= msg_len) {
        poly1305_process_block(&st, msg + offset);
        offset += POLY1305_BLOCK_SIZE;
    }

    /* 处理最后的不完整块 */
    if (offset < msg_len) {
        poly1305_process_partial(&st, msg + offset, msg_len - offset);
    }

    /* 如果消息长度为 0，也需处理一个 0x01 块 */
    if (msg_len == 0) {
        poly1305_process_partial(&st, NULL, 0);
    }

    poly1305_final(&st, tag);
}

/* ================================================================== */
/* ChaCha20-Poly1305 AEAD（RFC 8439 §2.8）                            */
/* ================================================================== */

/* 将数据 pad 到 16 字节边界（用 0 填充） */
static void pad16(poly1305_state* st, const uint8_t* data, size_t len)
{
    size_t i;
    uint8_t zeros[POLY1305_BLOCK_SIZE];

    if (len == 0) return;

    /* 处理完整块 */
    i = 0;
    while (i + POLY1305_BLOCK_SIZE <= len) {
        poly1305_process_block(st, data + i);
        i += POLY1305_BLOCK_SIZE;
    }

    /* 处理剩余 */
    if (i < len) {
        memset(zeros, 0, POLY1305_BLOCK_SIZE);
        memcpy(zeros, data + i, len - i);
        poly1305_process_block(st, zeros);
    }
}

/* ------------------------------------------------------------------ */
/* 公开接口：cng_chacha20_poly1305_encrypt                            */
/* ------------------------------------------------------------------ */
void cng_chacha20_poly1305_encrypt(const uint8_t key[32],
                                   const uint8_t nonce[12],
                                   const uint8_t* aad, size_t aad_len,
                                   const uint8_t* plaintext, size_t pt_len,
                                   uint8_t* ciphertext, uint8_t tag[16])
{
    uint8_t poly_key[64];  /* ChaCha20 counter=0 的输出，取前 32 字节 */
    poly1305_state mac_st;

    if (key == NULL || nonce == NULL || tag == NULL) {
        return;
    }

    /* 1) 生成 Poly1305 密钥：ChaCha20(key, counter=0, nonce) 前 32 字节 */
    chacha20_block(key, 0, nonce, poly_key);

    /* 2) 加密明文：ChaCha20(key, counter=1, nonce) */
    cng_chacha20_xor(key, 1, nonce, plaintext, ciphertext, pt_len);

    /* 3) 计算 Poly1305 MAC */
    poly1305_init(&mac_st, poly_key);

    /* MAC 输入 = pad16(AAD) || pad16(CT) || le64(aad_len) || le64(ct_len)
     * 注意：两个 le64 长度字段共 16 字节，作为一个完整块处理（加 2^128） */
    pad16(&mac_st, aad, aad_len);
    pad16(&mac_st, ciphertext, pt_len);

    {
        uint8_t len_block[POLY1305_BLOCK_SIZE];
        le64_store(len_block + 0, (uint64_t)aad_len);
        le64_store(len_block + 8, (uint64_t)pt_len);
        poly1305_process_block(&mac_st, len_block);
    }

    poly1305_final(&mac_st, tag);

    /* 清除敏感数据 */
    memset(poly_key, 0, sizeof(poly_key));
}

/* ------------------------------------------------------------------ */
/* 公开接口：cng_chacha20_poly1305_decrypt                            */
/* ------------------------------------------------------------------ */
int cng_chacha20_poly1305_decrypt(const uint8_t key[32],
                                  const uint8_t nonce[12],
                                  const uint8_t* aad, size_t aad_len,
                                  const uint8_t* ciphertext, size_t ct_len,
                                  const uint8_t tag[16],
                                  uint8_t* plaintext)
{
    uint8_t poly_key[64];
    uint8_t computed_tag[CNG_POLY1305_TAG_SIZE];
    poly1305_state mac_st;

    if (key == NULL || nonce == NULL || tag == NULL) {
        return -1;
    }

    /* 1) 生成 Poly1305 密钥 */
    chacha20_block(key, 0, nonce, poly_key);

    /* 2) 计算 MAC */
    poly1305_init(&mac_st, poly_key);

    pad16(&mac_st, aad, aad_len);
    pad16(&mac_st, ciphertext, ct_len);

    /* MAC 输入 = pad16(AAD) || pad16(CT) || le64(aad_len) || le64(ct_len)
     * 两个 le64 长度字段共 16 字节，作为一个完整块处理（加 2^128） */
    {
        uint8_t len_block[POLY1305_BLOCK_SIZE];
        le64_store(len_block + 0, (uint64_t)aad_len);
        le64_store(len_block + 8, (uint64_t)ct_len);
        poly1305_process_block(&mac_st, len_block);
    }

    poly1305_final(&mac_st, computed_tag);

    /* 3) 常量时间比较 tag */
    {
        uint8_t diff = 0;
        size_t i;
        for (i = 0; i < CNG_POLY1305_TAG_SIZE; ++i) {
            diff |= computed_tag[i] ^ tag[i];
        }
        if (diff != 0) {
            memset(poly_key, 0, sizeof(poly_key));
            return -1;
        }
    }

    /* 4) tag 校验通过，解密 */
    cng_chacha20_xor(key, 1, nonce, ciphertext, plaintext, ct_len);

    memset(poly_key, 0, sizeof(poly_key));
    return 0;
}
