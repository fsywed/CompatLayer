/*
 * cng_hkdf.c - Win7Bridge CNG HKDF 算法实现
 *
 * 实现 cng_hkdf.h 中的接口：
 *   - SHA-256（FIPS 180-4）：流式上下文 + 64 字节块压缩 + padding
 *   - HMAC-SHA256（RFC 2104）：key>64B 先 hash；ipad=0x36 / opad=0x5c
 *   - HKDF-Extract（RFC 5869 §2.2）：PRK = HMAC(salt, IKM)
 *   - HKDF-Expand（RFC 5869 §2.3）：T(N)=HMAC(PRK, T(N-1)|info|N)
 *   - HKDF 一步式：先 extract 再 expand
 *
 * 纯算法无平台依赖，不使用任何 Windows 专有 API；不引用
 * <windows.h>。可在原生 gcc 下 host 测试。
 *
 * 字节序：所有多字节整数（W 调度字、长度字段）均按大端序显式拼装，
 * 不依赖宿主机字节序。
 */
#include "win7bridge/cng_hkdf.h"

#include <stdint.h>
#include <stddef.h>
#include <string.h>

/* ------------------------------------------------------------------ */
/* SHA-256 内部实现                                                    */
/* ------------------------------------------------------------------ */

/* SHA-256 块大小（字节）与摘要长度                                   */
#define SHA256_BLOCK_SIZE  64
/* 摘要长度复用 CNG_HKDF_SHA256_HASH_SIZE (32)                         */

/* 旋转右移                                                            */
#define ROTR32(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

/* SHA-256 函数（FIPS 180-4 §4.1.2）                                  */
#define CH(x, y, z)  (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define BSIG0(x)     (ROTR32((x), 2)  ^ ROTR32((x), 13) ^ ROTR32((x), 22))
#define BSIG1(x)     (ROTR32((x), 6)  ^ ROTR32((x), 11) ^ ROTR32((x), 25))
#define SSIG0(x)     (ROTR32((x), 7)  ^ ROTR32((x), 18) ^ ((x) >> 3))
#define SSIG1(x)     (ROTR32((x), 17) ^ ROTR32((x), 19) ^ ((x) >> 10))

/* 初始哈希值 H0..H7（FIPS 180-4 §5.3.3）                            */
static const uint32_t k_sha256_h0[8] = {
    0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
    0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u
};

/* 轮常量 K[0..63]（FIPS 180-4 §4.2.2）                              */
static const uint32_t k_sha256_k[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u,
    0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
    0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
    0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
    0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu,
    0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u,
    0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
    0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
    0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u,
    0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u,
    0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
    0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u
};

/* SHA-256 流式上下文                                                  */
typedef struct {
    uint32_t h[8];           /* 状态字（H0..H7）                       */
    uint64_t total_len;      /* 已输入总字节数                         */
    uint8_t  buf[SHA256_BLOCK_SIZE]; /* 待压缩块缓冲                  */
    size_t   buf_len;        /* buf 中已有字节数                       */
} sha256_ctx_t;

/* 大端加载：从 4 字节拼装 uint32                                      */
static uint32_t sha256_load_be32(const uint8_t* p)
{
    return ((uint32_t)p[0] << 24) |
           ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] <<  8) |
           ((uint32_t)p[3]);
}

/* 大端存储：uint32 拆为 4 字节                                        */
static void sha256_store_be32(uint8_t* p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >>  8);
    p[3] = (uint8_t)(v);
}

/* 大端存储：uint64 拆为 8 字节                                        */
static void sha256_store_be64(uint8_t* p, uint64_t v)
{
    p[0] = (uint8_t)(v >> 56);
    p[1] = (uint8_t)(v >> 48);
    p[2] = (uint8_t)(v >> 40);
    p[3] = (uint8_t)(v >> 32);
    p[4] = (uint8_t)(v >> 24);
    p[5] = (uint8_t)(v >> 16);
    p[6] = (uint8_t)(v >>  8);
    p[7] = (uint8_t)(v);
}

/* 初始化上下文                                                        */
static void sha256_init(sha256_ctx_t* ctx)
{
    int i;
    for (i = 0; i < 8; ++i) {
        ctx->h[i] = k_sha256_h0[i];
    }
    ctx->total_len = 0;
    ctx->buf_len   = 0;
}

/* 压缩单个 64 字节块（FIPS 180-4 §6.2.2）                           */
static void sha256_transform(sha256_ctx_t* ctx, const uint8_t block[SHA256_BLOCK_SIZE])
{
    uint32_t w[64];
    uint32_t a, b, c, d, e, f, g, h;
    int t;

    /* 1) 前 16 字从块按大端加载                                       */
    for (t = 0; t < 16; ++t) {
        w[t] = sha256_load_be32(block + (size_t)t * 4);
    }
    /* 2) 后 48 字由消息调度扩展                                       */
    for (t = 16; t < 64; ++t) {
        w[t] = SSIG1(w[t - 2]) + w[t - 7] + SSIG0(w[t - 15]) + w[t - 16];
    }

    /* 3) 初始化工作变量                                              */
    a = ctx->h[0]; b = ctx->h[1]; c = ctx->h[2]; d = ctx->h[3];
    e = ctx->h[4]; f = ctx->h[5]; g = ctx->h[6]; h = ctx->h[7];

    /* 4) 64 轮压缩                                                   */
    for (t = 0; t < 64; ++t) {
        uint32_t t1 = h + BSIG1(e) + CH(e, f, g) + k_sha256_k[t] + w[t];
        uint32_t t2 = BSIG0(a) + MAJ(a, b, c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }

    /* 5) 累加到状态                                                  */
    ctx->h[0] += a; ctx->h[1] += b; ctx->h[2] += c; ctx->h[3] += d;
    ctx->h[4] += e; ctx->h[5] += f; ctx->h[6] += g; ctx->h[7] += h;
}

/* 流式追加数据                                                        */
static void sha256_update(sha256_ctx_t* ctx, const uint8_t* data, size_t len)
{
    size_t i = 0;

    ctx->total_len += (uint64_t)len;

    /* 先填满 buf 中残余                                              */
    if (ctx->buf_len > 0) {
        size_t need = SHA256_BLOCK_SIZE - ctx->buf_len;
        size_t take = (len < need) ? len : need;
        memcpy(ctx->buf + ctx->buf_len, data, take);
        ctx->buf_len += take;
        i += take;
        if (ctx->buf_len == SHA256_BLOCK_SIZE) {
            sha256_transform(ctx, ctx->buf);
            ctx->buf_len = 0;
        }
    }

    /* 逐块处理中间完整块                                            */
    while (i + SHA256_BLOCK_SIZE <= len) {
        sha256_transform(ctx, data + i);
        i += SHA256_BLOCK_SIZE;
    }

    /* 残余存入 buf                                                   */
    if (i < len) {
        size_t remain = len - i;
        memcpy(ctx->buf, data + i, remain);
        ctx->buf_len = remain;
    }
}

/* 结束并输出 32 字节摘要                                              */
static void sha256_final(sha256_ctx_t* ctx, uint8_t out[32])
{
    uint64_t bit_len = ctx->total_len * 8ULL;
    size_t i;

    /* padding：0x80 + 0x00* + 8 字节大端 bit 长度                    */
    ctx->buf[ctx->buf_len++] = 0x80u;
    if (ctx->buf_len > 56) {
        /* 当前块放不下长度字段，先填零压缩一块                        */
        while (ctx->buf_len < SHA256_BLOCK_SIZE) {
            ctx->buf[ctx->buf_len++] = 0x00u;
        }
        sha256_transform(ctx, ctx->buf);
        ctx->buf_len = 0;
    }
    while (ctx->buf_len < 56) {
        ctx->buf[ctx->buf_len++] = 0x00u;
    }
    sha256_store_be64(ctx->buf + 56, bit_len);
    sha256_transform(ctx, ctx->buf);

    /* 输出大端摘要                                                   */
    for (i = 0; i < 8; ++i) {
        sha256_store_be32(out + i * 4, ctx->h[i]);
    }
}

/* ------------------------------------------------------------------ */
/* 公开接口：cng_sha256                                                */
/* ------------------------------------------------------------------ */
void cng_sha256(const uint8_t* data, size_t len, uint8_t out[32])
{
    sha256_ctx_t ctx;
    sha256_init(&ctx);
    if (data != NULL && len > 0) {
        sha256_update(&ctx, data, len);
    }
    sha256_final(&ctx, out);
}

/* ------------------------------------------------------------------ */
/* 公开接口：cng_hmac_sha256（RFC 2104）                              */
/* ------------------------------------------------------------------ */
void cng_hmac_sha256(const uint8_t* key, size_t key_len,
                     const uint8_t* data, size_t data_len,
                     uint8_t out[32])
{
    uint8_t k_block[SHA256_BLOCK_SIZE];   /* 规整后的密钥块            */
    uint8_t k_ipad[SHA256_BLOCK_SIZE];    /* K ^ ipad                  */
    uint8_t k_opad[SHA256_BLOCK_SIZE];    /* K ^ opad                  */
    uint8_t inner[CNG_HKDF_SHA256_HASH_SIZE]; /* H(K_ipad, data)      */
    sha256_ctx_t ctx;
    size_t i;

    /* 1) 规整密钥：> 64 字节先 hash 折叠到 32 字节；不足 64 补零       */
    memset(k_block, 0, SHA256_BLOCK_SIZE);
    if (key != NULL && key_len > SHA256_BLOCK_SIZE) {
        /* 长密钥：K' = SHA256(key)                                    */
        sha256_ctx_t kc;
        sha256_init(&kc);
        sha256_update(&kc, key, key_len);
        sha256_final(&kc, k_block);   /* 32 字节，剩余 32 字节为 0     */
    } else if (key != NULL && key_len > 0) {
        memcpy(k_block, key, key_len); /* 直接拷贝，剩余补 0            */
    }
    /* key_len==0 时 k_block 保持全 0                                  */

    /* 2) 计算 ipad / opad                                            */
    for (i = 0; i < SHA256_BLOCK_SIZE; ++i) {
        k_ipad[i] = (uint8_t)(k_block[i] ^ 0x36u);
        k_opad[i] = (uint8_t)(k_block[i] ^ 0x5cu);
    }

    /* 3) inner = SHA256(K_ipad || data)                              */
    sha256_init(&ctx);
    sha256_update(&ctx, k_ipad, SHA256_BLOCK_SIZE);
    if (data != NULL && data_len > 0) {
        sha256_update(&ctx, data, data_len);
    }
    sha256_final(&ctx, inner);

    /* 4) out = SHA256(K_opad || inner)                               */
    sha256_init(&ctx);
    sha256_update(&ctx, k_opad, SHA256_BLOCK_SIZE);
    sha256_update(&ctx, inner, CNG_HKDF_SHA256_HASH_SIZE);
    sha256_final(&ctx, out);
}

/* ------------------------------------------------------------------ */
/* 公开接口：cng_hkdf_extract（RFC 5869 §2.2）                        */
/*   PRK = HMAC-SHA256(salt, IKM)                                      */
/*   salt 为 NULL 时按 HashLen 字节全 0 处理（RFC 5869 §2.2）          */
/* ------------------------------------------------------------------ */
int cng_hkdf_extract(const uint8_t* salt, size_t salt_len,
                     const uint8_t* ikm, size_t ikm_len,
                     uint8_t prk[32])
{
    if (ikm == NULL || prk == NULL || (salt == NULL && salt_len > 0)) {
        return CNG_HKDF_ERR_PARAM;
    }
    /* RFC 5869 §2.2：salt 未提供时用 HashLen 个 0x00；这里 HMAC 内部
     * key_len==0 即等价于 64 字节全 0，与规范一致，无需特殊处理。     */
    cng_hmac_sha256(salt, salt_len, ikm, ikm_len, prk);
    return CNG_HKDF_OK;
}

/* ------------------------------------------------------------------ */
/* 公开接口：cng_hkdf_expand（RFC 5869 §2.3）                         */
/*   N     = ceil(okm_len / HashLen)                                  */
/*   T(0)  = ""（空）                                                  */
/*   T(i)  = HMAC-SHA256(PRK, T(i-1) || info || byte(i))  (1<=i<=N)   */
/*   OKM   = T(1) || T(2) || ... || T(N) 的前 okm_len 字节            */
/* ------------------------------------------------------------------ */
int cng_hkdf_expand(const uint8_t prk[32],
                    const uint8_t* info, size_t info_len,
                    uint8_t* okm, size_t okm_len)
{
    uint8_t t_prev[CNG_HKDF_SHA256_HASH_SIZE]; /* T(i-1)              */
    uint8_t t_cur[CNG_HKDF_SHA256_HASH_SIZE];  /* T(i)                */
    size_t  t_prev_len;                        /* T(i-1) 长度          */
    size_t  done;                              /* 已写入 okm 字节数    */
    unsigned int n;                            /* 当前块序号 1..255    */
    unsigned int n_blocks;                     /* 总块数               */
    sha256_ctx_t ctx;

    if (prk == NULL || okm == NULL ||
        (info == NULL && info_len > 0)) {
        return CNG_HKDF_ERR_PARAM;
    }
    if (okm_len > (size_t)CNG_HKDF_MAX_EXPAND_LEN) {
        return CNG_HKDF_ERR_TOO_LARGE;
    }
    if (okm_len == 0) {
        /* 0 长度输出：无需任何计算                                   */
        return CNG_HKDF_OK;
    }

    n_blocks = (unsigned int)((okm_len + CNG_HKDF_SHA256_HASH_SIZE - 1) /
                              CNG_HKDF_SHA256_HASH_SIZE);
    /* n_blocks 由 okm_len <= 255*32 推得上限为 255，单字节 N 合法     */

    t_prev_len = 0;   /* T(0) 为空                                    */
    done = 0;
    for (n = 1; n <= n_blocks; ++n) {
        uint8_t counter = (uint8_t)n;
        size_t  copy_len;

        /* T(i) = HMAC(PRK, T(i-1) || info || N)
         * 这里 HMAC-SHA256 需要拼接三段输入；用流式 SHA256 直接实现
         * HMAC 以避免中间拼接大缓冲。                                  */
        uint8_t k_block[SHA256_BLOCK_SIZE];
        uint8_t k_ipad[SHA256_BLOCK_SIZE];
        uint8_t k_opad[SHA256_BLOCK_SIZE];
        uint8_t inner[CNG_HKDF_SHA256_HASH_SIZE];
        size_t i;

        /* PRK 固定 32 字节，< 64，补零到 64 字节                      */
        memset(k_block, 0, SHA256_BLOCK_SIZE);
        memcpy(k_block, prk, CNG_HKDF_SHA256_HASH_SIZE);
        for (i = 0; i < SHA256_BLOCK_SIZE; ++i) {
            k_ipad[i] = (uint8_t)(k_block[i] ^ 0x36u);
            k_opad[i] = (uint8_t)(k_block[i] ^ 0x5cu);
        }

        /* inner = SHA256(K_ipad || T(i-1) || info || N)              */
        sha256_init(&ctx);
        sha256_update(&ctx, k_ipad, SHA256_BLOCK_SIZE);
        if (t_prev_len > 0) {
            sha256_update(&ctx, t_prev, t_prev_len);
        }
        if (info_len > 0) {
            sha256_update(&ctx, info, info_len);
        }
        sha256_update(&ctx, &counter, 1);
        sha256_final(&ctx, inner);

        /* T(i) = SHA256(K_opad || inner)                             */
        sha256_init(&ctx);
        sha256_update(&ctx, k_opad, SHA256_BLOCK_SIZE);
        sha256_update(&ctx, inner, CNG_HKDF_SHA256_HASH_SIZE);
        sha256_final(&ctx, t_cur);

        /* 取 T(i) 前 (okm_len - done) 与 32 的较小者拷入 OKM         */
        copy_len = okm_len - done;
        if (copy_len > CNG_HKDF_SHA256_HASH_SIZE) {
            copy_len = CNG_HKDF_SHA256_HASH_SIZE;
        }
        memcpy(okm + done, t_cur, copy_len);
        done += copy_len;

        /* T(i) 成为下一轮的 T(i-1)                                   */
        memcpy(t_prev, t_cur, CNG_HKDF_SHA256_HASH_SIZE);
        t_prev_len = CNG_HKDF_SHA256_HASH_SIZE;
    }

    return CNG_HKDF_OK;
}

/* ------------------------------------------------------------------ */
/* 公开接口：cng_hkdf（一步式 Extract + Expand）                       */
/* ------------------------------------------------------------------ */
int cng_hkdf(const uint8_t* salt, size_t salt_len,
             const uint8_t* ikm, size_t ikm_len,
             const uint8_t* info, size_t info_len,
             uint8_t* okm, size_t okm_len)
{
    uint8_t prk[CNG_HKDF_SHA256_HASH_SIZE];
    int rc;

    if (ikm == NULL || okm == NULL ||
        (salt == NULL && salt_len > 0) ||
        (info == NULL && info_len > 0)) {
        return CNG_HKDF_ERR_PARAM;
    }
    if (okm_len > (size_t)CNG_HKDF_MAX_EXPAND_LEN) {
        return CNG_HKDF_ERR_TOO_LARGE;
    }

    /* 1) Extract                                                     */
    rc = cng_hkdf_extract(salt, salt_len, ikm, ikm_len, prk);
    if (rc != CNG_HKDF_OK) {
        return rc;
    }

    /* 2) Expand                                                      */
    rc = cng_hkdf_expand(prk, info, info_len, okm, okm_len);
    return rc;
}
