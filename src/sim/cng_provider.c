/*
 * cng_provider.c - Win7Bridge BCrypt provider 适配层实现
 *
 * 实现 cng_provider.h 中的接口，把 cng_chacha20.c 的纯算法函数
 * 包装成 BCrypt provider 句柄 + key 句柄 + AEAD 加解密路径。
 *
 * 纯 C 无平台依赖，不使用 <windows.h>；可在原生 gcc 下 host 测试。
 */
#include "win7bridge/cng_provider.h"
#include "win7bridge/cng_chacha20.h"

#include <stdlib.h>
#include <string.h>

/* ================================================================== */
/* 句柄判定                                                            */
/* ================================================================== */

int w7b_is_alg_handle(const void* h)
{
    const w7b_alg_handle* ah = (const w7b_alg_handle*)h;
    return (ah != NULL && ah->magic == W7B_ALG_MAGIC &&
            ah->alg != W7B_ALG_NONE);
}

int w7b_is_key_handle(const void* h)
{
    const w7b_key_handle* kh = (const w7b_key_handle*)h;
    return (kh != NULL && kh->magic == W7B_KEY_MAGIC &&
            kh->alg != W7B_ALG_NONE);
}

/* ================================================================== */
/* 创建 / 销毁算法 provider 句柄                                       */
/* ================================================================== */

int w7b_provider_open_alg(w7b_alg_type alg, w7b_alg_handle** ph)
{
    w7b_alg_handle* h;

    if (ph == NULL || alg == W7B_ALG_NONE) {
        return -1;
    }

    h = (w7b_alg_handle*)malloc(sizeof(w7b_alg_handle));
    if (h == NULL) {
        return -1;
    }
    h->magic = W7B_ALG_MAGIC;
    h->alg   = alg;
    *ph = h;
    return 0;
}

int w7b_provider_close_alg(w7b_alg_handle* h)
{
    if (!w7b_is_alg_handle(h)) {
        return -1;
    }
    h->magic = 0;   /* 防止 use-after-free */
    free(h);
    return 0;
}

/* ================================================================== */
/* 查询算法属性                                                        */
/* ================================================================== */

int w7b_provider_get_property(const w7b_alg_handle* h, w7b_prop_id prop,
                               uint8_t* out, size_t out_len,
                               size_t* out_result)
{
    size_t need = 0;

    if (!w7b_is_alg_handle(h) || out == NULL) {
        return -1;
    }

    switch (prop) {
    case W7B_PROP_KEY_LENGTH:
    {
        /* ULONG（32 位），单位 bit。CHACHA20_POLY1305 = 256 bit */
        uint32_t val = 0;
        if (h->alg == W7B_ALG_CHACHA20_POLY1305) {
            val = 256;
        } else {
            return -1;
        }
        need = 4;
        if (out_len < need) {
            return -1;
        }
        /* 小端存储 ULONG */
        out[0] = (uint8_t)(val);
        out[1] = (uint8_t)(val >> 8);
        out[2] = (uint8_t)(val >> 16);
        out[3] = (uint8_t)(val >> 24);
        break;
    }
    case W7B_PROP_AUTH_TAG_LENGTH:
    {
        /* BCRYPT_AUTH_TAG_LENGTHS_STRUCT：2×ULONG（min, max）。
         * CHACHA20_POLY1305 的 tag 固定 16 字节。 */
        uint32_t vmin = 0, vmax = 0;
        if (h->alg == W7B_ALG_CHACHA20_POLY1305) {
            vmin = vmax = CNG_POLY1305_TAG_SIZE;
        } else {
            return -1;
        }
        need = 8;
        if (out_len < need) {
            return -1;
        }
        out[0] = (uint8_t)(vmin);
        out[1] = (uint8_t)(vmin >> 8);
        out[2] = (uint8_t)(vmin >> 16);
        out[3] = (uint8_t)(vmin >> 24);
        out[4] = (uint8_t)(vmax);
        out[5] = (uint8_t)(vmax >> 8);
        out[6] = (uint8_t)(vmax >> 16);
        out[7] = (uint8_t)(vmax >> 24);
        break;
    }
    case W7B_PROP_OBJECT_LENGTH:
    {
        /* key 对象长度。本实现内部 malloc 分配，返回 0 表示由
         * provider 自行管理对象内存（调用方传 NULL/0 即可）。 */
        uint32_t val = 0;
        need = 4;
        if (out_len < need) {
            return -1;
        }
        out[0] = (uint8_t)(val);
        out[1] = (uint8_t)(val >> 8);
        out[2] = (uint8_t)(val >> 16);
        out[3] = (uint8_t)(val >> 24);
        break;
    }
    case W7B_PROP_BLOCK_LENGTH:
    {
        /* 块长度。CHACHA20_POLY1305 的 ChaCha20 块 = 64 字节。 */
        uint32_t val = 0;
        if (h->alg == W7B_ALG_CHACHA20_POLY1305) {
            val = CNG_CHACHA20_BLOCK_SIZE;
        } else {
            return -1;
        }
        need = 4;
        if (out_len < need) {
            return -1;
        }
        out[0] = (uint8_t)(val);
        out[1] = (uint8_t)(val >> 8);
        out[2] = (uint8_t)(val >> 16);
        out[3] = (uint8_t)(val >> 24);
        break;
    }
    default:
        return -1;
    }

    if (out_result) {
        *out_result = need;
    }
    return 0;
}

/* ================================================================== */
/* 生成 / 销毁对称密钥                                                  */
/* ================================================================== */

int w7b_provider_gen_key(const w7b_alg_handle* h,
                          w7b_key_handle** phKey,
                          const uint8_t* key, size_t key_len)
{
    w7b_key_handle* kh;

    if (!w7b_is_alg_handle(h) || phKey == NULL) {
        return -1;
    }

    /* 目前仅 CHACHA20_POLY1305 支持对称密钥 */
    if (h->alg != W7B_ALG_CHACHA20_POLY1305) {
        return -1;
    }
    if (key == NULL || key_len != CNG_CHACHA20_KEY_SIZE) {
        return -1;
    }

    kh = (w7b_key_handle*)malloc(sizeof(w7b_key_handle));
    if (kh == NULL) {
        return -1;
    }
    kh->magic = W7B_KEY_MAGIC;
    kh->alg   = h->alg;
    memcpy(kh->key, key, CNG_CHACHA20_KEY_SIZE);
    *phKey = kh;
    return 0;
}

int w7b_provider_destroy_key(w7b_key_handle* hKey)
{
    if (!w7b_is_key_handle(hKey)) {
        return -1;
    }
    hKey->magic = 0;
    /* 清除敏感密钥材料 */
    memset(hKey->key, 0, CNG_CHACHA20_KEY_SIZE);
    free(hKey);
    return 0;
}

/* ================================================================== */
/* AEAD 加密 / 解密                                                     */
/* ================================================================== */

int w7b_provider_encrypt(const w7b_key_handle* hKey,
                          const uint8_t* nonce, size_t nonce_len,
                          const uint8_t* aad, size_t aad_len,
                          const uint8_t* pt, size_t pt_len,
                          uint8_t* ct, uint8_t* tag, size_t tag_len)
{
    if (!w7b_is_key_handle(hKey) || hKey->alg != W7B_ALG_CHACHA20_POLY1305) {
        return -1;
    }
    if (nonce == NULL || nonce_len != CNG_CHACHA20_NONCE_SIZE) {
        return -1;
    }
    if (tag == NULL || tag_len != CNG_POLY1305_TAG_SIZE) {
        return -1;
    }
    /* 明文/密文可为 NULL 仅当长度为 0 */
    if ((pt == NULL && pt_len > 0) || (ct == NULL && pt_len > 0)) {
        return -1;
    }
    /* AAD 可为 NULL 仅当长度为 0 */
    if (aad == NULL && aad_len > 0) {
        return -1;
    }

    cng_chacha20_poly1305_encrypt(hKey->key, nonce,
                                   aad, aad_len,
                                   pt, pt_len,
                                   ct, tag);
    return 0;
}

int w7b_provider_decrypt(const w7b_key_handle* hKey,
                          const uint8_t* nonce, size_t nonce_len,
                          const uint8_t* aad, size_t aad_len,
                          const uint8_t* ct, size_t ct_len,
                          const uint8_t* tag, size_t tag_len,
                          uint8_t* pt)
{
    if (!w7b_is_key_handle(hKey) || hKey->alg != W7B_ALG_CHACHA20_POLY1305) {
        return -1;
    }
    if (nonce == NULL || nonce_len != CNG_CHACHA20_NONCE_SIZE) {
        return -1;
    }
    if (tag == NULL || tag_len != CNG_POLY1305_TAG_SIZE) {
        return -1;
    }
    if ((ct == NULL && ct_len > 0) || (pt == NULL && ct_len > 0)) {
        return -1;
    }
    if (aad == NULL && aad_len > 0) {
        return -1;
    }

    return cng_chacha20_poly1305_decrypt(hKey->key, nonce,
                                          aad, aad_len,
                                          ct, ct_len,
                                          tag, pt);
}
