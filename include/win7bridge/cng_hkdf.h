/*
 * cng_hkdf.h - Win7Bridge CNG HKDF 算法模拟接口
 *
 * Win7 的 BCrypt 缺失 Win10+ 引入的 HKDF 算法（BCRYPT_HKDF_ALGORITHM）。
 * 本层提供 RFC 5869（HMAC-SHA256）的纯 C 实现，供 Win7 上需要 HKDF 的
 * 场景本地回退使用，避免因算法缺失而失败。
 *
 * 实现：SHA-256（FIPS 180-4）+ HMAC-SHA256（RFC 2104）+ HKDF（RFC 5869）。
 * 不依赖 <windows.h>；可在原生 gcc 下 host 测试。
 *
 * 参考：
 *   - RFC 5869：HMAC-based Extract-and-Expand KDF
 *   - RFC 2104：HMAC
 *   - FIPS 180-4：SHA-256
 */
#ifndef WIN7BRIDGE_CNG_HKDF_H
#define WIN7BRIDGE_CNG_HKDF_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------ */
/* 常量                                                                */
/* ------------------------------------------------------------------ */
/* SHA-256 摘要长度（PRK 固定 32 字节）                                */
#define CNG_HKDF_SHA256_HASH_SIZE  32

/* HKDF-Expand 单次输出上限：255 * HashLen（RFC 5869 §2.3）            */
#define CNG_HKDF_MAX_EXPAND_LEN    (255 * CNG_HKDF_SHA256_HASH_SIZE)

/* ------------------------------------------------------------------ */
/* 返回码                                                              */
/* ------------------------------------------------------------------ */
#define CNG_HKDF_OK                0    /* 成功                         */
#define CNG_HKDF_ERR_PARAM        -1    /* 入参非法                     */
#define CNG_HKDF_ERR_TOO_LARGE    -2    /* okm_len 超过 255*32         */

/* ------------------------------------------------------------------ */
/* 基础哈希：SHA-256（FIPS 180-4）                                     */
/* ------------------------------------------------------------------ */
/*
 * cng_sha256 - 计算 SHA-256 摘要
 *   data    ：待哈希的字节缓冲（可为 NULL 仅当 len==0）
 *   len     ：data 的字节数
 *   out[32] ：输出 32 字节摘要
 * 注：out 不可为 NULL；data 为 NULL 时按空串处理。
 */
void cng_sha256(const uint8_t* data, size_t len, uint8_t out[32]);

/* ------------------------------------------------------------------ */
/* HMAC-SHA256（RFC 2104）                                             */
/* ------------------------------------------------------------------ */
/*
 * cng_hmac_sha256 - 计算 HMAC-SHA256
 *   key     ：HMAC 密钥（可为 NULL 仅当 key_len==0）
 *   key_len ：密钥字节数；> 64 时内部先 hash 折叠到 32 字节
 *   data    ：待认证的字节缓冲（可为 NULL 仅当 data_len==0）
 *   data_len：data 的字节数
 *   out[32] ：输出 32 字节 MAC
 */
void cng_hmac_sha256(const uint8_t* key, size_t key_len,
                     const uint8_t* data, size_t data_len,
                     uint8_t out[32]);

/* ------------------------------------------------------------------ */
/* HKDF-Extract（RFC 5869 §2.2）                                       */
/* ------------------------------------------------------------------ */
/*
 * cng_hkdf_extract - 提取伪随机密钥 PRK
 *   salt     ：可选盐值（可为 NULL 仅当 salt_len==0；NULL 时按全 0 处理）
 *   salt_len ：盐值字节数
 *   ikm      ：输入密钥材料（不可为 NULL）
 *   ikm_len  ：ikm 的字节数
 *   prk[32]  ：输出 32 字节伪随机密钥
 * 返回：CNG_HKDF_OK 成功；CNG_HKDF_ERR_PARAM 入参非法。
 */
int cng_hkdf_extract(const uint8_t* salt, size_t salt_len,
                     const uint8_t* ikm, size_t ikm_len,
                     uint8_t prk[32]);

/* ------------------------------------------------------------------ */
/* HKDF-Expand（RFC 5869 §2.3）                                        */
/* ------------------------------------------------------------------ */
/*
 * cng_hkdf_expand - 由 PRK 展开为指定长度的输出密钥材料 OKM
 *   prk[32]  ：伪随机密钥（来自 cng_hkdf_extract）
 *   info     ：可选上下文/应用信息（可为 NULL 仅当 info_len==0）
 *   info_len ：info 的字节数
 *   okm      ：输出缓冲（不可为 NULL）
 *   okm_len  ：期望输出字节数，必须 <= 255*32
 * 返回：CNG_HKDF_OK 成功；CNG_HKDF_ERR_PARAM 入参非法；
 *       CNG_HKDF_ERR_TOO_LARGE okm_len 超限。
 */
int cng_hkdf_expand(const uint8_t prk[32],
                    const uint8_t* info, size_t info_len,
                    uint8_t* okm, size_t okm_len);

/* ------------------------------------------------------------------ */
/* HKDF 一步式（Extract + Expand，RFC 5869 §2）                       */
/* ------------------------------------------------------------------ */
/*
 * cng_hkdf - 一步式 HKDF（先 extract 再 expand）
 *   salt     ：可选盐值（可为 NULL 仅当 salt_len==0）
 *   salt_len ：盐值字节数
 *   ikm      ：输入密钥材料（不可为 NULL）
 *   ikm_len  ：ikm 的字节数
 *   info     ：可选上下文信息（可为 NULL 仅当 info_len==0）
 *   info_len ：info 的字节数
 *   okm      ：输出缓冲（不可为 NULL）
 *   okm_len  ：期望输出字节数，必须 <= 255*32
 * 返回：CNG_HKDF_OK 成功；CNG_HKDF_ERR_PARAM 入参非法；
 *       CNG_HKDF_ERR_TOO_LARGE okm_len 超限。
 */
int cng_hkdf(const uint8_t* salt, size_t salt_len,
             const uint8_t* ikm, size_t ikm_len,
             const uint8_t* info, size_t info_len,
             uint8_t* okm, size_t okm_len);

#ifdef __cplusplus
}
#endif

#endif /* WIN7BRIDGE_CNG_HKDF_H */
