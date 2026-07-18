/*
 * cng_chacha20.h - Win7Bridge CNG ChaCha20-Poly1305 AEAD 算法模拟接口
 *
 * Win7 的 BCrypt 缺失 Win10+ 引入的 ChaCha20-Poly1305 AEAD 算法
 * （BCRYPT_CHACHA20_POLY1305_ALGORITHM）。本层提供 RFC 8439 的纯 C 实现，
 * 供 Win7 上需要该算法的场景本地回退使用，避免因算法缺失而失败。
 *
 * 实现：ChaCha20 流密码（RFC 8439 §2.3）+ Poly1305 MAC（RFC 8439 §2.4）
 *       + AEAD 组合（RFC 8439 §2.8）。不依赖 <windows.h>；可在原生 gcc 下
 *       host 测试。
 *
 * 参考：
 *   - RFC 8439：ChaCha20 and Poly1305 for IETF Protocols
 *   - docs/api-diff.md §2.9（CNG 算法差异）
 */
#ifndef WIN7BRIDGE_CNG_CHACHA20_H
#define WIN7BRIDGE_CNG_CHACHA20_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------ */
/* 常量                                                                */
/* ------------------------------------------------------------------ */
#define CNG_CHACHA20_KEY_SIZE     32   /* ChaCha20 密钥长度（字节）     */
#define CNG_CHACHA20_NONCE_SIZE   12   /* IETF 变体 nonce 长度（字节）  */
#define CNG_CHACHA20_BLOCK_SIZE   64   /* ChaCha20 单块大小（字节）     */
#define CNG_POLY1305_TAG_SIZE     16   /* Poly1305 标签长度（字节）     */

/* ------------------------------------------------------------------ */
/* ChaCha20 流密码（RFC 8439 §2.3）                                    */
/* ------------------------------------------------------------------ */
/*
 * cng_chacha20_xor - 用 ChaCha20 密钥流与输入数据 XOR
 *   key[32]    ：256 位密钥
 *   counter    ：初始块计数器（通常加密用 1）
 *   nonce[12]  ：96 位 nonce
 *   in         ：输入缓冲（可为 NULL 仅当 length==0）
 *   out        ：输出缓冲（可为 NULL 仅当 length==0）
 *   length     ：输入/输出字节数
 * 注：in 与 out 可指向同一地址（原地加解密）。
 */
void cng_chacha20_xor(const uint8_t key[32], uint32_t counter,
                      const uint8_t nonce[12],
                      const uint8_t* in, uint8_t* out, size_t length);

/* ------------------------------------------------------------------ */
/* Poly1305 消息认证码（RFC 8439 §2.4）                                */
/* ------------------------------------------------------------------ */
/*
 * cng_poly1305_mac - 计算 Poly1305 MAC
 *   key[32]     ：256 位密钥（前 16 字节为 r，后 16 字节为 s）
 *   msg         ：待认证的消息（可为 NULL 仅当 msg_len==0）
 *   msg_len     ：消息字节数
 *   tag[16]     ：输出 16 字节标签
 */
void cng_poly1305_mac(const uint8_t key[32],
                      const uint8_t* msg, size_t msg_len,
                      uint8_t tag[16]);

/* ------------------------------------------------------------------ */
/* ChaCha20-Poly1305 AEAD（RFC 8439 §2.8）                            */
/* ------------------------------------------------------------------ */
/*
 * cng_chacha20_poly1305_encrypt - AEAD 加密
 *   key[32]      ：256 位密钥
 *   nonce[12]    ：96 位 nonce
 *   aad          ：附加认证数据（可为 NULL 仅当 aad_len==0）
 *   aad_len      ：AAD 字节数
 *   plaintext    ：明文（可为 NULL 仅当 pt_len==0）
 *   pt_len       ：明文字节数
 *   ciphertext   ：输出密文缓冲（大小 >= pt_len）
 *   tag[16]      ：输出 16 字节认证标签
 */
void cng_chacha20_poly1305_encrypt(const uint8_t key[32],
                                   const uint8_t nonce[12],
                                   const uint8_t* aad, size_t aad_len,
                                   const uint8_t* plaintext, size_t pt_len,
                                   uint8_t* ciphertext, uint8_t tag[16]);

/*
 * cng_chacha20_poly1305_decrypt - AEAD 解密
 *   key[32]       ：256 位密钥
 *   nonce[12]     ：96 位 nonce
 *   aad           ：附加认证数据（可为 NULL 仅当 aad_len==0）
 *   aad_len       ：AAD 字节数
 *   ciphertext    ：密文（可为 NULL 仅当 ct_len==0）
 *   ct_len        ：密文字节数
 *   tag[16]       ：认证标签
 *   plaintext     ：输出明文缓冲（大小 >= ct_len）
 * 返回：0 成功；-1 标签校验失败（不输出明文）。
 */
int cng_chacha20_poly1305_decrypt(const uint8_t key[32],
                                  const uint8_t nonce[12],
                                  const uint8_t* aad, size_t aad_len,
                                  const uint8_t* ciphertext, size_t ct_len,
                                  const uint8_t tag[16],
                                  uint8_t* plaintext);

#ifdef __cplusplus
}
#endif

#endif /* WIN7BRIDGE_CNG_CHACHA20_H */
