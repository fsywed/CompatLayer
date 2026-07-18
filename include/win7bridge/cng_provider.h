/*
 * cng_provider.h - Win7Bridge BCrypt provider 适配层接口
 *
 * 【开发文档】
 *
 * 目的：在纯算法层（cng_chacha20.c / cng_hkdf.c）与 BCrypt hook 层
 *   （dllmain.c）之间建立适配层，把非 BCrypt ABI 的纯算法函数包装
 *   成可被 BCryptOpenAlgorithmProvider / BCryptGenerateSymmetricKey /
 *   BCryptEncrypt / BCryptDecrypt 等 BCrypt API 调用的 provider 对象。
 *
 * 分点展开：
 *   1. 平台无关
 *      本层不引用 <windows.h>，仅使用 uint8_t / size_t / uint32_t。
 *      算法名、属性名的字符串比较由 hook 层完成，本层只接收已解析的
 *      枚举值（w7b_alg_type / w7b_prop_id），便于 host 测试。
 *
 *   2. 句柄对象
 *      - w7b_alg_handle：算法 provider 句柄，含 magic + 算法类型。
 *      - w7b_key_handle：对称密钥句柄，含 magic + 算法类型 + 原始密钥。
 *      两者均由 malloc 分配，magic 字段用于区分本地句柄与系统句柄。
 *
 *   3. 覆盖的 BCrypt 路径
 *      - OpenAlgorithmProvider → w7b_provider_open_alg
 *      - CloseAlgorithmProvider → w7b_provider_close_alg
 *      - GetProperty → w7b_provider_get_property（KeyLength / AuthTagLength）
 *      - GenerateSymmetricKey → w7b_provider_gen_key
 *      - DestroyKey → w7b_provider_destroy_key
 *      - Encrypt → w7b_provider_encrypt（AEAD，nonce/AAD/tag 由 hook 层
 *        从 BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO 解包后传入）
 *      - Decrypt → w7b_provider_decrypt（同上）
 *
 *   4. 算法支持
 *      - CHACHA20_POLY1305：完整 AEAD 加解密（RFC 8439）
 *      - HKDF：仅 Open/Close（算法本体在 cng_hkdf.c，BCrypt KDF 路径
 *        涉及 BCryptKeyDerivation，留待后续扩展）
 *
 * 参考：
 *   - docs/api-diff.md §2.9（CNG 算法差异）
 *   - RFC 8439 §2.8（AEAD 组合）
 */
#ifndef WIN7BRIDGE_CNG_PROVIDER_H
#define WIN7BRIDGE_CNG_PROVIDER_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------ */
/* 算法类型（hook 层负责字符串→枚举映射）                               */
/* ------------------------------------------------------------------ */
typedef enum {
    W7B_ALG_NONE = 0,
    W7B_ALG_CHACHA20_POLY1305,   /* L"CHACHA20_POLY1305" */
    W7B_ALG_HKDF,                /* L"HKDF"              */
} w7b_alg_type;

/* ------------------------------------------------------------------ */
/* 属性 ID（hook 层负责字符串→枚举映射）                                */
/* ------------------------------------------------------------------ */
typedef enum {
    W7B_PROP_NONE = 0,
    W7B_PROP_KEY_LENGTH,      /* 密钥长度（ULONG，单位：bit）  */
    W7B_PROP_AUTH_TAG_LENGTH, /* 标签长度结构（2×ULONG：min,max） */
    W7B_PROP_OBJECT_LENGTH,   /* key 对象长度（ULONG，单位：byte） */
    W7B_PROP_BLOCK_LENGTH,    /* 块长度（ULONG，单位：byte）    */
} w7b_prop_id;

/* ------------------------------------------------------------------ */
/* 句柄 magic                                                          */
/* ------------------------------------------------------------------ */
#define W7B_ALG_MAGIC 0x41374257u   /* 'W7BA' */
#define W7B_KEY_MAGIC 0x4B374257u   /* 'W7BK' */

/* ------------------------------------------------------------------ */
/* 句柄对象（内部布局，外部仅作为不透明指针使用）                       */
/* ------------------------------------------------------------------ */
typedef struct {
    uint32_t      magic;
    w7b_alg_type  alg;
} w7b_alg_handle;

typedef struct {
    uint32_t      magic;
    w7b_alg_type  alg;
    uint8_t       key[32];   /* 原始密钥字节 */
} w7b_key_handle;

/* ------------------------------------------------------------------ */
/* 句柄判定（hook 层用此区分本地句柄与系统句柄）                        */
/*   返回 1 = 是本地句柄；0 = 不是                                     */
/* ------------------------------------------------------------------ */
int w7b_is_alg_handle(const void* h);
int w7b_is_key_handle(const void* h);

/* ------------------------------------------------------------------ */
/* 创建 / 销毁算法 provider 句柄                                       */
/*   返回 0 成功；-1 失败                                              */
/* ------------------------------------------------------------------ */
int w7b_provider_open_alg(w7b_alg_type alg, w7b_alg_handle** ph);
int w7b_provider_close_alg(w7b_alg_handle* h);

/* ------------------------------------------------------------------ */
/* 查询算法属性                                                        */
/*   prop       ：属性 ID                                              */
/*   out        ：输出缓冲                                             */
/*   out_len    ：输出缓冲容量                                         */
/*   out_result ：实际写入字节数（可为 NULL）                          */
/*   返回 0 成功；-1 未知属性或参数非法                                */
/* ------------------------------------------------------------------ */
int w7b_provider_get_property(const w7b_alg_handle* h, w7b_prop_id prop,
                               uint8_t* out, size_t out_len,
                               size_t* out_result);

/* ------------------------------------------------------------------ */
/* 生成 / 销毁对称密钥                                                  */
/*   key     ：原始密钥字节                                             */
/*   key_len ：密钥字节数（CHACHA20_POLY1305 必须 32）                 */
/*   返回 0 成功；-1 失败                                              */
/* ------------------------------------------------------------------ */
int w7b_provider_gen_key(const w7b_alg_handle* h,
                          w7b_key_handle** phKey,
                          const uint8_t* key, size_t key_len);
int w7b_provider_destroy_key(w7b_key_handle* hKey);

/* ------------------------------------------------------------------ */
/* AEAD 加密（仅 CHACHA20_POLY1305）                                    */
/*   nonce     ：12 字节 nonce                                          */
/*   nonce_len ：必须 12                                                */
/*   aad       ：附加认证数据（可为 NULL 仅当 aad_len==0）              */
/*   aad_len   ：AAD 字节数                                             */
/*   pt        ：明文（可为 NULL 仅当 pt_len==0）                       */
/*   pt_len    ：明文字节数                                             */
/*   ct        ：输出密文（大小 >= pt_len）                             */
/*   tag       ：输出 16 字节标签                                       */
/*   tag_len   ：必须 16                                                */
/*   返回 0 成功；-1 参数非法                                           */
/* ------------------------------------------------------------------ */
int w7b_provider_encrypt(const w7b_key_handle* hKey,
                          const uint8_t* nonce, size_t nonce_len,
                          const uint8_t* aad, size_t aad_len,
                          const uint8_t* pt, size_t pt_len,
                          uint8_t* ct, uint8_t* tag, size_t tag_len);

/* ------------------------------------------------------------------ */
/* AEAD 解密（仅 CHACHA20_POLY1305）                                    */
/*   返回 0 成功；-1 标签校验失败或参数非法                             */
/* ------------------------------------------------------------------ */
int w7b_provider_decrypt(const w7b_key_handle* hKey,
                          const uint8_t* nonce, size_t nonce_len,
                          const uint8_t* aad, size_t aad_len,
                          const uint8_t* ct, size_t ct_len,
                          const uint8_t* tag, size_t tag_len,
                          uint8_t* pt);

#ifdef __cplusplus
}
#endif

#endif /* WIN7BRIDGE_CNG_PROVIDER_H */
