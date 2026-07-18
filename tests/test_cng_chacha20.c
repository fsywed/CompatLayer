/*
 * test_cng_chacha20.c - Win7Bridge CNG ChaCha20-Poly1305 host 测试
 *
 * 覆盖（参考 RFC 8439）：
 *   1) ChaCha20 block 函数（§2.3.2）：固定 key/nonce/counter=1，比对 64 字节密钥流
 *   2) ChaCha20 加密（§2.5.2）：114 字节明文加密，比对密文
 *   3) Poly1305 MAC（§2.4.2）：单块消息，比对 16 字节 tag
 *   4) AEAD encrypt（§2.8.2）：AAD+明文加密，比对密文与 tag
 *   5) AEAD decrypt：用 §2.8.2 密文/tag 解密，比对明文，返回 0
 *   6) AEAD decrypt 篡改 tag：返回 -1
 *   7) AEAD round-trip：固定 key/nonce/AAD/明文，encrypt 再 decrypt 一致
 *   8) 入参非法：key/nonce/tag 为 NULL 时安全返回
 *
 * 仅在定义 WIN7BRIDGE_HOST_TEST 时编译 main，用原生 gcc 运行。
 * 返回 0 表示全部通过，非 0 表示有失败。
 */
#include "win7bridge/cng_chacha20.h"

#include <stdio.h>
#include <string.h>
#include <stdint.h>

/* ------------------------------------------------------------------ */
/* 简单断言（风格与 test_spoof_time.c 一致）                          */
/* ------------------------------------------------------------------ */
static int g_fail = 0;
#define CHECK(cond, msg)                                                  \
    do {                                                                  \
        if (!(cond)) {                                                    \
            printf("[FAIL] %s:%d %s\n", __FILE__, __LINE__, (msg));       \
            g_fail = 1;                                                   \
        } else {                                                          \
            printf("[ok]   %s\n", (msg));                                 \
        }                                                                 \
    } while (0)

/* ------------------------------------------------------------------ */
/* 辅助：十六进制字符串 -> 字节                                         */
/* ------------------------------------------------------------------ */
static size_t hex_to_bytes(const char* hex, uint8_t* out)
{
    size_t i;
    size_t n = strlen(hex);
    if (n % 2 != 0) {
        return 0;
    }
    for (i = 0; i < n / 2; ++i) {
        const char* p = hex + i * 2;
        uint8_t hi, lo;
        char c1 = p[0], c2 = p[1];
        if (c1 >= '0' && c1 <= '9')      hi = (uint8_t)(c1 - '0');
        else if (c1 >= 'a' && c1 <= 'f') hi = (uint8_t)(c1 - 'a' + 10);
        else if (c1 >= 'A' && c1 <= 'F') hi = (uint8_t)(c1 - 'A' + 10);
        else return 0;
        if (c2 >= '0' && c2 <= '9')      lo = (uint8_t)(c2 - '0');
        else if (c2 >= 'a' && c2 <= 'f') lo = (uint8_t)(c2 - 'a' + 10);
        else if (c2 >= 'A' && c2 <= 'F') lo = (uint8_t)(c2 - 'A' + 10);
        else return 0;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return n / 2;
}

/* 比较缓冲与期望十六进制串是否一致；返回 1 一致，0 不一致或长度不符 */
static int bytes_match(const uint8_t* buf, size_t len, const char* hex_expected)
{
    /* RFC 8439 向量最长 114 字节                                            */
    uint8_t tmp[256];
    size_t  exp_len;
    if (len > sizeof(tmp)) {
        return 0;
    }
    exp_len = hex_to_bytes(hex_expected, tmp);
    if (exp_len != len) {
        return 0;
    }
    return memcmp(buf, tmp, len) == 0;
}

/* 打印缓冲为十六进制（仅失败诊断用）                                  */
static void print_hex(const char* prefix, const uint8_t* buf, size_t len)
{
    size_t i;
    printf("%s", prefix);
    for (i = 0; i < len; ++i) {
        printf("%02x", buf[i]);
    }
    printf("\n");
}

/* ------------------------------------------------------------------ */
/* 用例 1：ChaCha20 block 函数（RFC 8439 §2.3.2）                     */
/*   key    = 00:01:...:1f                                            */
/*   nonce  = 00:00:00:09:00:00:00:4a:00:00:00:00                    */
/*   counter= 1                                                       */
/*   期望：64 字节密钥流                                              */
/* ------------------------------------------------------------------ */
static void test_chacha20_block_rfc8439(void)
{
    uint8_t key[32];
    uint8_t nonce[12];
    uint8_t zero[64];
    uint8_t out[64];
    size_t i;

    printf("==== 用例 1：ChaCha20 block (RFC 8439 §2.3.2) ====\n");
    for (i = 0; i < 32; ++i) key[i] = (uint8_t)i;
    /* nonce = 00000009 0000004a 00000000 */
    memset(nonce, 0, 12);
    nonce[3] = 0x09u;
    nonce[7] = 0x4au;

    /* 用 cng_chacha20_xor 对 0 串加密等价于输出密钥流                */
    memset(zero, 0, 64);
    cng_chacha20_xor(key, 1, nonce, zero, out, 64);

    /* RFC 8439 §2.3.2 官方 64 字节密钥流                              */
    if (!bytes_match(out, 64,
            "10f1e7e4d13b5915500fdd1fa32071c4"
            "c7d1f4c733c068030422aa9ac3d46c4e"
            "d2826446079faa0914c2d705d98b02a2"
            "b5129cd1de164eb9cbd083e8a2503c4e")) {
        print_hex("  实际: ", out, 64);
        CHECK(0, "ChaCha20 block == RFC 8439 §2.3.2 向量");
    } else {
        CHECK(1, "ChaCha20 block == RFC 8439 §2.3.2 向量");
    }
}

/* ------------------------------------------------------------------ */
/* 用例 2：ChaCha20 加密（RFC 8439 §2.5.2）                           */
/*   key    = 00:01:...:1f                                            */
/*   nonce  = 00:00:00:00:00:00:00:4a:00:00:00:00                    */
/*   counter= 1                                                       */
/*   plaintext = "Ladies and Gentlemen of the class of '99..."        */
/* ------------------------------------------------------------------ */
static void test_chacha20_encrypt_rfc8439(void)
{
    uint8_t key[32];
    uint8_t nonce[12];
    static const char* pt_str =
        "Ladies and Gentlemen of the class of '99: "
        "If I could offer you only one tip for the future, "
        "sunscreen would be it.";
    uint8_t ct[128];
    size_t pt_len = strlen(pt_str);
    size_t i;

    printf("==== 用例 2：ChaCha20 加密 (RFC 8439 §2.5.2) ====\n");
    for (i = 0; i < 32; ++i) key[i] = (uint8_t)i;
    memset(nonce, 0, 12);
    nonce[7] = 0x4au;

    cng_chacha20_xor(key, 1, nonce, (const uint8_t*)pt_str, ct, pt_len);

    /* RFC 8439 §2.4.2 官方密文（114 字节，纯净 hex） */
    if (!bytes_match(ct, pt_len,
            "6e2e359a2568f98041ba0728dd0d6981"
            "e97e7aec1d4360c20a27afccfd9fae0b"
            "f91b65c5524733ab8f593dabcd62b357"
            "1639d624e65152ab8f530c359f0861d8"
            "07ca0dbf500d6a6156a38e088a22b65e"
            "52bc514d16ccf806818ce91ab7793736"
            "5af90bbf74a35be6b40b8eedf2785e42"
            "874d")) {
        print_hex("  实际: ", ct, pt_len);
        CHECK(0, "ChaCha20 加密 == RFC 8439 §2.5.2 向量");
    } else {
        CHECK(1, "ChaCha20 加密 == RFC 8439 §2.5.2 向量");
    }
}

/* ------------------------------------------------------------------ */
/* 用例 3：Poly1305 MAC（RFC 8439 §2.4.2）                            */
/*   key  = 85:d6:be:78:...:f5:1b（32 字节）                         */
/*   msg  = "Cryptographic Forum Research Group"                      */
/*   tag  = a8:06:1d:c1:30:51:36:c6:c2:2b:8b:af:0c:01:27:a9         */
/* ------------------------------------------------------------------ */
static void test_poly1305_rfc8439(void)
{
    static const char* key_hex =
        "85d6be7857556d337f4452fe42d506a8"
        "0103808afb0db2fd4abff6af4149f51b";
    static const char* msg = "Cryptographic Forum Research Group";
    uint8_t key[32];
    uint8_t tag[16];

    printf("==== 用例 3：Poly1305 MAC (RFC 8439 §2.4.2) ====\n");
    hex_to_bytes(key_hex, key);
    cng_poly1305_mac(key, (const uint8_t*)msg, strlen(msg), tag);

    if (!bytes_match(tag, 16, "a8061dc1305136c6c22b8baf0c0127a9")) {
        print_hex("  实际: ", tag, 16);
        CHECK(0, "Poly1305 tag == a8061dc1...0127a9");
    } else {
        CHECK(1, "Poly1305 tag == a8061dc1...0127a9");
    }
}

/* ------------------------------------------------------------------ */
/* 用例 4：AEAD encrypt（RFC 8439 §2.8.2）                            */
/*   key  = 80:81:...:9f                                             */
/*   nonce= 07:00:00:00:40:41:42:43:44:45:46:47                      */
/*   AAD  = 50:51:52:53:c0:c1:c2:c3:c4:c5:c6:c7（12 字节）           */
/*   PT   = "Ladies and Gentlemen of the class of '99..."（114 字节）*/
/* ------------------------------------------------------------------ */
static void test_aead_encrypt_rfc8439(void)
{
    static const char* key_hex =
        "808182838485868788898a8b8c8d8e8f"
        "909192939495969798999a9b9c9d9e9f";
    static const char* nonce_hex = "070000004041424344454647";
    static const char* aad_hex   = "50515253c0c1c2c3c4c5c6c7";
    static const char* pt_str =
        "Ladies and Gentlemen of the class of '99: "
        "If I could offer you only one tip for the future, "
        "sunscreen would be it.";
    uint8_t key[32];
    uint8_t nonce[12];
    uint8_t aad[12];
    uint8_t ct[128];
    uint8_t tag[16];
    size_t pt_len = strlen(pt_str);

    printf("==== 用例 4：AEAD encrypt (RFC 8439 §2.8.2) ====\n");
    hex_to_bytes(key_hex, key);
    hex_to_bytes(nonce_hex, nonce);
    hex_to_bytes(aad_hex, aad);

    cng_chacha20_poly1305_encrypt(key, nonce,
                                  aad, sizeof(aad),
                                  (const uint8_t*)pt_str, pt_len,
                                  ct, tag);

    /* RFC 8439 §2.8.2 官方密文（114 字节，纯净 hex） */
    if (!bytes_match(ct, pt_len,
            "d31a8d34648e60db7b86afbc53ef7ec2"
            "a4aded51296e08fea9e2b5a736ee62d6"
            "3dbea45e8ca9671282fafb69da92728b"
            "1a71de0a9e060b2905d6a5b67ecd3b36"
            "92ddbd7f2d778b8c9803aee328091b58"
            "fab324e4fad675945585808b4831d7bc"
            "3ff4def08e4b7a9de576d26586cec64b"
            "6116")) {
        print_hex("  实际: ", ct, pt_len);
        CHECK(0, "AEAD 密文 == RFC 8439 §2.8.2 向量");
    } else {
        CHECK(1, "AEAD 密文 == RFC 8439 §2.8.2 向量");
    }

    /* RFC 8439 §2.8.2 官方 tag */
    if (!bytes_match(tag, 16, "1ae10b594f09e26a7e902ecbd0600691")) {
        print_hex("  实际: ", tag, 16);
        CHECK(0, "AEAD tag == 1ae10b59...060691");
    } else {
        CHECK(1, "AEAD tag == 1ae10b59...060691");
    }
}

/* ------------------------------------------------------------------ */
/* 用例 5：AEAD decrypt（RFC 8439 §2.8.2）                            */
/*   用例 4 的 key/nonce/aad/ct/tag 解密，比对明文，返回 0            */
/* ------------------------------------------------------------------ */
static void test_aead_decrypt_rfc8439(void)
{
    static const char* key_hex =
        "808182838485868788898a8b8c8d8e8f"
        "909192939495969798999a9b9c9d9e9f";
    static const char* nonce_hex = "070000004041424344454647";
    static const char* aad_hex   = "50515253c0c1c2c3c4c5c6c7";
    static const char* ct_hex =
        "d31a8d34648e60db7b86afbc53ef7ec2"
        "a4aded51296e08fea9e2b5a736ee62d6"
        "3dbea45e8ca9671282fafb69da92728b"
        "1a71de0a9e060b2905d6a5b67ecd3b36"
        "92ddbd7f2d778b8c9803aee328091b58"
        "fab324e4fad675945585808b4831d7bc"
        "3ff4def08e4b7a9de576d26586cec64b"
        "6116";
    static const char* tag_hex = "1ae10b594f09e26a7e902ecbd0600691";
    static const char* pt_expect =
        "Ladies and Gentlemen of the class of '99: "
        "If I could offer you only one tip for the future, "
        "sunscreen would be it.";
    uint8_t key[32];
    uint8_t nonce[12];
    uint8_t aad[12];
    uint8_t ct[128];
    uint8_t tag[16];
    uint8_t pt[128];
    size_t ct_len;
    int rc;

    printf("==== 用例 5：AEAD decrypt (RFC 8439 §2.8.2) ====\n");
    hex_to_bytes(key_hex, key);
    hex_to_bytes(nonce_hex, nonce);
    hex_to_bytes(aad_hex, aad);
    ct_len = hex_to_bytes(ct_hex, ct);
    hex_to_bytes(tag_hex, tag);

    rc = cng_chacha20_poly1305_decrypt(key, nonce,
                                       aad, sizeof(aad),
                                       ct, ct_len, tag, pt);
    CHECK(rc == 0, "AEAD decrypt 返回 0（tag 校验通过）");
    if (memcmp(pt, pt_expect, ct_len) != 0) {
        print_hex("  实际: ", pt, ct_len);
        CHECK(0, "AEAD 解密明文 == 原始 PT");
    } else {
        CHECK(1, "AEAD 解密明文 == 原始 PT");
    }
}

/* ------------------------------------------------------------------ */
/* 用例 6：AEAD decrypt 篡改 tag 返回 -1                              */
/* ------------------------------------------------------------------ */
static void test_aead_decrypt_tampered(void)
{
    static const char* key_hex =
        "808182838485868788898a8b8c8d8e8f"
        "909192939495969798999a9b9c9d9e9f";
    static const char* nonce_hex = "070000004041424344454647";
    static const char* aad_hex   = "50515253c0c1c2c3c4c5c6c7";
    static const char* ct_hex =
        "d31a8d34648e60db7b86afbc53ef7ec2"
        "a4aded51296e08fea9e2b5a736ee62d6";
    static const char* tag_hex = "1ae10b594f09e26a7e902ecbd0600691";
    uint8_t key[32];
    uint8_t nonce[12];
    uint8_t aad[12];
    uint8_t ct[64];
    uint8_t tag[16];
    uint8_t pt[64];
    size_t ct_len;
    int rc;

    printf("==== 用例 6：AEAD decrypt 篡改 tag ====\n");
    hex_to_bytes(key_hex, key);
    hex_to_bytes(nonce_hex, nonce);
    hex_to_bytes(aad_hex, aad);
    ct_len = hex_to_bytes(ct_hex, ct);
    hex_to_bytes(tag_hex, tag);

    /* 篡改 tag 最后一个字节 */
    tag[15] ^= 0x01u;

    rc = cng_chacha20_poly1305_decrypt(key, nonce,
                                       aad, sizeof(aad),
                                       ct, ct_len, tag, pt);
    CHECK(rc == -1, "AEAD decrypt 篡改 tag 返回 -1");
}

/* ------------------------------------------------------------------ */
/* 用例 7：AEAD round-trip（encrypt 再 decrypt）                      */
/* ------------------------------------------------------------------ */
static void test_aead_roundtrip(void)
{
    uint8_t key[32];
    uint8_t nonce[12];
    uint8_t aad[16];
    uint8_t pt[200];
    uint8_t ct[200];
    uint8_t tag[16];
    uint8_t pt2[200];
    size_t pt_len = sizeof(pt);
    size_t i;
    int rc;

    printf("==== 用例 7：AEAD round-trip ====\n");

    /* 用确定性数据填充（不依赖随机源） */
    for (i = 0; i < 32; ++i) key[i]   = (uint8_t)(0x80u + i);
    for (i = 0; i < 12; ++i) nonce[i] = (uint8_t)(0x10u + i);
    for (i = 0; i < 16; ++i) aad[i]   = (uint8_t)(0xa0u + i);
    for (i = 0; i < pt_len; ++i) pt[i] = (uint8_t)(i * 7 + 3);

    /* 7.1 明文长度为 0 */
    cng_chacha20_poly1305_encrypt(key, nonce, aad, sizeof(aad),
                                  pt, 0, ct, tag);
    rc = cng_chacha20_poly1305_decrypt(key, nonce, aad, sizeof(aad),
                                       ct, 0, tag, pt2);
    CHECK(rc == 0, "AEAD round-trip (空明文) 返回 0");

    /* 7.2 明文长度为 1（不足一个块） */
    cng_chacha20_poly1305_encrypt(key, nonce, aad, sizeof(aad),
                                  pt, 1, ct, tag);
    rc = cng_chacha20_poly1305_decrypt(key, nonce, aad, sizeof(aad),
                                       ct, 1, tag, pt2);
    CHECK(rc == 0, "AEAD round-trip (1B) 返回 0");
    CHECK(pt2[0] == pt[0], "AEAD round-trip (1B) 明文一致");

    /* 7.3 明文长度为 64（恰一个 ChaCha20 块） */
    cng_chacha20_poly1305_encrypt(key, nonce, aad, sizeof(aad),
                                  pt, 64, ct, tag);
    rc = cng_chacha20_poly1305_decrypt(key, nonce, aad, sizeof(aad),
                                       ct, 64, tag, pt2);
    CHECK(rc == 0, "AEAD round-trip (64B) 返回 0");
    CHECK(memcmp(pt, pt2, 64) == 0, "AEAD round-trip (64B) 明文一致");

    /* 7.4 明文长度为 200（多块 + 不完整尾块） */
    cng_chacha20_poly1305_encrypt(key, nonce, aad, sizeof(aad),
                                  pt, pt_len, ct, tag);
    rc = cng_chacha20_poly1305_decrypt(key, nonce, aad, sizeof(aad),
                                       ct, pt_len, tag, pt2);
    CHECK(rc == 0, "AEAD round-trip (200B) 返回 0");
    CHECK(memcmp(pt, pt2, pt_len) == 0, "AEAD round-trip (200B) 明文一致");

    /* 7.5 AAD 长度为 0 */
    cng_chacha20_poly1305_encrypt(key, nonce, NULL, 0,
                                  pt, 100, ct, tag);
    rc = cng_chacha20_poly1305_decrypt(key, nonce, NULL, 0,
                                       ct, 100, tag, pt2);
    CHECK(rc == 0, "AEAD round-trip (无 AAD) 返回 0");
    CHECK(memcmp(pt, pt2, 100) == 0, "AEAD round-trip (无 AAD) 明文一致");

    /* 7.6 AAD 不齐 16 字节（13B，需 pad16） */
    cng_chacha20_poly1305_encrypt(key, nonce, aad, 13,
                                  pt, 100, ct, tag);
    rc = cng_chacha20_poly1305_decrypt(key, nonce, aad, 13,
                                       ct, 100, tag, pt2);
    CHECK(rc == 0, "AEAD round-trip (AAD=13B) 返回 0");
    CHECK(memcmp(pt, pt2, 100) == 0, "AEAD round-trip (AAD=13B) 明文一致");
}

/* ------------------------------------------------------------------ */
/* 用例 8：入参非法安全返回                                            */
/* ------------------------------------------------------------------ */
static void test_aead_invalid_params(void)
{
    uint8_t key[32];
    uint8_t nonce[12];
    uint8_t aad[8];
    uint8_t pt[16];
    uint8_t ct[16];
    uint8_t tag[16];
    int rc;

    printf("==== 用例 8：入参非法 ====\n");

    memset(key, 0x11, sizeof(key));
    memset(nonce, 0x22, sizeof(nonce));
    memset(aad, 0x33, sizeof(aad));
    memset(pt, 0x44, sizeof(pt));

    /* encrypt: key=NULL（应直接返回，不崩） */
    cng_chacha20_poly1305_encrypt(NULL, nonce, aad, sizeof(aad),
                                  pt, sizeof(pt), ct, tag);
    CHECK(1, "encrypt key=NULL 不崩溃");

    /* encrypt: nonce=NULL */
    cng_chacha20_poly1305_encrypt(key, NULL, aad, sizeof(aad),
                                  pt, sizeof(pt), ct, tag);
    CHECK(1, "encrypt nonce=NULL 不崩溃");

    /* encrypt: tag=NULL */
    cng_chacha20_poly1305_encrypt(key, nonce, aad, sizeof(aad),
                                  pt, sizeof(pt), ct, NULL);
    CHECK(1, "encrypt tag=NULL 不崩溃");

    /* decrypt: key=NULL 返回 -1 */
    rc = cng_chacha20_poly1305_decrypt(NULL, nonce, aad, sizeof(aad),
                                       ct, sizeof(ct), tag, pt);
    CHECK(rc == -1, "decrypt key=NULL 返回 -1");

    /* decrypt: nonce=NULL 返回 -1 */
    rc = cng_chacha20_poly1305_decrypt(key, NULL, aad, sizeof(aad),
                                       ct, sizeof(ct), tag, pt);
    CHECK(rc == -1, "decrypt nonce=NULL 返回 -1");

    /* decrypt: tag=NULL 返回 -1 */
    rc = cng_chacha20_poly1305_decrypt(key, nonce, aad, sizeof(aad),
                                       ct, sizeof(ct), NULL, pt);
    CHECK(rc == -1, "decrypt tag=NULL 返回 -1");
}

/* ------------------------------------------------------------------ */
/* main                                                                */
/* ------------------------------------------------------------------ */
#ifdef WIN7BRIDGE_HOST_TEST
int main(void)
{
    test_chacha20_block_rfc8439();
    test_chacha20_encrypt_rfc8439();
    test_poly1305_rfc8439();
    test_aead_encrypt_rfc8439();
    test_aead_decrypt_rfc8439();
    test_aead_decrypt_tampered();
    test_aead_roundtrip();
    test_aead_invalid_params();

    if (g_fail) {
        printf("\n==== 存在失败用例 ====\n");
        return 1;
    }
    printf("\n==== 全部通过 ====\n");
    return 0;
}
#endif /* WIN7BRIDGE_HOST_TEST */
