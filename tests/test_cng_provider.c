/*
 * test_cng_provider.c - Win7Bridge BCrypt provider 适配层 host 测试
 *
 * 覆盖：
 *   1) Open/Close algorithm provider（CHACHA20_POLY1305 + HKDF）
 *   2) 句柄判定：magic 校验、NULL 检测、非本地指针检测
 *   3) GetProperty：KeyLength=256bit、AuthTagLength(min=max=16)、BlockLength=64
 *   4) GenerateSymmetricKey / DestroyKey：正常 + 非法 key_len
 *   5) Encrypt/Decrypt round-trip（含 AAD、空明文、200B）
 *   6) RFC 8439 §2.8.2 官方向量（与 test_cng_chacha20 用例 4 对齐）
 *   7) 篡改 tag → decrypt 返回 -1
 *   8) 入参非法：NULL 句柄、错误算法类型、错误 nonce/tag 长度
 *
 * 仅在定义 WIN7BRIDGE_HOST_TEST 时编译 main，用原生 gcc 运行。
 */
#include "win7bridge/cng_provider.h"
#include "win7bridge/cng_chacha20.h"

#include <stdio.h>
#include <string.h>
#include <stdint.h>

/* ------------------------------------------------------------------ */
/* 断言                                                                */
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
/* 辅助                                                                */
/* ------------------------------------------------------------------ */
static size_t hex_to_bytes(const char* hex, uint8_t* out)
{
    size_t i, n = strlen(hex);
    if (n % 2 != 0) return 0;
    for (i = 0; i < n / 2; ++i) {
        const char* p = hex + i * 2;
        char c1 = p[0], c2 = p[1];
        uint8_t hi, lo;
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

static uint32_t le32_from_bytes(const uint8_t* p)
{
    return ((uint32_t)p[0]) | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

/* ------------------------------------------------------------------ */
/* 用例 1：Open / Close algorithm provider                              */
/* ------------------------------------------------------------------ */
static void test_open_close(void)
{
    w7b_alg_handle* hCha = NULL;
    w7b_alg_handle* hHkdf = NULL;

    printf("==== 用例 1：Open/Close algorithm provider ====\n");

    CHECK(w7b_provider_open_alg(W7B_ALG_CHACHA20_POLY1305, &hCha) == 0,
          "open CHACHA20_POLY1305 返回 0");
    CHECK(hCha != NULL, "alg handle 非 NULL");
    CHECK(w7b_is_alg_handle(hCha), "w7b_is_alg_handle 识别本地句柄");

    CHECK(w7b_provider_open_alg(W7B_ALG_HKDF, &hHkdf) == 0,
          "open HKDF 返回 0");
    CHECK(w7b_is_alg_handle(hHkdf), "HKDF handle 识别");

    CHECK(w7b_provider_close_alg(hCha) == 0, "close CHACHA20_POLY1305 返回 0");
    CHECK(w7b_provider_close_alg(hHkdf) == 0, "close HKDF 返回 0");

    /* 关闭后不再有效 */
    CHECK(!w7b_is_alg_handle(hCha), "close 后 is_alg_handle 返回 0");

    /* 非法参数 */
    CHECK(w7b_provider_open_alg(W7B_ALG_NONE, &hCha) == -1,
          "open ALG_NONE 返回 -1");
    CHECK(w7b_provider_open_alg(W7B_ALG_CHACHA20_POLY1305, NULL) == -1,
          "open ph=NULL 返回 -1");
    CHECK(w7b_provider_close_alg(NULL) == -1, "close NULL 返回 -1");
}

/* ------------------------------------------------------------------ */
/* 用例 2：句柄判定                                                     */
/* ------------------------------------------------------------------ */
static void test_handle_check(void)
{
    int dummy = 0;
    w7b_alg_handle* h = NULL;

    printf("==== 用例 2：句柄判定 ====\n");

    CHECK(!w7b_is_alg_handle(NULL), "is_alg_handle(NULL) == 0");
    CHECK(!w7b_is_key_handle(NULL), "is_key_handle(NULL) == 0");
    /* 非本地指针（栈变量）不应被误判 */
    CHECK(!w7b_is_alg_handle(&dummy), "is_alg_handle(栈变量) == 0");
    CHECK(!w7b_is_key_handle(&dummy), "is_key_handle(栈变量) == 0");

    w7b_provider_open_alg(W7B_ALG_CHACHA20_POLY1305, &h);
    CHECK(w7b_is_alg_handle(h) && !w7b_is_key_handle(h),
          "alg handle 不被误判为 key handle");
    w7b_provider_close_alg(h);
}

/* ------------------------------------------------------------------ */
/* 用例 3：GetProperty                                                  */
/* ------------------------------------------------------------------ */
static void test_get_property(void)
{
    w7b_alg_handle* h = NULL;
    uint8_t buf[16];
    size_t result = 0;

    printf("==== 用例 3：GetProperty ====\n");

    w7b_provider_open_alg(W7B_ALG_CHACHA20_POLY1305, &h);

    /* KeyLength = 256 bit */
    CHECK(w7b_provider_get_property(h, W7B_PROP_KEY_LENGTH,
                                     buf, sizeof(buf), &result) == 0,
          "GetProperty(KeyLength) 返回 0");
    CHECK(result == 4, "KeyLength 写入 4 字节");
    CHECK(le32_from_bytes(buf) == 256, "KeyLength == 256 bit");

    /* AuthTagLength: min=max=16 */
    CHECK(w7b_provider_get_property(h, W7B_PROP_AUTH_TAG_LENGTH,
                                     buf, sizeof(buf), &result) == 0,
          "GetProperty(AuthTagLength) 返回 0");
    CHECK(result == 8, "AuthTagLength 写入 8 字节");
    CHECK(le32_from_bytes(buf) == 16, "AuthTagLength.min == 16");
    CHECK(le32_from_bytes(buf + 4) == 16, "AuthTagLength.max == 16");

    /* BlockLength = 64 */
    CHECK(w7b_provider_get_property(h, W7B_PROP_BLOCK_LENGTH,
                                     buf, sizeof(buf), &result) == 0,
          "GetProperty(BlockLength) 返回 0");
    CHECK(le32_from_bytes(buf) == 64, "BlockLength == 64");

    /* ObjectLength = 0（provider 自行管理） */
    CHECK(w7b_provider_get_property(h, W7B_PROP_OBJECT_LENGTH,
                                     buf, sizeof(buf), &result) == 0,
          "GetProperty(ObjectLength) 返回 0");
    CHECK(le32_from_bytes(buf) == 0, "ObjectLength == 0");

    /* 缓冲过小 */
    CHECK(w7b_provider_get_property(h, W7B_PROP_KEY_LENGTH,
                                     buf, 2, NULL) == -1,
          "GetProperty 缓冲过小返回 -1");

    /* 未知属性 */
    CHECK(w7b_provider_get_property(h, W7B_PROP_NONE,
                                     buf, sizeof(buf), &result) == -1,
          "GetProperty(NONE) 返回 -1");

    w7b_provider_close_alg(h);
}

/* ------------------------------------------------------------------ */
/* 用例 4：GenerateSymmetricKey / DestroyKey                            */
/* ------------------------------------------------------------------ */
static void test_gen_key(void)
{
    w7b_alg_handle* hAlg = NULL;
    w7b_key_handle* hKey = NULL;
    uint8_t key[32];
    size_t i;

    printf("==== 用例 4：GenerateSymmetricKey / DestroyKey ====\n");

    w7b_provider_open_alg(W7B_ALG_CHACHA20_POLY1305, &hAlg);

    for (i = 0; i < 32; ++i) key[i] = (uint8_t)(i + 1);

    CHECK(w7b_provider_gen_key(hAlg, &hKey, key, 32) == 0,
          "gen_key(32B) 返回 0");
    CHECK(w7b_is_key_handle(hKey), "key handle 有效");
    CHECK(hKey->alg == W7B_ALG_CHACHA20_POLY1305, "key alg 正确");
    CHECK(memcmp(hKey->key, key, 32) == 0, "key 内容正确");

    CHECK(w7b_provider_destroy_key(hKey) == 0, "destroy_key 返回 0");
    CHECK(!w7b_is_key_handle(hKey), "destroy 后无效");

    /* 非法 key 长度 */
    CHECK(w7b_provider_gen_key(hAlg, &hKey, key, 16) == -1,
          "gen_key(16B) 返回 -1");
    CHECK(w7b_provider_gen_key(hAlg, &hKey, key, 31) == -1,
          "gen_key(31B) 返回 -1");
    CHECK(w7b_provider_gen_key(hAlg, &hKey, NULL, 32) == -1,
          "gen_key(key=NULL) 返回 -1");
    CHECK(w7b_provider_gen_key(hAlg, NULL, key, 32) == -1,
          "gen_key(phKey=NULL) 返回 -1");

    w7b_provider_close_alg(hAlg);
}

/* ------------------------------------------------------------------ */
/* 用例 5：Encrypt/Decrypt round-trip                                  */
/* ------------------------------------------------------------------ */
static void test_roundtrip(void)
{
    w7b_alg_handle* hAlg = NULL;
    w7b_key_handle* hKey = NULL;
    uint8_t key[32], nonce[12], aad[16];
    uint8_t pt[200], ct[200], pt2[200], tag[16];
    size_t i;

    printf("==== 用例 5：Encrypt/Decrypt round-trip ====\n");

    w7b_provider_open_alg(W7B_ALG_CHACHA20_POLY1305, &hAlg);
    for (i = 0; i < 32; ++i) key[i] = (uint8_t)(i * 7 + 3);
    w7b_provider_gen_key(hAlg, &hKey, key, 32);

    for (i = 0; i < 12; ++i) nonce[i] = (uint8_t)(i + 0xA0);
    for (i = 0; i < 16; ++i) aad[i] = (uint8_t)(i + 0xB0);

    /* 空明文 */
    {
        uint8_t t[16];
        CHECK(w7b_provider_encrypt(hKey, nonce, 12, aad, 16,
                                    NULL, 0, NULL, t, 16) == 0,
              "encrypt(空明文) 返回 0");
        CHECK(w7b_provider_decrypt(hKey, nonce, 12, aad, 16,
                                    NULL, 0, t, 16, NULL) == 0,
              "decrypt(空明文) 返回 0");
    }

    /* 200 字节明文 */
    for (i = 0; i < 200; ++i) pt[i] = (uint8_t)(i * 3 + 1);
    CHECK(w7b_provider_encrypt(hKey, nonce, 12, aad, 16,
                                pt, 200, ct, tag, 16) == 0,
          "encrypt(200B) 返回 0");
    CHECK(w7b_provider_decrypt(hKey, nonce, 12, aad, 16,
                                ct, 200, tag, 16, pt2) == 0,
          "decrypt(200B) 返回 0");
    CHECK(memcmp(pt, pt2, 200) == 0, "200B round-trip 明文一致");

    /* 无 AAD */
    CHECK(w7b_provider_encrypt(hKey, nonce, 12, NULL, 0,
                                pt, 100, ct, tag, 16) == 0,
          "encrypt(无AAD) 返回 0");
    CHECK(w7b_provider_decrypt(hKey, nonce, 12, NULL, 0,
                                ct, 100, tag, 16, pt2) == 0,
          "decrypt(无AAD) 返回 0");
    CHECK(memcmp(pt, pt2, 100) == 0, "无AAD round-trip 明文一致");

    w7b_provider_destroy_key(hKey);
    w7b_provider_close_alg(hAlg);
}

/* ------------------------------------------------------------------ */
/* 用例 6：RFC 8439 §2.8.2 官方向量                                     */
/* ------------------------------------------------------------------ */
static void test_rfc8439_aead(void)
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
    static const char* ct_expect =
        "d31a8d34648e60db7b86afbc53ef7ec2"
        "a4aded51296e08fea9e2b5a736ee62d6"
        "3dbea45e8ca9671282fafb69da92728b"
        "1a71de0a9e060b2905d6a5b67ecd3b36"
        "92ddbd7f2d778b8c9803aee328091b58"
        "fab324e4fad675945585808b4831d7bc"
        "3ff4def08e4b7a9de576d26586cec64b"
        "6116";
    static const char* tag_expect = "1ae10b594f09e26a7e902ecbd0600691";

    w7b_alg_handle* hAlg = NULL;
    w7b_key_handle* hKey = NULL;
    uint8_t key[32], nonce[12], aad[12];
    uint8_t ct[128], tag[16], pt2[128];
    uint8_t ct_want[128], tag_want[16];
    size_t pt_len = strlen(pt_str);

    printf("==== 用例 6：RFC 8439 §2.8.2 官方向量 ====\n");

    hex_to_bytes(key_hex, key);
    hex_to_bytes(nonce_hex, nonce);
    hex_to_bytes(aad_hex, aad);
    hex_to_bytes(ct_expect, ct_want);
    hex_to_bytes(tag_expect, tag_want);

    w7b_provider_open_alg(W7B_ALG_CHACHA20_POLY1305, &hAlg);
    w7b_provider_gen_key(hAlg, &hKey, key, 32);

    CHECK(w7b_provider_encrypt(hKey, nonce, 12, aad, 12,
                                (const uint8_t*)pt_str, pt_len,
                                ct, tag, 16) == 0,
          "encrypt 返回 0");
    CHECK(memcmp(ct, ct_want, pt_len) == 0, "密文 == RFC 8439 §2.8.2");
    CHECK(memcmp(tag, tag_want, 16) == 0, "tag == RFC 8439 §2.8.2");

    CHECK(w7b_provider_decrypt(hKey, nonce, 12, aad, 12,
                                ct, pt_len, tag, 16, pt2) == 0,
          "decrypt 返回 0");
    CHECK(memcmp(pt2, pt_str, pt_len) == 0, "解密明文一致");

    w7b_provider_destroy_key(hKey);
    w7b_provider_close_alg(hAlg);
}

/* ------------------------------------------------------------------ */
/* 用例 7：篡改 tag → decrypt 返回 -1                                   */
/* ------------------------------------------------------------------ */
static void test_tampered_tag(void)
{
    w7b_alg_handle* hAlg = NULL;
    w7b_key_handle* hKey = NULL;
    uint8_t key[32], nonce[12], pt[64], ct[64], tag[16], pt2[64];
    size_t i;

    printf("==== 用例 7：篡改 tag ====\n");

    w7b_provider_open_alg(W7B_ALG_CHACHA20_POLY1305, &hAlg);
    for (i = 0; i < 32; ++i) key[i] = (uint8_t)(0x40 + i);
    for (i = 0; i < 12; ++i) nonce[i] = 0;
    for (i = 0; i < 64; ++i) pt[i] = (uint8_t)i;
    w7b_provider_gen_key(hAlg, &hKey, key, 32);

    w7b_provider_encrypt(hKey, nonce, 12, NULL, 0, pt, 64, ct, tag, 16);
    tag[15] ^= 0x01;
    CHECK(w7b_provider_decrypt(hKey, nonce, 12, NULL, 0,
                                ct, 64, tag, 16, pt2) == -1,
          "篡改 tag 后 decrypt 返回 -1");

    w7b_provider_destroy_key(hKey);
    w7b_provider_close_alg(hAlg);
}

/* ------------------------------------------------------------------ */
/* 用例 8：入参非法                                                     */
/* ------------------------------------------------------------------ */
static void test_invalid_params(void)
{
    w7b_alg_handle* hAlg = NULL;
    w7b_key_handle* hKey = NULL;
    uint8_t key[32], nonce[12], pt[16], ct[16], tag[16];
    size_t i;

    printf("==== 用例 8：入参非法 ====\n");

    for (i = 0; i < 32; ++i) key[i] = 0;
    for (i = 0; i < 12; ++i) nonce[i] = 0;
    for (i = 0; i < 16; ++i) { pt[i] = 0; ct[i] = 0; tag[i] = 0; }

    w7b_provider_open_alg(W7B_ALG_CHACHA20_POLY1305, &hAlg);
    w7b_provider_gen_key(hAlg, &hKey, key, 32);

    /* encrypt: NULL key handle */
    CHECK(w7b_provider_encrypt(NULL, nonce, 12, NULL, 0,
                                pt, 16, ct, tag, 16) == -1,
          "encrypt hKey=NULL 返回 -1");
    /* encrypt: nonce 长度错误 */
    CHECK(w7b_provider_encrypt(hKey, nonce, 8, NULL, 0,
                                pt, 16, ct, tag, 16) == -1,
          "encrypt nonce_len=8 返回 -1");
    /* encrypt: tag 长度错误 */
    CHECK(w7b_provider_encrypt(hKey, nonce, 12, NULL, 0,
                                pt, 16, ct, tag, 12) == -1,
          "encrypt tag_len=12 返回 -1");

    /* decrypt: NULL key handle */
    CHECK(w7b_provider_decrypt(NULL, nonce, 12, NULL, 0,
                                ct, 16, tag, 16, pt) == -1,
          "decrypt hKey=NULL 返回 -1");
    /* decrypt: nonce 长度错误 */
    CHECK(w7b_provider_decrypt(hKey, nonce, 8, NULL, 0,
                                ct, 16, tag, 16, pt) == -1,
          "decrypt nonce_len=8 返回 -1");

    /* gen_key: 非算法句柄 */
    CHECK(w7b_provider_gen_key((w7b_alg_handle*)hKey, &hKey, key, 32) == -1,
          "gen_key 用 key handle 当 alg handle 返回 -1");

    /* get_property: 非算法句柄 */
    {
        uint8_t buf[8];
        size_t r;
        CHECK(w7b_provider_get_property((w7b_alg_handle*)hKey,
                                         W7B_PROP_KEY_LENGTH,
                                         buf, sizeof(buf), &r) == -1,
              "get_property 用 key handle 返回 -1");
    }

    w7b_provider_destroy_key(hKey);
    w7b_provider_close_alg(hAlg);
}

/* ------------------------------------------------------------------ */
/* main                                                                */
/* ------------------------------------------------------------------ */
#ifdef WIN7BRIDGE_HOST_TEST
int main(void)
{
    test_open_close();
    test_handle_check();
    test_get_property();
    test_gen_key();
    test_roundtrip();
    test_rfc8439_aead();
    test_tampered_tag();
    test_invalid_params();

    if (g_fail) {
        printf("\n==== 存在失败 ====\n");
        return 1;
    }
    printf("\n==== 全部通过 ====\n");
    return 0;
}
#endif
