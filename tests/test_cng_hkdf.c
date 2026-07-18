/*
 * test_cng_hkdf.c - Win7Bridge CNG HKDF host 测试
 *
 * 覆盖：
 *   1) SHA-256 空串（FIPS 180-4 / 公认向量）
 *   2) SHA-256 "abc"（FIPS 180-4 B.1 示例）
 *   3) HMAC-SHA256 RFC 4231 Test Case 1
 *   4) HKDF RFC 5869 Appendix A.1（Test Case 1，SHA-256）：校验 PRK 与 OKM
 *   5) HKDF RFC 5869 Appendix A.2（Test Case 2，SHA-256）：校验 PRK 与 OKM
 *   6) HKDF RFC 5869 Appendix A.3（Test Case 3，SHA-256）：salt/info 为空，校验 PRK 与 OKM
 *   7) HKDF-Expand okm_len 超过 255*32 返回 CNG_HKDF_ERR_TOO_LARGE(-2)
 *   8) 入参非法返回 CNG_HKDF_ERR_PARAM(-1)
 *
 * 仅在定义 WIN7BRIDGE_HOST_TEST 时编译 main，用原生 gcc 运行。
 * 返回 0 表示全部通过，非 0 表示有失败。
 *
 * 注：RFC 5869 A.2 官方输入为 IKM=0x00..4f(80B)、salt=0x60..af(80B)、
 *     info=0xb0..ff(80B)、L=82；本测试按 RFC 官方向量取值，以便与
 *     RFC 公布的 PRK/OKM 比对。
 */
#include "win7bridge/cng_hkdf.h"

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
/*   hex  ：仅含 [0-9a-fA-F] 的偶数长度字符串                          */
/*   out  ：输出缓冲，容量 >= len(hex)/2                                */
/*   返回 ：字节数；0 表示解析失败                                       */
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
    uint8_t tmp[256];   /* 本测试最大向量 82 字节，足够                  */
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
/* 用例 1：SHA-256 空串                                                */
/* ------------------------------------------------------------------ */
static void test_sha256_empty(void)
{
    uint8_t out[32];

    printf("==== 用例 1：SHA-256(\"\") ====\n");
    cng_sha256(NULL, 0, out);
    if (!bytes_match(out, 32,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")) {
        print_hex("  实际: ", out, 32);
        CHECK(0, "SHA-256(\"\") == e3b0c442...b855");
    } else {
        CHECK(1, "SHA-256(\"\") == e3b0c442...b855");
    }
}

/* ------------------------------------------------------------------ */
/* 用例 2：SHA-256 "abc"                                               */
/* ------------------------------------------------------------------ */
static void test_sha256_abc(void)
{
    const char* abc = "abc";
    uint8_t out[32];

    printf("==== 用例 2：SHA-256(\"abc\") ====\n");
    cng_sha256((const uint8_t*)abc, 3, out);
    if (!bytes_match(out, 32,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")) {
        print_hex("  实际: ", out, 32);
        CHECK(0, "SHA-256(\"abc\") == ba7816bf...015ad");
    } else {
        CHECK(1, "SHA-256(\"abc\") == ba7816bf...015ad");
    }
}

/* ------------------------------------------------------------------ */
/* 用例 3：HMAC-SHA256 RFC 4231 Test Case 1                           */
/*   Key  = 0x0b * 20                                                  */
/*   Data = "Hi There"                                                 */
/* ------------------------------------------------------------------ */
static void test_hmac_sha256_rfc4231_1(void)
{
    uint8_t key[20];
    const char* data = "Hi There";
    uint8_t out[32];
    int i;

    printf("==== 用例 3：HMAC-SHA256 RFC 4231 Case 1 ====\n");
    for (i = 0; i < 20; ++i) {
        key[i] = 0x0bu;
    }
    cng_hmac_sha256(key, 20, (const uint8_t*)data, 8, out);
    if (!bytes_match(out, 32,
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")) {
        print_hex("  实际: ", out, 32);
        CHECK(0, "HMAC-SHA256 == b0344c61...2cff7");
    } else {
        CHECK(1, "HMAC-SHA256 == b0344c61...2cff7");
    }
}

/* ------------------------------------------------------------------ */
/* 用例 4：HKDF RFC 5869 Appendix A.1                                  */
/*   IKM  = 0x0b * 22                                                  */
/*   salt = 0x000102...0c (13B)                                        */
/*   info = 0xf0f1...f9  (10B)                                         */
/*   L    = 42                                                         */
/* ------------------------------------------------------------------ */
static void test_hkdf_rfc5869_a1(void)
{
    uint8_t ikm[22];
    uint8_t salt[13];
    uint8_t info[10];
    uint8_t prk[32];
    uint8_t okm[42];
    int rc, i;

    printf("==== 用例 4：HKDF RFC 5869 A.1 ====\n");

    for (i = 0; i < 22; ++i) ikm[i]  = 0x0bu;
    for (i = 0; i < 13; ++i) salt[i] = (uint8_t)i;
    for (i = 0; i < 10; ++i) info[i] = (uint8_t)(0xf0u + i);

    /* 4.1 Extract 校验 PRK                                            */
    rc = cng_hkdf_extract(salt, 13, ikm, 22, prk);
    CHECK(rc == CNG_HKDF_OK, "cng_hkdf_extract 返回 0");
    if (!bytes_match(prk, 32,
            "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5")) {
        print_hex("  PRK 实际: ", prk, 32);
        CHECK(0, "PRK == 07770936...b3e5");
    } else {
        CHECK(1, "PRK == 07770936...b3e5");
    }

    /* 4.2 Expand 校验 OKM                                            */
    rc = cng_hkdf_expand(prk, info, 10, okm, 42);
    CHECK(rc == CNG_HKDF_OK, "cng_hkdf_expand 返回 0");
    if (!bytes_match(okm, 42,
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865")) {
        print_hex("  OKM 实际: ", okm, 42);
        CHECK(0, "OKM == 3cb25f25...185865");
    } else {
        CHECK(1, "OKM == 3cb25f25...185865");
    }

    /* 4.3 一步式 cng_hkdf 应与分步结果一致                            */
    {
        uint8_t okm2[42];
        rc = cng_hkdf(salt, 13, ikm, 22, info, 10, okm2, 42);
        CHECK(rc == CNG_HKDF_OK, "cng_hkdf 一步式 返回 0");
        CHECK(memcmp(okm, okm2, 42) == 0, "一步式 OKM 与分步一致");
    }
}

/* ------------------------------------------------------------------ */
/* 用例 5：HKDF RFC 5869 Appendix A.2                                  */
/*   IKM  = 0x00..4f (80B)                                             */
/*   salt = 0x60..af (80B)                                             */
/*   info = 0xb0..ff (80B)                                             */
/*   L    = 82                                                         */
/* ------------------------------------------------------------------ */
static void test_hkdf_rfc5869_a2(void)
{
    uint8_t ikm[80];
    uint8_t salt[80];
    uint8_t info[80];
    uint8_t prk[32];
    uint8_t okm[82];
    int rc, i;

    printf("==== 用例 5：HKDF RFC 5869 A.2 ====\n");

    for (i = 0; i < 80; ++i) ikm[i]  = (uint8_t)(0x00u + i);
    for (i = 0; i < 80; ++i) salt[i] = (uint8_t)(0x60u + i);
    for (i = 0; i < 80; ++i) info[i] = (uint8_t)(0xb0u + i);

    rc = cng_hkdf_extract(salt, 80, ikm, 80, prk);
    CHECK(rc == CNG_HKDF_OK, "cng_hkdf_extract 返回 0");
    if (!bytes_match(prk, 32,
            "06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244")) {
        print_hex("  PRK 实际: ", prk, 32);
        CHECK(0, "PRK == 06a6b88c...fc244");
    } else {
        CHECK(1, "PRK == 06a6b88c...fc244");
    }

    rc = cng_hkdf_expand(prk, info, 80, okm, 82);
    CHECK(rc == CNG_HKDF_OK, "cng_hkdf_expand 返回 0");
    if (!bytes_match(okm, 82,
            "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87")) {
        print_hex("  OKM 实际: ", okm, 82);
        CHECK(0, "OKM == b11e398d...3f1d87");
    } else {
        CHECK(1, "OKM == b11e398d...3f1d87");
    }

    /* 一步式一致性                                                   */
    {
        uint8_t okm2[82];
        rc = cng_hkdf(salt, 80, ikm, 80, info, 80, okm2, 82);
        CHECK(rc == CNG_HKDF_OK, "cng_hkdf 一步式 返回 0");
        CHECK(memcmp(okm, okm2, 82) == 0, "一步式 OKM 与分步一致");
    }
}

/* ------------------------------------------------------------------ */
/* 用例 6：HKDF RFC 5869 Appendix A.3                                  */
/*   IKM  = 0x0b * 22                                                  */
/*   salt = NULL（长度 0）                                             */
/*   info = NULL（长度 0）                                             */
/*   L    = 42                                                         */
/* ------------------------------------------------------------------ */
static void test_hkdf_rfc5869_a3(void)
{
    uint8_t ikm[22];
    uint8_t prk[32];
    uint8_t okm[42];
    int rc, i;

    printf("==== 用例 6：HKDF RFC 5869 A.3（salt/info 空）====\n");

    for (i = 0; i < 22; ++i) ikm[i] = 0x0bu;

    /* salt=NULL/len=0：cng_hkdf_extract 内部 HMAC key_len==0 等价全 0 */
    rc = cng_hkdf_extract(NULL, 0, ikm, 22, prk);
    CHECK(rc == CNG_HKDF_OK, "cng_hkdf_extract(salt=NULL) 返回 0");
    if (!bytes_match(prk, 32,
            "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04")) {
        print_hex("  PRK 实际: ", prk, 32);
        CHECK(0, "PRK == 19ef24a3...ccb04");
    } else {
        CHECK(1, "PRK == 19ef24a3...ccb04");
    }

    rc = cng_hkdf_expand(prk, NULL, 0, okm, 42);
    CHECK(rc == CNG_HKDF_OK, "cng_hkdf_expand(info=NULL) 返回 0");
    if (!bytes_match(okm, 42,
            "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8")) {
        print_hex("  OKM 实际: ", okm, 42);
        CHECK(0, "OKM == 8da4e775...61a96c8");
    } else {
        CHECK(1, "OKM == 8da4e775...61a96c8");
    }

    /* 一步式一致性                                                   */
    {
        uint8_t okm2[42];
        rc = cng_hkdf(NULL, 0, ikm, 22, NULL, 0, okm2, 42);
        CHECK(rc == CNG_HKDF_OK, "cng_hkdf 一步式 返回 0");
        CHECK(memcmp(okm, okm2, 42) == 0, "一步式 OKM 与分步一致");
    }
}

/* ------------------------------------------------------------------ */
/* 用例 7：HKDF-Expand okm_len 超限返回 -2                             */
/* ------------------------------------------------------------------ */
static void test_hkdf_expand_too_large(void)
{
    uint8_t prk[32];
    uint8_t okm[CNG_HKDF_MAX_EXPAND_LEN + 1];   /* 8161 字节           */
    int rc;

    printf("==== 用例 7：HKDF-Expand okm_len 超限 ====\n");

    memset(prk, 0x11, sizeof(prk));
    rc = cng_hkdf_expand(prk, NULL, 0, okm, CNG_HKDF_MAX_EXPAND_LEN);
    CHECK(rc == CNG_HKDF_OK, "okm_len == 255*32 返回 0（边界）");

    rc = cng_hkdf_expand(prk, NULL, 0, okm, CNG_HKDF_MAX_EXPAND_LEN + 1);
    CHECK(rc == CNG_HKDF_ERR_TOO_LARGE, "okm_len == 255*32+1 返回 -2");

    /* 一步式同样校验                                                 */
    rc = cng_hkdf(NULL, 0, prk, 32, NULL, 0, okm, CNG_HKDF_MAX_EXPAND_LEN + 1);
    CHECK(rc == CNG_HKDF_ERR_TOO_LARGE, "cng_hkdf okm_len 超限 返回 -2");
}

/* ------------------------------------------------------------------ */
/* 用例 8：入参非法返回 -1                                             */
/* ------------------------------------------------------------------ */
static void test_hkdf_invalid_params(void)
{
    uint8_t prk[32];
    uint8_t okm[32];
    int rc;

    printf("==== 用例 8：入参非法返回 -1 ====\n");

    /* extract: ikm=NULL                                              */
    rc = cng_hkdf_extract(NULL, 0, NULL, 0, prk);
    CHECK(rc == CNG_HKDF_ERR_PARAM, "extract ikm=NULL 返回 -1");

    /* extract: prk 输出 NULL                                         */
    rc = cng_hkdf_extract(NULL, 0, (const uint8_t*)"", 0, NULL);
    CHECK(rc == CNG_HKDF_ERR_PARAM, "extract prk=NULL 返回 -1");

    /* expand: prk=NULL                                               */
    rc = cng_hkdf_expand(NULL, NULL, 0, okm, 16);
    CHECK(rc == CNG_HKDF_ERR_PARAM, "expand prk=NULL 返回 -1");

    /* expand: okm=NULL                                               */
    rc = cng_hkdf_expand(prk, NULL, 0, NULL, 16);
    CHECK(rc == CNG_HKDF_ERR_PARAM, "expand okm=NULL 返回 -1");

    /* expand: info=NULL 但 info_len>0                                */
    rc = cng_hkdf_expand(prk, NULL, 4, okm, 16);
    CHECK(rc == CNG_HKDF_ERR_PARAM, "expand info=NULL,len>0 返回 -1");

    /* 一步式：ikm=NULL                                               */
    rc = cng_hkdf(NULL, 0, NULL, 0, NULL, 0, okm, 16);
    CHECK(rc == CNG_HKDF_ERR_PARAM, "cng_hkdf ikm=NULL 返回 -1");
}

/* ------------------------------------------------------------------ */
/* main                                                                */
/* ------------------------------------------------------------------ */
#ifdef WIN7BRIDGE_HOST_TEST
int main(void)
{
    test_sha256_empty();
    test_sha256_abc();
    test_hmac_sha256_rfc4231_1();
    test_hkdf_rfc5869_a1();
    test_hkdf_rfc5869_a2();
    test_hkdf_rfc5869_a3();
    test_hkdf_expand_too_large();
    test_hkdf_invalid_params();

    if (g_fail) {
        printf("\n==== 存在失败用例 ====\n");
        return 1;
    }
    printf("\n==== 全部通过 ====\n");
    return 0;
}
#endif /* WIN7BRIDGE_HOST_TEST */
