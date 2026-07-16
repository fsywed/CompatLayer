/*
 * test_manifest.c - Win7Bridge PE manifest 改写 host 测试
 *
 * 验证 manifest_inject_win7_guid 与 manifest_strip_win10_only 的行为：
 *   - inject：无 Win7 GUID 时注入；已含时不重复注入；无 compatibility 块时
 *     追加最小块。
 *   - strip：剥离配对 <maxversiontested>...</maxversiontested> 与自闭合
 *     <msix .../>，剥离后不再含对应子串。
 *
 * 用 -DWIN7BRIDGE_HOST_TEST 编译，原生 gcc 运行。返回 0 表示全部通过。
 */
#include "win7bridge/manifest.h"

#include <stdio.h>
#include <string.h>

/* Win7 GUID 主体（用于计数出现次数） */
#define WIN7_GUID_BODY "35138b9a-5d96-4fbd-8e2d-a2440225f93a"

static int g_fail = 0;

/* 简单断言：失败则计数并打印 */
static void check(int cond, const char* msg)
{
    if (cond) {
        printf("[ OK ] %s\n", msg);
    } else {
        printf("[FAIL] %s\n", msg);
        ++g_fail;
    }
}

/* 统计 sub 在 buf 中出现次数 */
static int count_occurrences(const char* buf, const char* sub)
{
    int cnt = 0;
    const char* p = buf;
    size_t sl = strlen(sub);
    while ((p = strstr(p, sub)) != NULL) {
        ++cnt;
        p += sl;
    }
    return cnt;
}

/* ------------------------------------------------------------------ */
/* 测试 1：无 Win7 GUID 的 manifest，注入后应含 Win7 GUID              */
/* ------------------------------------------------------------------ */
static void test_inject_basic(void)
{
    static const char src[] =
        "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n"
        "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\">\n"
        "  <compatibility xmlns=\"urn:schemas-microsoft-com:compatibility.v1\">\n"
        "    <application>\n"
        "      <supportedOS Id=\"{1f676c76-80e1-4239-95bb-83d0f6d0da78}\"/>\n"
        "    </application>\n"
        "  </compatibility>\n"
        "</assembly>\n";
    char buf[1024];
    size_t sz = strlen(src);
    size_t newsz = 0;
    int r;

    memcpy(buf, src, sz + 1);  /* 含末尾 NUL */

    r = manifest_inject_win7_guid(buf, sz, sizeof(buf), &newsz);
    check(r == 1, "inject_basic: 返回 1（已注入）");
    check(newsz > sz, "inject_basic: 新长度大于原长度");
    check(strstr(buf, WIN7_GUID_BODY) != NULL,
          "inject_basic: 注入后含 Win7 GUID");
    check(strstr(buf, "</assembly>") != NULL,
          "inject_basic: 结构完整，仍含 </assembly>");
    /* 原有的非 Win7 GUID 不应被破坏 */
    check(strstr(buf, "1f676c76-80e1-4239-95bb-83d0f6d0da78") != NULL,
          "inject_basic: 保留原有 supportedOS GUID");
}

/* ------------------------------------------------------------------ */
/* 测试 2：已含 Win7 GUID，不应重复注入                                */
/* ------------------------------------------------------------------ */
static void test_inject_idempotent(void)
{
    static const char src[] =
        "<assembly>\n"
        "  <compatibility>\n"
        "    <application>\n"
        "      <supportedOS Id=\"{35138b9a-5d96-4fbd-8e2d-a2440225f93a}\"/>\n"
        "    </application>\n"
        "  </compatibility>\n"
        "</assembly>\n";
    char buf[1024];
    size_t sz = strlen(src);
    size_t newsz = 0;
    int before, after;
    int r;

    memcpy(buf, src, sz + 1);
    before = count_occurrences(buf, WIN7_GUID_BODY);

    r = manifest_inject_win7_guid(buf, sz, sizeof(buf), &newsz);
    check(r == 0, "inject_idempotent: 返回 0（无需注入）");
    check(newsz == sz, "inject_idempotent: 长度不变");

    after = count_occurrences(buf, WIN7_GUID_BODY);
    check(after == before, "inject_idempotent: Win7 GUID 数量未增加");
}

/* ------------------------------------------------------------------ */
/* 测试 3：无 compatibility 块，应追加最小 compatibility 块            */
/* ------------------------------------------------------------------ */
static void test_inject_no_compat(void)
{
    static const char src[] =
        "<assembly>\n"
        "  <dependency>\n"
        "    <dependentAssembly/>\n"
        "  </dependency>\n"
        "</assembly>\n";
    char buf[1024];
    size_t sz = strlen(src);
    size_t newsz = 0;
    int r;

    memcpy(buf, src, sz + 1);

    r = manifest_inject_win7_guid(buf, sz, sizeof(buf), &newsz);
    check(r == 1, "inject_no_compat: 返回 1（已注入）");
    check(strstr(buf, "<compatibility") != NULL,
          "inject_no_compat: 已追加 compatibility 块");
    check(strstr(buf, WIN7_GUID_BODY) != NULL,
          "inject_no_compat: 含 Win7 GUID");
    check(strstr(buf, "</assembly>") != NULL,
          "inject_no_compat: 结构完整，仍含 </assembly>");
}

/* ------------------------------------------------------------------ */
/* 测试 4：剥离配对 <maxversiontested> 与配对/自闭合 <msix>           */
/* ------------------------------------------------------------------ */
static void test_strip(void)
{
    static const char src[] =
        "<assembly>\n"
        "  <compatibility>\n"
        "    <application>\n"
        "      <maxversiontested Id=\"bar\"/>\n"
        "      <supportedOS Id=\"{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}\"/>\n"
        "      <msix>\n"
        "        <inner>data</inner>\n"
        "      </msix>\n"
        "    </application>\n"
        "  </compatibility>\n"
        "</assembly>\n";
    char buf[1024];
    size_t sz = strlen(src);
    size_t newsz = 0;
    int r;

    memcpy(buf, src, sz + 1);

    r = manifest_strip_win10_only(buf, sz, sizeof(buf), &newsz);
    check(r >= 2, "strip: 返回剥离个数 >= 2");
    check(newsz < sz, "strip: 剥离后长度减小");

    check(strstr(buf, "maxversiontested") == NULL,
          "strip: 不再含 maxversiontested");
    check(strstr(buf, "msix") == NULL,
          "strip: 不再含 msix");
    /* 应保留非 Win10-only 的内容 */
    check(strstr(buf, "supportedOS") != NULL,
          "strip: 保留 supportedOS");
    check(strstr(buf, "</assembly>") != NULL,
          "strip: 结构完整，仍含 </assembly>");
}

/* ------------------------------------------------------------------ */
/* 测试 5：多次/混合剥离，验证循环剥离彻底                              */
/* ------------------------------------------------------------------ */
static void test_strip_multiple(void)
{
    static const char src[] =
        "<assembly>\n"
        "  <maxversiontested Id=\"a\"/>\n"
        "  <msix x=\"1\"/>\n"
        "  <maxversiontested Id=\"b\"><child/></maxversiontested>\n"
        "  <msix><child/></msix>\n"
        "</assembly>\n";
    char buf[1024];
    size_t sz = strlen(src);
    size_t newsz = 0;
    int r;

    memcpy(buf, src, sz + 1);

    r = manifest_strip_win10_only(buf, sz, sizeof(buf), &newsz);
    check(r >= 4, "strip_multiple: 返回剥离个数 >= 4");
    check(strstr(buf, "maxversiontested") == NULL,
          "strip_multiple: 不再含 maxversiontested");
    check(strstr(buf, "msix") == NULL,
          "strip_multiple: 不再含 msix");
    check(strstr(buf, "<assembly>") != NULL,
          "strip_multiple: 保留 assembly");
}

int main(void)
{
    test_inject_basic();
    test_inject_idempotent();
    test_inject_no_compat();
    test_strip();
    test_strip_multiple();

    if (g_fail == 0) {
        printf("\n所有 manifest 测试通过\n");
        return 0;
    }
    printf("\n%d 项 manifest 测试失败\n", g_fail);
    return 1;
}
