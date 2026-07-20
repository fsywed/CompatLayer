/*
 * test_synch_resolve.c - Win7Bridge SubTask 2.3.4 验证测试
 *
 * 验证：测试程序导入 api-ms-win-core-synch-l1-2-0.dll 能正常解析到
 * WaitOnAddress 本地实现。
 *
 * 端到端验证链：
 *   1) 合成 PE 导入 api-ms-win-core-synch-l1-2-0.dll!WaitOnAddress
 *   2) apiset_is_virtual_name 识别为虚拟名
 *   3) apiset_lookup 解析为 TO_LOCAL + host_dll=win7bridge_local
 *   4) apiset_resolve_imports 报告需要处理
 *   5) engine_add_dll_redirect 配置转发规则
 *   6) engine_rewrite_imports 改写导入 DLL 名
 *   7) sim_WaitOnAddress 本地实现可调用且语义正确
 *
 * 仅在定义 WIN7BRIDGE_HOST_TEST 时编译 main，用原生 gcc 运行。
 * 返回 0 表示全部通过，非 0 表示有失败。
 */
#include "win7bridge/apiset.h"
#include "win7bridge/engine.h"
#include "win7bridge/pe.h"
#include "win7bridge/sim_time.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------ */
/* 合成 PE 布局常量（与 test_apiset.c 同布局）                          */
/* ------------------------------------------------------------------ */
#define IMG_SIZE           0x400   /* 1024 字节                        */
#define DOS_OFF            0x00
#define NT_OFF             0x40
#define OPT_OFF            (NT_OFF + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER))
#define SEC_OFF            (NT_OFF + sizeof(IMAGE_NT_HEADERS32))
#define SEC_VA             0x200
#define SIZE_OF_HEADERS    0x200
#define SIZE_OF_IMAGE      0x400

#define IMP_DESC_OFF       0x200   /* 导入描述符数组（2 项）           */
#define IMP_NAME_OFF       0x240   /* DLL 名字符串（预留 0x30 字节）   */
#define ILT_OFF            0x280   /* Import Lookup Table              */
#define IAT_OFF            0x288   /* Import Address Table             */
#define IBN_OFF            0x2A0   /* IMAGE_IMPORT_BY_NAME             */

/* ------------------------------------------------------------------ */
/* 简单断言                                                            */
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

/*
 * build_pe_with_import - 构造含单个 DLL/单个函数导入的最小 PE32 镜像
 *   dll_name  ：导入的 DLL 名（写入 IMP_NAME_OFF，需不超过 0x3F 字节）
 *   func_name ：按名导入的函数名（写入 IBN_OFF）
 * 缓冲区需 >= IMG_SIZE 字节且可写。
 */
static void build_pe_with_import(unsigned char* buf, size_t size,
                                 const char* dll_name, const char* func_name)
{
    IMAGE_DOS_HEADER* dos;
    IMAGE_NT_HEADERS32* nt;
    IMAGE_OPTIONAL_HEADER32* opt;
    IMAGE_SECTION_HEADER* sec;
    IMAGE_IMPORT_DESCRIPTOR* imp;
    DWORD* ilt;
    DWORD* iat;
    IMAGE_IMPORT_BY_NAME* ibn;

    (void)size;
    memset(buf, 0, IMG_SIZE);

    /* DOS 头 */
    dos = (IMAGE_DOS_HEADER*)(buf + DOS_OFF);
    dos->e_magic = IMAGE_DOS_SIGNATURE;
    dos->e_lfanew = NT_OFF;

    /* NT 头 */
    nt = (IMAGE_NT_HEADERS32*)(buf + NT_OFF);
    nt->Signature = IMAGE_NT_SIGNATURE;
    nt->FileHeader.Machine = 0x014C;                 /* I386 */
    nt->FileHeader.NumberOfSections = 1;
    nt->FileHeader.SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER32);
    nt->FileHeader.Characteristics = 0x0102;

    /* OptionalHeader */
    opt = (IMAGE_OPTIONAL_HEADER32*)(buf + OPT_OFF);
    opt->Magic = IMAGE_NT_OPTIONAL_HDR32_MAGIC;
    opt->MajorOperatingSystemVersion = 6;
    opt->MinorOperatingSystemVersion = 1;
    opt->MajorSubsystemVersion = 6;
    opt->MinorSubsystemVersion = 1;
    opt->ImageBase = 0x00400000;
    opt->SectionAlignment = 0x200;
    opt->FileAlignment = 0x200;
    opt->SizeOfImage = SIZE_OF_IMAGE;
    opt->SizeOfHeaders = SIZE_OF_HEADERS;
    opt->Subsystem = 3;                              /* WINDOWS_CUI */
    opt->NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;

    /* 导入表数据目录 */
    opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = IMP_DESC_OFF;
    opt->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size = 2 * sizeof(IMAGE_IMPORT_DESCRIPTOR);

    /* 节头 */
    sec = (IMAGE_SECTION_HEADER*)(buf + SEC_OFF);
    memcpy(sec->Name, ".text\0\0\0", 8);
    sec->Misc.VirtualSize = 0x200;
    sec->VirtualAddress = SEC_VA;
    sec->SizeOfRawData = 0x200;
    sec->PointerToRawData = SEC_VA;
    sec->Characteristics = 0x60000020;               /* CODE|EXECUTE|READ */

    /* 导入描述符（1 项 + 终止项） */
    imp = (IMAGE_IMPORT_DESCRIPTOR*)(buf + IMP_DESC_OFF);
    imp[0].OriginalFirstThunk = ILT_OFF;
    imp[0].TimeDateStamp = 0;
    imp[0].ForwarderChain = 0;
    imp[0].Name = IMP_NAME_OFF;
    imp[0].FirstThunk = IAT_OFF;
    /* imp[1] 全零终止 */

    /* DLL 名 */
    memcpy(buf + IMP_NAME_OFF, dll_name, strlen(dll_name) + 1);

    /* ILT / IAT：各 2 个 DWORD（1 thunk + 0 终止） */
    ilt = (DWORD*)(buf + ILT_OFF);
    ilt[0] = IBN_OFF;                                /* 指向 IMPORT_BY_NAME */
    ilt[1] = 0;
    iat = (DWORD*)(buf + IAT_OFF);
    iat[0] = IBN_OFF;
    iat[1] = 0;

    /* IMAGE_IMPORT_BY_NAME */
    ibn = (IMAGE_IMPORT_BY_NAME*)(buf + IBN_OFF);
    ibn->Hint = 0;
    memcpy(ibn->Name, func_name, strlen(func_name) + 1);
}

/* ------------------------------------------------------------------ */
/* 端到端验证                                                          */
/* ------------------------------------------------------------------ */
static void test_synch_resolve_chain(void)
{
    unsigned char* buf;
    PeInfo pe;
    ApiSetMap m;
    ApiSetEntry entry;
    RewriteEngine e;
    int rc;
    const char* dll_name_after;
    const char* target_dll = "api-ms-win-core-synch-l1-2-0.dll";
    const char* target_func = "WaitOnAddress";

    printf("==== 端到端：api-ms-win-core-synch-l1-2-0.dll -> WaitOnAddress ====\n");

    /* 步骤 1：合成 PE 导入 api-ms-win-core-synch-l1-2-0.dll!WaitOnAddress */
    buf = (unsigned char*)malloc(IMG_SIZE);
    if (buf == NULL) {
        printf("[FAIL] malloc 失败\n");
        g_fail = 1;
        return;
    }
    build_pe_with_import(buf, IMG_SIZE, target_dll, target_func);
    printf("[step 1] 合成 PE 导入 %s!%s\n", target_dll, target_func);

    /* 步骤 2：pe_parse 解析 PE */
    rc = pe_parse(buf, IMG_SIZE, &pe);
    CHECK(rc == PE_OK, "pe_parse 成功");
    CHECK(pe.import_dir != NULL, "导入表已定位");

    /* 步骤 3：apiset_is_virtual_name 识别为虚拟名 */
    rc = apiset_is_virtual_name(target_dll);
    CHECK(rc == 1, "api-ms-win-core-synch-l1-2-0.dll 识别为虚拟名");

    /* 步骤 4：apiset_load_default 加载预置映射表 */
    rc = apiset_init(&m);
    CHECK(rc == APISET_OK, "apiset_init 成功");
    rc = apiset_load_default(&m);
    CHECK(rc == APISET_OK, "apiset_load_default 成功");
    CHECK(m.count > 0, "预置映射表非空");

    /* 步骤 5：apiset_lookup 解析 api-ms-win-core-synch-l1-2-0 */
    /*   （映射表中键已剥离 .dll 后缀）                                */
    rc = apiset_lookup(&m, "api-ms-win-core-synch-l1-2-0", &entry);
    CHECK(rc == 1, "apiset_lookup 命中 synch-l1-2-0");
    CHECK(entry.kind == APISET_TO_LOCAL,
          "synch-l1-2-0 kind == TO_LOCAL（转发到本地实现）");
    CHECK(entry.host_dll != NULL &&
          strcmp(entry.host_dll, "win7bridge_local") == 0,
          "host_dll == win7bridge_local");
    printf("[step 5] 映射表解析：synch-l1-2-0 -> TO_LOCAL win7bridge_local\n");

    /* 步骤 6：apiset_resolve_imports 遍历 PE 导入表，报告需要处理 */
    rc = apiset_resolve_imports(&m, &pe);
    CHECK(rc >= 1, "apiset_resolve_imports 报告需处理条目 >= 1");

    /* 步骤 7：用 engine_add_dll_redirect 配置转发规则 */
    /*   实际部署中转发到 win7bridge_local.dll；此处用同长度测试名 */
    engine_init(&e);
    rc = engine_add_dll_redirect(&e, target_dll, "win7bridge_local.dll");
    CHECK(rc == ENGINE_OK, "engine_add_dll_redirect 配置转发规则");

    /* 步骤 8：engine_rewrite_imports 改写导入 DLL 名 */
    rc = engine_rewrite_imports(&e, &pe);
    CHECK(rc >= 1, "engine_rewrite_imports 改写 >= 1 项");

    /* 步骤 9：验证导入表 DLL 名已改为 win7bridge_local.dll */
    dll_name_after = (const char*)(buf + IMP_NAME_OFF);
    CHECK(strcmp(dll_name_after, "win7bridge_local.dll") == 0,
          "导入 DLL 名已改写为 win7bridge_local.dll");
    printf("[step 9] 导入表已改写：%s -> %s\n", target_dll, dll_name_after);

    /* 步骤 10：sim_WaitOnAddress 本地实现可调用且语义正确            */
    /*   场景 A：*addr != *compare -> 立即返回 WAIT_OBJECT_0           */
    {
        volatile int addr_val = 1;
        int compare_val = 0;  /* 不相等 */
        int wait_rc = sim_WaitOnAddress((volatile void*)&addr_val,
                                        (void*)&compare_val,
                                        sizeof(int), 100);
        CHECK(wait_rc == WAIT_OBJECT_0,
              "sim_WaitOnAddress *addr!=*compare 立即返回 WAIT_OBJECT_0");
    }

    /*   场景 B：*addr == *compare, timeout=0 -> WAIT_TIMEOUT          */
    {
        volatile int addr_val = 42;
        int compare_val = 42;  /* 相等 */
        int wait_rc = sim_WaitOnAddress((volatile void*)&addr_val,
                                        (void*)&compare_val,
                                        sizeof(int), 0);
        CHECK(wait_rc == WAIT_TIMEOUT,
              "sim_WaitOnAddress *addr==*compare timeout=0 返回 WAIT_TIMEOUT");
    }

    /*   场景 C：WakeByAddressSingle 后 WaitOnAddress 唤醒返回         */
    {
        volatile int addr_val = 100;
        int compare_val = 100;  /* 初始相等，需等待唤醒 */
        int wake_rc;
        int wait_rc;
        /* 先设置唤醒标志 */
        wake_rc = sim_WakeByAddressSingle((void*)&addr_val);
        CHECK(wake_rc == 0, "sim_WakeByAddressSingle 返回 0");
        /* WaitOnAddress 应能命中唤醒标志并立即返回 WAIT_OBJECT_0 */
        wait_rc = sim_WaitOnAddress((volatile void*)&addr_val,
                                    (void*)&compare_val,
                                    sizeof(int), 100);
        CHECK(wait_rc == WAIT_OBJECT_0,
              "WakeByAddressSingle 后 WaitOnAddress 返回 WAIT_OBJECT_0");
    }

    /*   场景 D：非法 size -> ERROR_INVALID_PARAMETER                  */
    {
        volatile int addr_val = 1;
        int compare_val = 1;
        int wait_rc = sim_WaitOnAddress((volatile void*)&addr_val,
                                        (void*)&compare_val,
                                        3, 100);  /* size=3 非法 */
        CHECK(wait_rc == ERROR_INVALID_PARAMETER,
              "sim_WaitOnAddress size=3 返回 ERROR_INVALID_PARAMETER");
    }

    /*   场景 E：WakeByAddressAll 也工作                              */
    {
        volatile int addr_val = 200;
        int compare_val = 200;
        int wake_rc;
        int wait_rc;
        wake_rc = sim_WakeByAddressAll((void*)&addr_val);
        CHECK(wake_rc == 0, "sim_WakeByAddressAll 返回 0");
        wait_rc = sim_WaitOnAddress((volatile void*)&addr_val,
                                    (void*)&compare_val,
                                    sizeof(int), 100);
        CHECK(wait_rc == WAIT_OBJECT_0,
              "WakeByAddressAll 后 WaitOnAddress 返回 WAIT_OBJECT_0");
    }

    free(e.dll_rules);
    free(e.func_rules);
    free(m.entries);
    free(buf);
}

/* ------------------------------------------------------------------ */
/* 主入口                                                              */
/* ------------------------------------------------------------------ */
#ifdef WIN7BRIDGE_HOST_TEST
int main(void)
{
    printf("=== SubTask 2.3.4 验证：api-ms-win-core-synch-l1-2-0 解析到 WaitOnAddress 本地实现 ===\n\n");

    test_synch_resolve_chain();

    if (g_fail) {
        printf("\n[RESULT] test_synch_resolve: FAIL\n");
        return 1;
    }
    printf("\n[RESULT] test_synch_resolve: PASS\n");
    printf("\n验证结论：\n");
    printf("  - PE 导入 api-ms-win-core-synch-l1-2-0.dll!WaitOnAddress 后，\n");
    printf("    Win7Bridge L2 API Set 虚拟解析层将其识别为虚拟名并查表，\n");
    printf("    映射表条目 kind=TO_LOCAL, host_dll=win7bridge_local。\n");
    printf("  - L1 重写引擎据此把导入表 DLL 名改写为 win7bridge_local.dll，\n");
    printf("    使 Win7 加载器转而加载兼容层本地实现 DLL。\n");
    printf("  - 本地 sim_WaitOnAddress / sim_WakeByAddress{Single,All}\n");
    printf("    提供与 Win8+ 一致的语义（立即返回/超时/唤醒/参数校验）。\n");
    printf("  端到端解析链验证通过。\n");
    return 0;
}
#endif
