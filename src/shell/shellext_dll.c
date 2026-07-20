/*
 * shellext_dll.c - Win7Bridge SubTask 3.4.2 Shell 扩展 Windows COM 主体
 *
 * 【开发文档】
 *
 * 目的：在 .exe / exefile 的"属性"对话框新增"Win7Bridge"页，让用户
 *   图形化地启用/关闭兼容层、选择注入路径、调整版本伪装参数。
 *
 * 分点展开：
 *   1. 平台隔离
 *      Windows COM 实现 IShellExtInit + IShellPropSheetExt；host 走桩，
 *      DllGetClassObject/DllRegisterServer 等返回 E_FAIL/SELFREG_E_TYPE。
 *
 *   2. 注册位置
 *      HKCR\exefile\shellex\PropertySheetHandlers\Win7Bridge = {CLSID}
 *      HKCR\*\shellex\PropertySheetHandlers\Win7Bridge      = {CLSID}
 *      HKCR\CLSID\{CLSID}\InProcServer32 = <dll path>, ThreadingModel=Apartment
 *
 *   3. UI 布局（DialogProc）
 *      - 复选框：启用 Win7Bridge
 *      - 复选框：版本伪装（含三个 EDIT 框 major/minor/build）
 *      - 复选框：子系统版本修正
 *      - 复选框：剥离 bound import
 *      - 组合框：注入路径（loader / pe_patch / appinit）
 *      - 静态文本：摘要（用 w7b_shellext_summary_text 渲染）
 *      - 静态文本：appinit 路径风险警告
 *
 *   4. 数据流
 *      Initialize：从 IDataObject 取第一个 EXE 路径，加载/默认 cfg
 *      AddPages：创建 propertysheet page，把 cfg 拷贝传过去
 *      WM_INITDIALOG：把 cfg 同步到 UI 控件
 *      WM_COMMAND：UI 改动 -> 更新内存 cfg -> 重渲摘要
 *      WM_NOTIFY (PSN_APPLY)：保存 cfg 到 per-user 配置目录
 *
 *   5. CLSID
 *      固定生成：{8F2C5D31-7B9A-4E1C-9D3F-2A6B8E1C5D31}
 *      （手工生成，非真实分配；真机阶段发布时再正式申请）
 *
 *   6. 错误处理
 *      Initialize 失败 -> AddPages 不调用；DialogProc 中保存失败 -> 弹
 *      MessageBox 警告但不阻塞属性页关闭。
 *
 *   7. host/syntax-check 桩
 *      全部导出函数返回错误码；不依赖 <windows.h>，让 make test 链接
 *      通过且 make check 的 syntax-check 不被 #include 卡住。
 */

#include "win7bridge/shellext.h"
#include "win7bridge/w7b_config.h"

#include <stdio.h>
#include <string.h>

/* ================================================================== */
/* Windows 真实实现                                                     */
/* ================================================================== */
#if defined(_WIN32) && !defined(WIN7BRIDGE_HOST_TEST) && !defined(WIN7BRIDGE_SYNTAX_CHECK)

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shlobj.h>
#include <objbase.h>

/* Win7 SDK 缺少时显式给出 */
#ifndef SELFREG_E_TYPE
#define SELFREG_E_TYPE ((HRESULT)0x80040201L)
#endif

/* DLL 实例句柄；DllMain 中赋值，注册时用于取模块路径 */
HINSTANCE g_hinstThisDll = NULL;

/* Win7Bridge Shell 扩展 CLSID: {8F2C5D31-7B9A-4E1C-9D3F-2A6B8E1C5D31} */
static const CLSID CLSID_Win7BridgeShellExt = {
    0x8F2C5D31, 0x7B9A, 0x4E1C,
    { 0x9D, 0x3F, 0x2A, 0x6B, 0x8E, 0x1C, 0x5D, 0x31 }
};

#define W7B_SHELL_PROGID_EXEFILE  L"exefile"
#define W7B_SHELL_PROGID_ALL      L"*"
#define W7B_SHELL_HANDLER_NAME    L"Win7Bridge"

/* ------------------------------------------------------------------ */
/* 持有 per-EXE 配置的对象                                              */
/* ------------------------------------------------------------------ */
typedef struct {
    IShellExtInit       isi;
    IShellPropSheetExt  sps;
    LONG                ref;
    W7bProgramConfig    cfg;
    char                exe_path[W7B_CONFIG_EXE_PATH_MAX];
} Win7BridgeShellExt;

/* vtable 前置声明 */
static const IShellExtInitVtbl       g_isi_vtbl;
static const IShellPropSheetExtVtbl  g_sps_vtbl;

/* 构造 */
static Win7BridgeShellExt* _new_ext(void)
{
    Win7BridgeShellExt* self = (Win7BridgeShellExt*)
        CoTaskMemAlloc(sizeof(Win7BridgeShellExt));
    if (self == NULL) return NULL;
    memset(self, 0, sizeof(*self));
    self->isi.lpVtbl  = &g_isi_vtbl;
    self->sps.lpVtbl  = &g_sps_vtbl;
    self->ref         = 1;
    w7b_config_set_defaults(&self->cfg, NULL);
    return self;
}

/* ------------------------------------------------------------------ */
/* IUnknown：把两个接口的 AddRef/Release/QueryInterface 委托到这里       */
/* ------------------------------------------------------------------ */
static HRESULT _query_iface(Win7BridgeShellExt* self, REFIID riid, void** out)
{
    if (out == NULL) return E_POINTER;
    *out = NULL;
    if (IsEqualIID(riid, &IID_IUnknown) ||
        IsEqualIID(riid, &IID_IShellExtInit)) {
        *out = &self->isi;
    } else if (IsEqualIID(riid, &IID_IShellPropSheetExt)) {
        *out = &self->sps;
    } else {
        return E_NOINTERFACE;
    }
    InterlockedIncrement(&self->ref);
    return S_OK;
}

static ULONG _add_ref(Win7BridgeShellExt* self)
{
    return (ULONG)InterlockedIncrement(&self->ref);
}

static ULONG _release(Win7BridgeShellExt* self)
{
    LONG n = InterlockedDecrement(&self->ref);
    if (n == 0) {
        CoTaskMemFree(self);
    }
    return (ULONG)n;
}

/* ------------------------------------------------------------------ */
/* IShellExtInit                                                        */
/* ------------------------------------------------------------------ */
static HRESULT STDMETHODCALLTYPE isi_QueryInterface(
    IShellExtInit* p, REFIID riid, void** out)
{
    Win7BridgeShellExt* self = (Win7BridgeShellExt*)p;
    return _query_iface(self, riid, out);
}
static ULONG STDMETHODCALLTYPE isi_AddRef(IShellExtInit* p)
{
    return _add_ref((Win7BridgeShellExt*)p);
}
static ULONG STDMETHODCALLTYPE isi_Release(IShellExtInit* p)
{
    return _release((Win7BridgeShellExt*)p);
}

static HRESULT STDMETHODCALLTYPE isi_Initialize(
    IShellExtInit* p, LPCITEMIDLIST pidlFolder, LPDATAOBJECT pDataObj,
    HKEY hkeyProgID)
{
    Win7BridgeShellExt* self = (Win7BridgeShellExt*)p;
    FORMATETC fe = { CF_HDROP, NULL, DVASPECT_CONTENT, -1, TYMED_HGLOBAL };
    STGMEDIUM stg;
    HDROP hdrop;
    WCHAR wpath[MAX_PATH];
    char  apath[MAX_PATH];
    UINT  n, len;
    char  cfg_dir[512];
    char  cfg_path[640];

    (void)pidlFolder; (void)hkeyProgID;

    if (pDataObj == NULL) return E_INVALIDARG;
    if (FAILED(IDataObject_GetData(pDataObj, &fe, &stg)) ||
        stg.hGlobal == NULL) {
        return E_INVALIDARG;
    }
    hdrop = (HDROP)stg.hGlobal;
    n = DragQueryFileW(hdrop, 0xFFFFFFFF, NULL, 0);
    if (n == 0) { ReleaseStgMedium(&stg); return E_INVALIDARG; }
    len = DragQueryFileW(hdrop, 0, wpath, MAX_PATH);
    ReleaseStgMedium(&stg);
    if (len == 0 || len >= MAX_PATH) return E_INVALIDARG;

    /* 仅处理 .exe */
    if (len < 4 || _wcsicmp(wpath + len - 4, L".exe") != 0) {
        return S_FALSE;
    }

    WideCharToMultiByte(CP_ACP, 0, wpath, -1, apath, sizeof(apath), NULL, NULL);
    strncpy(self->exe_path, apath, sizeof(self->exe_path) - 1);
    self->exe_path[sizeof(self->exe_path) - 1] = 0;

    /* 加载已有配置（无则用默认） */
    w7b_config_set_defaults(&self->cfg, apath);
    if (w7b_config_default_dir(cfg_dir, sizeof(cfg_dir)) == 0 &&
        w7b_config_path_for(apath, cfg_dir, cfg_path, sizeof(cfg_path)) == 0) {
        w7b_config_load(cfg_path, &self->cfg);
    }
    return S_OK;
}

static const IShellExtInitVtbl g_isi_vtbl = {
    isi_QueryInterface, isi_AddRef, isi_Release, isi_Initialize
};

/* ------------------------------------------------------------------ */
/* DialogProc：UI 主体                                                   */
/* ------------------------------------------------------------------ */
#define IDC_CHK_ENABLE       1001
#define IDC_CMB_INJECT       1002
#define IDC_CHK_SPOOF        1003
#define IDC_EDIT_MAJOR       1004
#define IDC_EDIT_MINOR       1005
#define IDC_EDIT_BUILD       1006
#define IDC_CHK_SUBSYS       1007
#define IDC_CHK_STRIP_BOUND  1008
#define IDC_STATIC_SUMMARY   1009
#define IDC_STATIC_WARN      1010

static void _sync_cfg_to_ui(HWND hDlg, const W7bProgramConfig* cfg)
{
    char buf[16];
    int  idx = w7b_shellext_injection_path_to_index(cfg->injection_path);
    char summary[256];

    CheckDlgButton(hDlg, IDC_CHK_ENABLE,
        cfg->enabled ? BST_CHECKED : BST_UNCHECKED);
    CheckDlgButton(hDlg, IDC_CHK_SPOOF,
        cfg->version_spoof_enabled ? BST_CHECKED : BST_UNCHECKED);
    CheckDlgButton(hDlg, IDC_CHK_SUBSYS,
        cfg->fix_subsystem_version ? BST_CHECKED : BST_UNCHECKED);
    CheckDlgButton(hDlg, IDC_CHK_STRIP_BOUND,
        cfg->strip_bound_imports ? BST_CHECKED : BST_UNCHECKED);

    SendMessageA(GetDlgItem(hDlg, IDC_CMB_INJECT), CB_SETCURSEL, (WPARAM)idx, 0);

    _snprintf(buf, sizeof(buf), "%d", cfg->spoof_major);
    SetDlgItemTextA(hDlg, IDC_EDIT_MAJOR, buf);
    _snprintf(buf, sizeof(buf), "%d", cfg->spoof_minor);
    SetDlgItemTextA(hDlg, IDC_EDIT_MINOR, buf);
    _snprintf(buf, sizeof(buf), "%d", cfg->spoof_build);
    SetDlgItemTextA(hDlg, IDC_EDIT_BUILD, buf);

    if (w7b_shellext_summary_text(cfg, summary, sizeof(summary)) > 0) {
        SetDlgItemTextA(hDlg, IDC_STATIC_SUMMARY, summary);
    }
}

static void _sync_ui_to_cfg(HWND hDlg, W7bProgramConfig* cfg)
{
    char buf[16];
    int  idx;
    const char* path_str;

    cfg->enabled = (IsDlgButtonChecked(hDlg, IDC_CHK_ENABLE) == BST_CHECKED);
    cfg->version_spoof_enabled =
        (IsDlgButtonChecked(hDlg, IDC_CHK_SPOOF) == BST_CHECKED);
    cfg->fix_subsystem_version =
        (IsDlgButtonChecked(hDlg, IDC_CHK_SUBSYS) == BST_CHECKED);
    cfg->strip_bound_imports =
        (IsDlgButtonChecked(hDlg, IDC_CHK_STRIP_BOUND) == BST_CHECKED);

    idx = (int)SendMessageA(GetDlgItem(hDlg, IDC_CMB_INJECT), CB_GETCURSEL, 0, 0);
    path_str = w7b_shellext_injection_path_from_index(idx);
    if (path_str) {
        strncpy(cfg->injection_path, path_str,
                sizeof(cfg->injection_path) - 1);
        cfg->injection_path[sizeof(cfg->injection_path) - 1] = 0;
    }

    if (GetDlgItemTextA(hDlg, IDC_EDIT_MAJOR, buf, sizeof(buf)) > 0)
        cfg->spoof_major = atoi(buf);
    if (GetDlgItemTextA(hDlg, IDC_EDIT_MINOR, buf, sizeof(buf)) > 0)
        cfg->spoof_minor = atoi(buf);
    if (GetDlgItemTextA(hDlg, IDC_EDIT_BUILD, buf, sizeof(buf)) > 0)
        cfg->spoof_build = atoi(buf);
}

static void _refresh_summary(HWND hDlg, W7bProgramConfig* cfg)
{
    char summary[256];
    if (w7b_shellext_summary_text(cfg, summary, sizeof(summary)) > 0) {
        SetDlgItemTextA(hDlg, IDC_STATIC_SUMMARY, summary);
    }
}

static INT_PTR CALLBACK _dlg_proc(HWND hDlg, UINT msg, WPARAM wp, LPARAM lp)
{
    W7bProgramConfig* cfg;
    PROPSHEETPAGEW*   psp;

    switch (msg) {
    case WM_INITDIALOG: {
        /* lp 指向 PROPSHEETPAGE；lParam 携带 cfg 指针（由 AddPages 设置） */
        psp = (PROPSHEETPAGEW*)lp;
        cfg = (W7bProgramConfig*)psp->lParam;
        SetWindowLongPtrW(hDlg, GWLP_USERDATA, (LONG_PTR)cfg);
        /* 填充组合框 */
        SendDlgItemMessageA(hDlg, IDC_CMB_INJECT, CB_ADDSTRING, 0, (LPARAM)"loader");
        SendDlgItemMessageA(hDlg, IDC_CMB_INJECT, CB_ADDSTRING, 0, (LPARAM)"pe_patch");
        SendDlgItemMessageA(hDlg, IDC_CMB_INJECT, CB_ADDSTRING, 0, (LPARAM)"appinit");
        SetDlgItemTextA(hDlg, IDC_STATIC_WARN,
            "注意：appinit 路径会触发反调试检测/与沙箱冲突");
        _sync_cfg_to_ui(hDlg, cfg);
        return TRUE;
    }
    case WM_COMMAND:
        cfg = (W7bProgramConfig*)GetWindowLongPtrW(hDlg, GWLP_USERDATA);
        if (cfg == NULL) break;
        if (LOWORD(wp) == IDC_CHK_ENABLE) {
            int en = (IsDlgButtonChecked(hDlg, IDC_CHK_ENABLE) == BST_CHECKED);
            w7b_shellext_apply_toggle(cfg, en);
            _sync_cfg_to_ui(hDlg, cfg);
        } else {
            _sync_ui_to_cfg(hDlg, cfg);
            _refresh_summary(hDlg, cfg);
        }
        return TRUE;
    case WM_NOTIFY: {
        NMHDR* nmh = (NMHDR*)lp;
        cfg = (W7bProgramConfig*)GetWindowLongPtrW(hDlg, GWLP_USERDATA);
        if (cfg == NULL) break;
        if (nmh->code == PSN_APPLY) {
            _sync_ui_to_cfg(hDlg, cfg);
            if (!w7b_shellext_is_config_valid(cfg)) {
                MessageBoxA(hDlg,
                    "配置无效：请检查版本伪装参数或注入路径",
                    "Win7Bridge", MB_OK | MB_ICONWARNING);
                SetWindowLongPtrW(hDlg, DWLP_MSGRESULT, PSNRET_INVALID);
                return TRUE;
            }
            /* 保存到 per-user 配置目录 */
            {
                char cfg_dir[512];
                char cfg_path[640];
                if (w7b_config_default_dir(cfg_dir, sizeof(cfg_dir)) == 0 &&
                    w7b_config_path_for(cfg->exe_path, cfg_dir,
                                         cfg_path, sizeof(cfg_path)) == 0) {
                    if (w7b_config_save(cfg_path, cfg) != 0) {
                        MessageBoxA(hDlg, "保存配置失败",
                            "Win7Bridge", MB_OK | MB_ICONERROR);
                    }
                }
            }
            SetWindowLongPtrW(hDlg, DWLP_MSGRESULT, PSNRET_NOERROR);
            return TRUE;
        }
        break;
    }
    }
    return FALSE;
}

/* ------------------------------------------------------------------ */
/* IShellPropSheetExt                                                   */
/* ------------------------------------------------------------------ */
static HRESULT STDMETHODCALLTYPE sps_QueryInterface(
    IShellPropSheetExt* p, REFIID riid, void** out)
{
    Win7BridgeShellExt* self = (Win7BridgeShellExt*)p;
    return _query_iface(self, riid, out);
}
static ULONG STDMETHODCALLTYPE sps_AddRef(IShellPropSheetExt* p)
{
    return _add_ref((Win7BridgeShellExt*)p);
}
static ULONG STDMETHODCALLTYPE sps_Release(IShellPropSheetExt* p)
{
    return _release((Win7BridgeShellExt*)p);
}

static UINT CALLBACK _prop_sheet_callback(
    HWND hwnd, UINT msg, LPPROPSHEETPAGEW ppsp)
{
    (void)hwnd; (void)msg;
    if (msg == PSPCB_RELEASE) {
        /* AddPages 中 CoTaskMemAlloc 的副本在此释放 */
        W7bProgramConfig* cfg = (W7bProgramConfig*)ppsp->lParam;
        if (cfg) CoTaskMemFree(cfg);
    }
    return 1;
}

static HRESULT STDMETHODCALLTYPE sps_AddPages(
    IShellPropSheetExt* p, LPFNADDPROPSHEETPAGE lpfnAdd, LPARAM lParam)
{
    Win7BridgeShellExt* self = (Win7BridgeShellExt*)p;
    PROPSHEETPAGEW      psp;
    HPROPSHEETPAGE      hpage;
    W7bProgramConfig*   cfg_copy;

    if (lpfnAdd == NULL) return E_POINTER;

    /* 把 cfg 拷贝到堆上，让 DialogProc 在 page 生命周期内持有 */
    cfg_copy = (W7bProgramConfig*)
        CoTaskMemAlloc(sizeof(W7bProgramConfig));
    if (cfg_copy == NULL) return E_OUTOFMEMORY;
    memcpy(cfg_copy, &self->cfg, sizeof(*cfg_copy));

    memset(&psp, 0, sizeof(psp));
    psp.dwSize      = sizeof(psp);
    psp.dwFlags     = PSP_USETITLE | PSP_USECALLBACK;
    psp.hInstance   = GetModuleHandleW(NULL);
    /* IDD 自定义：在真机阶段由 .rc 资源提供；此处暂用系统通用对话框
     * 风格的占位 ID 100；3.2.2 真机验证时再补 .rc */
    psp.pszTemplate = MAKEINTRESOURCEW(100);
    psp.pszIcon     = NULL;
    psp.pszTitle    = L"Win7Bridge";
    psp.pfnDlgProc  = _dlg_proc;
    psp.pcRefParent = NULL;
    psp.pfnCallback = _prop_sheet_callback;
    psp.lParam      = (LPARAM)cfg_copy;

    hpage = CreatePropertySheetPageW(&psp);
    if (hpage == NULL) {
        CoTaskMemFree(cfg_copy);
        return E_OUTOFMEMORY;
    }
    if (!lpfnAdd(hpage, lParam)) {
        DestroyPropertySheetPage(hpage);
    }
    return S_OK;
}

static HRESULT STDMETHODCALLTYPE sps_ReplacePage(
    IShellPropSheetExt* p, UINT uPageID,
    LPFNADDPROPSHEETPAGE lpfnReplace, LPARAM lParam)
{
    (void)p; (void)uPageID; (void)lpfnReplace; (void)lParam;
    return E_NOTIMPL;
}

static const IShellPropSheetExtVtbl g_sps_vtbl = {
    sps_QueryInterface, sps_AddRef, sps_Release,
    sps_AddPages, sps_ReplacePage
};

/* ------------------------------------------------------------------ */
/* 类厂                                                                 */
/* ------------------------------------------------------------------ */
typedef struct {
    IClassFactory cf;
    LONG          ref;
} Win7BridgeClassFactory;

static HRESULT STDMETHODCALLTYPE cf_QueryInterface(
    IClassFactory* p, REFIID riid, void** out)
{
    if (out == NULL) return E_POINTER;
    *out = NULL;
    if (IsEqualIID(riid, &IID_IUnknown) ||
        IsEqualIID(riid, &IID_IClassFactory)) {
        *out = p;
        p->lpVtbl->AddRef(p);
        return S_OK;
    }
    return E_NOINTERFACE;
}
static ULONG STDMETHODCALLTYPE cf_AddRef(IClassFactory* p)
{
    Win7BridgeClassFactory* self = (Win7BridgeClassFactory*)p;
    return (ULONG)InterlockedIncrement(&self->ref);
}
static ULONG STDMETHODCALLTYPE cf_Release(IClassFactory* p)
{
    Win7BridgeClassFactory* self = (Win7BridgeClassFactory*)p;
    LONG n = InterlockedDecrement(&self->ref);
    if (n == 0) CoTaskMemFree(self);
    return (ULONG)n;
}
static HRESULT STDMETHODCALLTYPE cf_CreateInstance(
    IClassFactory* p, IUnknown* pOuter, REFIID riid, void** out)
{
    Win7BridgeShellExt* self;
    (void)p;
    if (out == NULL) return E_POINTER;
    *out = NULL;
    if (pOuter != NULL) return CLASS_E_NOAGGREGATION;
    self = _new_ext();
    if (self == NULL) return E_OUTOFMEMORY;
    {
        HRESULT hr = _query_iface(self, riid, out);
        /* _query_iface 已 AddRef，这里 Release 构造时的初始引用 */
        _release(self);
        return hr;
    }
}
static HRESULT STDMETHODCALLTYPE cf_LockServer(IClassFactory* p, BOOL bLock)
{
    (void)p; (void)bLock;
    return S_OK;
}
static const IClassFactoryVtbl g_cf_vtbl = {
    cf_QueryInterface, cf_AddRef, cf_Release,
    cf_CreateInstance, cf_LockServer
};

static Win7BridgeClassFactory* _new_factory(void)
{
    Win7BridgeClassFactory* f = (Win7BridgeClassFactory*)
        CoTaskMemAlloc(sizeof(Win7BridgeClassFactory));
    if (f == NULL) return NULL;
    f->cf.lpVtbl = &g_cf_vtbl;
    f->ref       = 1;
    return f;
}

/* ------------------------------------------------------------------ */
/* DLL 导出                                                             */
/* ------------------------------------------------------------------ */
STDAPI DllGetClassObject(REFCLSID rclsid, REFIID riid, void** out)
{
    static Win7BridgeClassFactory* g_factory = NULL;
    if (out == NULL) return E_POINTER;
    *out = NULL;
    if (!IsEqualCLSID(rclsid, &CLSID_Win7BridgeShellExt)) {
        return CLASS_E_CLASSNOTAVAILABLE;
    }
    if (g_factory == NULL) {
        g_factory = _new_factory();
        if (g_factory == NULL) return E_OUTOFMEMORY;
        InterlockedIncrement(&g_factory->ref);  /* 永不释放 */
    }
    return cf_QueryInterface((IClassFactory*)g_factory, riid, out);
}

STDAPI DllCanUnloadNow(void)
{
    return S_FALSE;  /* 简化：永不卸载 */
}

/* 把 CLSID 转宽字符 "{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}" */
static void _clsid_to_wstr(const CLSID* c, wchar_t* out, size_t cap)
{
    StringFromGUID2(*c, out, (int)cap);
}

/* 注册到 HKCR\<progid>\shellex\PropertySheetHandlers\<handler> */
static HRESULT _register_under(const wchar_t* progid)
{
    HKEY hRoot, hSub;
    wchar_t path[256];
    wchar_t clsid_str[64];

    _clsid_to_wstr(&CLSID_Win7BridgeShellExt, clsid_str, 64);
    _snwprintf(path, 256, L"%s\\shellex\\PropertySheetHandlers\\%s",
               progid, W7B_SHELL_HANDLER_NAME);
    if (RegCreateKeyExW(HKEY_CLASSES_ROOT, path, 0, NULL, 0,
                        KEY_WRITE, NULL, &hRoot, NULL) != ERROR_SUCCESS) {
        return SELFREG_E_TYPE;
    }
    if (RegSetValueExW(hRoot, NULL, 0, REG_SZ,
                       (const BYTE*)clsid_str,
                       (DWORD)(wcslen(clsid_str) + 1) * sizeof(wchar_t))
            != ERROR_SUCCESS) {
        RegCloseKey(hRoot);
        return SELFREG_E_TYPE;
    }
    RegCloseKey(hRoot);

    /* CLSID\{...}\InProcServer32 = dll path, ThreadingModel=Apartment */
    _snwprintf(path, 256, L"CLSID\\%s", clsid_str);
    if (RegCreateKeyExW(HKEY_CLASSES_ROOT, path, 0, NULL, 0,
                        KEY_WRITE, NULL, &hRoot, NULL) != ERROR_SUCCESS) {
        return SELFREG_E_TYPE;
    }
    {
        wchar_t dll_path[MAX_PATH];
        GetModuleFileNameW(g_hinstThisDll, dll_path, MAX_PATH);
        RegSetValueExW(hRoot, NULL, 0, REG_SZ,
                       (const BYTE*)dll_path,
                       (DWORD)(wcslen(dll_path) + 1) * sizeof(wchar_t));
    }
    if (RegCreateKeyExW(hRoot, L"InProcServer32", 0, NULL, 0,
                        KEY_WRITE, NULL, &hSub, NULL) != ERROR_SUCCESS) {
        RegCloseKey(hRoot);
        return SELFREG_E_TYPE;
    }
    RegSetValueExW(hSub, L"ThreadingModel", 0, REG_SZ,
                   (const BYTE*)L"Apartment", sizeof(L"Apartment"));
    RegCloseKey(hSub);
    RegCloseKey(hRoot);
    return S_OK;
}

static HRESULT _unregister_under(const wchar_t* progid)
{
    wchar_t path[256];
    wchar_t clsid_str[64];
    _clsid_to_wstr(&CLSID_Win7BridgeShellExt, clsid_str, 64);
    _snwprintf(path, 256, L"%s\\shellex\\PropertySheetHandlers\\%s",
               progid, W7B_SHELL_HANDLER_NAME);
    SHDeleteKeyW(HKEY_CLASSES_ROOT, path);
    _snwprintf(path, 256, L"CLSID\\%s", clsid_str);
    SHDeleteKeyW(HKEY_CLASSES_ROOT, path);
    return S_OK;
}

STDAPI DllRegisterServer(void)
{
    HRESULT hr;
    hr = _register_under(W7B_SHELL_PROGID_EXEFILE);
    if (FAILED(hr)) return hr;
    hr = _register_under(W7B_SHELL_PROGID_ALL);
    return hr;
}

STDAPI DllUnregisterServer(void)
{
    _unregister_under(W7B_SHELL_PROGID_EXEFILE);
    _unregister_under(W7B_SHELL_PROGID_ALL);
    return S_OK;
}

BOOL APIENTRY DllMain(HINSTANCE hinst, DWORD reason, LPVOID reserved)
{
    (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) {
        g_hinstThisDll = hinst;
        DisableThreadLibraryCalls(hinst);
    }
    return TRUE;
}

/* ================================================================== */
/* host / syntax-check 桩                                              */
/* ================================================================== */
#else  /* !(_WIN32 && !HOST_TEST && !SYNTAX_CHECK) */

/* host 模式不暴露 Dll* 导出；保留两个空函数让 build/test 链接通过 */
int w7b_shellext_dll_host_dummy(void)
{
    return 0;
}

#endif
