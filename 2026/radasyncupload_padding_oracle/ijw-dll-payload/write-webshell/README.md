# write-webshell

IJW mixed-mode C++/CLI DLL that writes a self-decrypting `.aspx` webshell to the
IIS web root and serves command execution through it. This is the primary payload
variant for standard targets where the IIS app pool account has write access to
the web root.

## How it works

The DLL is loaded into the IIS worker process (`w3wp.exe`) via the
`System.Configuration.Install.AssemblyInstaller` gadget, triggered by a forged
`rau_ClientState` postback. The Windows PE loader fires `DllMain(DLL_PROCESS_ATTACH)`
before the CLR runs any managed code, giving us synchronous native execution
inside the target process.

### Web root discovery

The payload discovers the web root at runtime with no hardcoded paths. It works
against any IIS installation regardless of where the application is deployed.

**Step 1 — Get the per-pool config path from the process command line.**

IIS starts every `w3wp.exe` with a `-h "path\to\config.config"` argument. The
path points to a temporary per-pool configuration file that IIS generates for
each app pool and grants the pool account read access to. `GetCommandLineW()`
reads the command line; the payload scans for ` -h "` and extracts everything
between the quotes.

**Step 2 — Read the per-pool config file.**

`CreateFileW` + `ReadFile` open the config file into a heap buffer. The file is
XML-formatted application configuration. It always contains a `physicalPath="..."`
attribute whose value is the physical path of the root virtual directory for this
app pool. On a single-site pool that is the web root.

**Step 3 — Extract physicalPath.**

A CRT-free byte scan (implemented without `strstr`) finds the `physicalPath="`
substring and copies the value up to the closing quote.

**Step 4 — Expand environment variables.**

The path may contain `%SystemDrive%` or similar variables. `ExpandEnvironmentStringsA`
resolves them before the path is used.

**Step 5 — Write the webshell.**

`CreateFileW` + `WriteFile` write the webshell to `<webroot>\<shellname>`. The
shell filename comes from the patched config block (default `shell.aspx`; the
exploit normally sets an auto-generated `<random>.aspx`). The content is built at
runtime by `buildAspx` from the encrypted stub block described below; no file is
read at runtime.

### The webshell

The shell written to disk is a self-decrypting ASPX. Its body carries the
XOR-encrypted bytes of the managed webshell stub
([`aspx-stub/webshell.cs`](aspx-stub/webshell.cs), compiled to `webshell.dll`)
as a C# byte-array literal, sandwiched between a fixed prefix and suffix
(`ASPX_PREFIX` / `ASPX_SUFFIX`). At request time the ASPX XOR-decrypts those bytes
using its own filename (`Path.GetFileName(Request.PhysicalPath)`) as the key, loads
the result with `Assembly.Load(byte[])`, and invokes class `W` method
`R(HttpRequest, HttpResponse)`.

The stub bytes are not compiled into `payload_write.dll`. The exploit tool takes
the compiled `webshell.dll` via its `-shell-dll` flag, XOR-encrypts it with the
shell filename, and patches it into the DLL's stub block (native `.tsblob`
section, magic `TSWSHLL\0`) before upload. `-shell-dll` is required in write mode.

The stub is POST-only: the command comes from `Request.Form["c"]` and the output
is returned as `text/plain`. Access it after planting:

```
POST /<shellname>.aspx    (form field: c=whoami)
POST /<shellname>.aspx    (form field: c=ipconfig /all)
```

`<shellname>` is `shell.aspx` by default, or the auto-generated `<random>.aspx`
the exploit patched in.

## DllMain constraints

`Assembly.LoadFrom` bypasses `_DllMainCRTStartup`, which means the Visual C++
CRT is never initialised when the DLL is loaded via the gadget chain. DllMain
also runs while the Windows loader lock is held. Both facts impose hard constraints
on what the payload may do:

**No CRT string functions.** `wcsstr`, `strlen`, `strstr`, and friends depend on
CRT state that does not exist. The payload replaces them with four small helpers
(`w_find`, `w_findch`, `a_find`, `a_findch`) that use only `lstrlenW`/`lstrlenA`,
which are kernel32 exports and safe without CRT initialisation.

**No directory enumeration.** `GetFileAttributesW`, `FindFirstFile`, and similar
calls can re-enter the CLR through an internal code path that faults with exception
code `0xe0434352` while the loader lock is held. The payload never enumerates;
it opens and writes files by exact path only (`CreateFileW`).

**No managed code in DllMain.** The `#pragma managed` section (the stub type
`ContentHelper`) is never called from DllMain. Everything in DllMain is
`#pragma unmanaged` and uses only kernel32 exports. The managed stub is present
solely to satisfy the CLR assembly manifest requirement: a `/clr` image must
contain at least one managed type.

## Why IJW (It Just Works)

The exploit chain uses `Type.GetType` to resolve a .NET assembly and
`Assembly.LoadFrom` to load it. The gadget expects a .NET assembly, so a
purely native DLL would not be accepted by the runtime. A purely managed
(.NET-only) DLL has no `DllMain` entry point; the CLR never fires one for a
managed assembly, so there is no synchronous execution at load time.

The IJW format is simultaneously a valid .NET assembly (with a manifest and
managed types visible to `Assembly.LoadFrom`) and a native PE (with a real
`DllMain` that the Windows loader fires on `DLL_PROCESS_ATTACH`). That combination
is what makes the exploit work: the runtime accepts it as a managed assembly, the
loader fires `DllMain`, and our code runs before the CLR ever calls a managed
method.

## Assembly name patching

The CLR caches assemblies by manifest name. If the same manifest name is loaded
twice into the same worker process, `Assembly.LoadFrom` returns the cached instance
and the loader does not fire `DllMain` a second time. The exploit tool patches the
.NET manifest name in the DLL bytes before each upload so every upload looks like
a new assembly the process has not seen before.

## Building

Run from the `ijw-dll-payload` parent directory:

```powershell
.\compile_x64.ps1   # 64-bit app pools (default)
.\compile_x86.ps1   # 32-bit app pools (Enable 32-Bit Applications = True)
```

Output: `write-webshell\payload_write.dll` (x64) or `write-webshell\payload_write_x86.dll`
(x86), plus the managed stub `write-webshell\aspx-stub\webshell.dll` (AnyCPU) that the exploit
patches into the payload via `-shell-dll`.

The scripts share `build-env.ps1`, which resolves the toolchain (MSVC C++/CLI, a
Windows SDK, and the .NET Framework 4.8 SDK) and installs any missing component
automatically, so they run on any Windows x64 machine (server, desktop, or VM).
The .NET Framework 4.x runtime provides `System.Web.dll` and `csc.exe`.

## Diagnostic log

When debug mode is enabled, each step writes a line to `C:\Windows\Temp\dlltest.txt`
(with debug off the payload performs no file I/O):

| Line | Meaning |
|---|---|
| `DllMain start` | DllMain fired; DLL was loaded by the gadget |
| `config read failed` | Could not open or read the per-pool config file |
| `physicalPath not found` | Config file did not contain `physicalPath="..."` |
| `<web root path>` | Resolved web root before writing the shell |
| `buildAspx: bad wshell magic` | Stub block magic `TSWSHLL\0` not present in the DLL |
| `buildAspx: wshell not loaded (run with -shell-dll)` | Stub block present but empty; the exploit ran without `-shell-dll` |
| `buildAspx: HeapAlloc failed` | Could not allocate the ASPX build buffer |
| `CreateFileW failed` | Could not create the shell file (likely a permissions failure) |
| `buildAspx failed` | ASPX assembly failed (see the preceding `buildAspx` line) |
| `shell written OK` | Shell is live at the resolved path |

## When to use this variant

Use `write-webshell` when the IIS app pool account has write access to the web
root, which is the default on a standard IIS installation. The shell persists on
disk across app pool recycles and IIS restarts until it is explicitly deleted.

For targets where the pool account cannot write to the web root, use the
`inmemory-webshell` variant instead.

## Disclaimer

The exploits and proof-of-concept code in this repository are published for
security research, defensive use, and authorised testing. All of the
vulnerabilities demonstrated here are already patched; we strongly recommend
updating Telerik UI for ASP.NET AJAX to the latest version.

## License

Released under the [MIT License](../../../../LICENSE).
