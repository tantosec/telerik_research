# IJW DLL Payloads

IJW (It Just Works) mixed-mode C++/CLI DLLs for use with the Telerik RadAsyncUpload
RCE exploit. The exploit plants the DLL in the server's temp upload directory via a
forged `_serializedConfiguration` token, then triggers `Assembly.LoadFrom` through
a forged `rau_ClientState` postback using the `System.Configuration.Install.AssemblyInstaller`
gadget. Because the DLL is simultaneously a valid .NET assembly and a native PE,
`Assembly.LoadFrom` accepts it and the Windows loader fires `DllMain` on load.

Two payload variants are provided for different target hardening levels.

## Variants

| Variant | Folder | Shell access | Persists across recycle | Requires webroot write |
|---|---|---|---|---|
| Write webshell | [`write-webshell/`](write-webshell/) | `POST /<shell>.aspx` (form field `c=<cmd>`) | Yes | Yes |
| In-memory injection | [`inmemory-webshell/`](inmemory-webshell/) | Any URL + `X-Shell-Cmd: <cmd>` header | No | No |

### write-webshell

Runs entirely in `DllMain` with no threads and no managed code. Reads the IIS
per-pool config file from the path in `w3wp.exe`'s command line, extracts
`physicalPath`, and writes `shell.aspx` to the web root. The shell persists on
disk until manually removed.

Use this on standard targets where the app pool account can write to the web root.
Pass the compiled DLL to the exploit with `-dll`.

The managed command-execution code it plants lives in the nested
[`write-webshell/aspx-stub/`](write-webshell/aspx-stub/README.md) component.

See [`write-webshell/README.md`](write-webshell/README.md) for full technical detail.

### inmemory-webshell

Spawns a native thread from `DllMain`, then uses .NET reflection to walk into
`HttpApplicationFactory._freeList` and inject a custom `IHttpModule` onto every
idle `HttpApplication` instance in the worker process pool. The injected module
intercepts all inbound requests, checks for the command header (default
`X-Shell-Cmd`, or an auto-generated `X-<random>`), and executes the command
value inline. No file is written to the web root.

Use this when the app pool account lacks write access to the web root. The shell
is lost when the app pool recycles.

See [`inmemory-webshell/README.md`](inmemory-webshell/README.md) for full technical detail.

## Building

Both variants are compiled from the `ijw-dll-payload` directory by the scripts
at this level. Run on any Windows x64 machine (server, desktop, or VM).

The scripts share `build-env.ps1`, which resolves the toolchain automatically:
it detects an MSVC C++/CLI toolset (a custom `C:\BuildTools` root or a standard
VS 2022 BuildTools/Community/Professional/Enterprise install), a Windows SDK
(standard `Windows Kits\10` layout or a NuGet-packaged layout), and the NETFXSDK
4.8 (`mscoree.lib`). Anything missing is installed: the compiler via the VS
Build Tools bootstrapper (or winget when present), and a missing Windows SDK via
its NuGet packages into a local `sdk\` dir. Installing the compiler needs an
elevated session; provisioning only the SDK does not.

**x64 (standard 64-bit app pool):**

```powershell
.\compile_x64.ps1
```

Produces:
- `write-webshell\payload_write.dll`
- `inmemory-webshell\payload_inmemory.dll`

**x86 (app pool with "Enable 32-Bit Applications" = True):**

```powershell
.\compile_x86.ps1
```

Produces:
- `write-webshell\payload_write_x86.dll`
- `inmemory-webshell\payload_inmemory_x86.dll`

Compiled DLLs are build outputs and are not committed to the repository.

## Choosing the right DLL

```
App pool has write access to web root?
  Yes → write-webshell/payload_write.dll        (simpler, persistent)
  No  → inmemory-webshell/payload_inmemory.dll  (no write needed, non-persistent)
```

App pool bitness: check IIS Manager → Application Pools → Advanced Settings →
"Enable 32-Bit Applications". True → use the `_x86.dll` variant.

## Diagnostic logs

Both variants log execution steps to `C:\Windows\Temp\`:

| File | Variant |
|---|---|
| `dlltest.txt` | [write-webshell](write-webshell/) |
| `dlltest_inmem.txt` | [inmemory-webshell](inmemory-webshell/) |

Check these after a trigger attempt if no shell is reachable.

## Assembly name patching

The CLR caches assemblies by manifest name and only fires `DllMain` once per
assembly per worker process lifetime. The exploit tool patches the .NET manifest
name in the DLL bytes before each upload so every upload appears as a new assembly
the process has not yet loaded. This applies to both variants.

## Disclaimer

The exploits and proof-of-concept code in this repository are published for
security research, defensive use, and authorised testing. All of the
vulnerabilities demonstrated here are already patched; we strongly recommend
updating Telerik UI for ASP.NET AJAX to the latest version.

## License

Released under the [MIT License](../../../LICENSE).
