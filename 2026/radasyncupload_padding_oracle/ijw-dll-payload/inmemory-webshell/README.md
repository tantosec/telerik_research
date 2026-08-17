# inmemory-webshell

IJW mixed-mode C++/CLI DLL that injects a live HTTP handler into the ASP.NET
pipeline of the running IIS worker process. Command execution is served through
an in-memory `IHttpModule` with no files written to the web root.

Use this variant when the IIS app pool account cannot write to the web root.

## How it works

Like the `write-webshell` variant, this DLL enters the process via the
`AssemblyInstaller` gadget and the Windows loader fires `DllMain` on load. The
difference is what DllMain does: instead of writing a file, it spawns a native
thread that uses .NET reflection to hook the ASP.NET request pipeline.

### Why a thread instead of direct execution in DllMain

DllMain runs while the Windows loader lock is held. Calling managed code from
DllMain in an IJW DLL risks a deadlock: the CLR's own initialisation acquires
internal locks that can depend on the loader lock. Spawning a native thread via
`CreateThread` returns control to DllMain immediately; the thread runs after the
loader lock is released and the CLR is fully initialised, so managed code is safe
to call.

### Why the thread sleeps before injecting

The DLL is loaded during an active HTTP postback (the exploit's Phase 9 trigger).
While that postback is in flight, `HttpApplicationFactory` has dispatched the
worker's `HttpApplication` instance to handle it. The factory's `_freeList` is
empty because the only idle instance is busy serving the postback.

The injection thread sleeps 500 ms to let the postback complete. When it does,
the `HttpApplication` instance returns to `_freeList`, and the injection loop
finds it there. If 500 ms is not enough (slow server, heavy load), the retry
loop in `DoInject` polls up to 15 more times at 300 ms intervals.

### Injecting the handler

`DoInject` installs `ContentModule` (an `IHttpModule`) two ways, covering both
future and existing `HttpApplication` instances.

**Future instances - `HttpApplication.RegisterModule`.** If the runtime exposes
the public static `HttpApplication.RegisterModule`, the payload registers
`ContentModule` through it. Every `HttpApplication` the factory builds afterwards
initialises with the module attached. When this succeeds it is enough on its own.

**Existing instances - free-list reflection plus step patching.** As a fallback,
and to reach instances that already exist, the payload reflects into the factory
pool and wires the handler onto each idle instance:

```
typeof(System.Web.HttpRuntime)
  ._theApplicationFactory              [private static - HttpApplicationFactory singleton]
    ._freeList / ._specialFreeList     [private - idle HttpApplication instances]
      [each entry]                     [HttpApplication instance]
        ContentModule.Init(app)          [subscribes to events]
        PatchExistingSteps(app, handler) [splices handler into pipeline steps]
```

`_theApplicationFactory`, `_freeList`, and `_specialFreeList` are private fields
read with `BindingFlags.NonPublic`. Their names have been stable across .NET
Framework 4.x and are not part of any public API.

### Why the steps must be patched

Calling `ContentModule.Init(app)` on its own is not enough on the IIS 7+
integrated pipeline. Each module's `SyncEventExecutionStep` captures its
event-handler delegate at `AddEventMapping` time, during the application's
`InitInternal`. Subscribing after init updates the application's `_events` table
but not the delegate already captured inside those steps, so a late subscriber
never runs.

`PatchExistingSteps` walks every `SyncEventExecutionStep` in the application's
`_moduleContainers`, finds the captured handler delegate field, and
`Delegate.Combine`s `ContentModule.OnShellEvent` onto it. An `s_handled` guard on
the request context stops the handler running more than once when it is spliced
into several steps for the same request.

### The handler

`ContentModule.OnShellEvent` runs at the start of every request served by a
patched instance. It checks the command header (default `X-Shell-Cmd`; the
exploit usually patches in `X-<random>`). If the header is absent or empty the
request proceeds untouched. If present, `cmd.exe` is spawned with the header value
as the command:

```
GET /any/path HTTP/1.1
Host: target.example.com
X-Shell-Cmd: whoami
```

`stdout` and `stderr` are both captured and written as `text/plain`.
`CompleteRequest()` then bypasses the remaining pipeline stages (no handler, no
page, no view engine). This is cleaner than `Response.End()`, which throws
`ThreadAbortException`.

### Coverage — which instances get the module

When `RegisterModule` is available, future instances are covered automatically.
The free-list patch covers the instances that already exist in `_freeList` and
`_specialFreeList` when the thread runs. On a standard single-worker, low-traffic
IIS installation the two together reach the whole pool. On a scaled-out web garden
(multiple `w3wp` processes per site), only the process that loaded the DLL is
affected.

If `RegisterModule` is unavailable and the pool scales up after injection, the
instances created later are not patched. For a typical engagement session this is
acceptable: the pool is sized at startup (default ten per CPU core) and all
instances exist from warm-up. The retry loop handles temporarily empty pools
during transient spikes.

### Lifetime

The injected module lives in the managed heap of `w3wp.exe`. It is lost when:

- The app pool recycles (IIS nightly recycle, memory limit, explicit `/recycle`)
- `w3wp.exe` crashes or is killed
- The server is rebooted

Nothing persists on disk. The uploaded DLL lands in the Telerik temp upload
directory and is cleaned up by the application in the normal course of operation.

## DllMain constraints

The same constraints as `write-webshell` apply:

**No CRT.** `Assembly.LoadFrom` bypasses `_DllMainCRTStartup`. The native portion
of the payload (`DiagNative`) uses only kernel32 exports.

**No managed calls from DllMain.** The managed injection logic runs on the
spawned thread, not in DllMain. The `DoInject` forward declaration with
`#pragma managed` tells the compiler to generate an IJW thunk so the native
`ShellThreadProc` can call into managed code safely once the loader lock is gone.

**No directory enumeration.** Not needed by this variant — no files are opened
or written except the diagnostic log.

## Building

Run from the `ijw-dll-payload` parent directory:

```powershell
.\compile_x64.ps1   # 64-bit app pools (default)
.\compile_x86.ps1   # 32-bit app pools (Enable 32-Bit Applications = True)
```

Output: `inmemory-webshell\payload_inmemory.dll` and
`inmemory-webshell\payload_inmemory_x86.dll`.

The scripts share `build-env.ps1`, which resolves the toolchain (MSVC C++/CLI, a
Windows SDK, and the .NET Framework 4.8 SDK) and installs any missing component
automatically, so they run on any Windows x64 machine (server, desktop, or VM).
The .NET Framework 4.x runtime provides `System.Web.dll` and `csc.exe`.

The compile scripts pass `/AI "$dotnetFx"` to `cl.exe`, which adds the .NET
Framework runtime directory to the `#using` search path. `payload_inmemory.c`
uses `#using <System.Web.dll>` to import the ASP.NET types; `System.Web.dll`
lives in that runtime directory.

## Diagnostic log

Each step writes a line to `C:\Windows\Temp\dlltest_inmem.txt`:

| Line | Meaning |
|---|---|
| `DllMain: creating injection thread` | DllMain fired; thread spawned |
| `injection thread: calling DoInject` | Thread woke after the initial sleep |
| `attempt N/15: pool still empty, retrying in 300ms` | Free list empty; will retry |
| `reflection: _theApplicationFactory field not found` | Unexpected .NET version |
| `reflection: _freeList field not found` | Unexpected .NET version |
| `reflection: _freeList is empty` | Pool empty at this attempt |
| `injected into N app instance(s) OK` | Success; N instances now carry the module |
| `injection failed: _freeList remained empty after all attempts` | Pool never freed an instance |

## Shell usage

After successful injection, any URL on the target serves as the trigger. Pass the
command in the configured command header (default `X-Shell-Cmd`, or the
auto-generated `X-<random>` the exploit patched in):

```
GET /AsyncUpload/Examples/ImageUploader/DefaultCS.aspx HTTP/1.1
Host: telerik.tanto.lab:8088
X-Shell-Cmd: whoami
```

```
GET /AsyncUpload/Examples/ImageUploader/DefaultCS.aspx HTTP/1.1
Host: telerik.tanto.lab:8088
X-Shell-Cmd: ipconfig /all
```

The response body is `text/plain` containing stdout and stderr combined.

## When to use this variant

Use `inmemory-webshell` when the IIS app pool account cannot write to the web
root. In that case `write-webshell` fails at the `CreateFileW` step and logs
`CreateFileW failed`.

The trade-off is persistence: the disk variant survives app pool recycles and
reboots; this variant does not. For a short exploitation window during a
pentest or research session the in-memory approach is sufficient, and it leaves
a smaller forensic footprint.

## Disclaimer

The exploits and proof-of-concept code in this repository are published for
security research, defensive use, and authorised testing. All of the
vulnerabilities demonstrated here are already patched; we strongly recommend
updating Telerik UI for ASP.NET AJAX to the latest version.

## License

Released under the [MIT License](../../../../LICENSE).
