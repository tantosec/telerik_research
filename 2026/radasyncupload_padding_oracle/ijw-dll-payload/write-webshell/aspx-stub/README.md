# aspx-stub

Managed .NET webshell stub used by the [`write-webshell`](../) payload.
This is a supporting component, not a standalone payload. It is never uploaded to the
target on its own; it is the command-execution code that ends up running inside the
ASPX that write-webshell plants on the web root.

## Role in the chain

`compile_x64.ps1` / `compile_x86.ps1` compile [`webshell.cs`](webshell.cs) to
`webshell.dll` (AnyCPU). The exploit tool takes that DLL via its `-shell-dll` flag,
XOR-encrypts it with the shell filename, and patches the encrypted bytes into the
`payload_write.dll` stub block (native `.tsblob` section, magic `TSWSHLL\0`) before
upload.

At request time the ASPX that write-webshell planted XOR-decrypts those bytes using
its own filename (`Path.GetFileName(Request.PhysicalPath)`) as the key, loads the
result with `Assembly.Load(byte[])`, and invokes the stub. Decoupling the stub from
the ASPX filename means the encrypted body only decrypts correctly when served under
the exact name the exploit chose.

## The stub

- Class `W`, method `R(HttpRequest, HttpResponse)` — the fixed entry point the ASPX
  template calls.
- POST only: the command is read from `Request.Form["c"]`; other methods are ignored.
- Spawns `cmd.exe /c <command>` with output redirected, and returns stdout followed
  by stderr as `text/plain`.

## Usage

Once the shell is planted, drive it with a POST carrying the command in form field `c`:

```
POST /<shell>.aspx    (form field: c=whoami)
POST /<shell>.aspx    (form field: c=ipconfig /all)
```

`<shell>` is `shell.aspx` by default, or the auto-generated `<random>.aspx` the
exploit patched in.

## Building

Built automatically by the `compile_x64.ps1` / `compile_x86.ps1` scripts in the
`ijw-dll-payload` directory as part of the write-webshell build. The output `webshell.dll` is a build artifact and
is not committed to the repository.

## Disclaimer

The exploits and proof-of-concept code in this repository are published for
security research, defensive use, and authorised testing. All of the
vulnerabilities demonstrated here are already patched; we strongly recommend
updating Telerik UI for ASP.NET AJAX to the latest version.

## License

Released under the [MIT License](../../../../../LICENSE).
