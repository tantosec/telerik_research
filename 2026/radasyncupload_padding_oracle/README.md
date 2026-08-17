# RadAsyncUpload Padding Oracle to RCE

Proof-of-concept for the unauthenticated `RadAsyncUpload` padding-oracle-to-RCE
chain in Telerik UI for ASP.NET AJAX (CVE-2026-13181 / 13182 / 13183 / 13184),
fixed in 2026.2.708.

The chain turns an AES-CBC padding oracle in `Telerik.Web.UI.WebResource.axd?type=rau`
into remote code execution. It recovers or forges an `AsyncUploadConfiguration`
token, uploads an IJW mixed-mode DLL, and triggers execution through the
`AssemblyInstaller` deserialisation gadget on a forged `rau_ClientState` postback.

## Layout

| Path | Description |
|---|---|
| [`telerik-rau-exploit/`](telerik-rau-exploit/) | The Go exploit: padding oracle, token forging, upload, and trigger. See its [README](telerik-rau-exploit/README.md) for flags, phases, and prerequisites. |
| [`ijw-dll-payload/`](ijw-dll-payload/) | IJW mixed-mode C++/CLI DLL payloads loaded by the exploit. See its [README](ijw-dll-payload/README.md) for the payload variants and build steps. |
| [`docker-compose.yml`](docker-compose.yml) | Runs the exploit with the compiled DLL payloads mounted read-only. |

## Disclaimer

The exploits and proof-of-concept code in this repository are published for
security research, defensive use, and authorised testing. All of the
vulnerabilities demonstrated here are already patched; we strongly recommend
updating Telerik UI for ASP.NET AJAX to the latest version.

## License

Released under the [MIT License](../../LICENSE).
