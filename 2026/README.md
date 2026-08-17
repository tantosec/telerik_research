# Telerik Research

Proof-of-concept exploits and research artefacts from TantoSec's 2026 security
research into **Telerik UI for ASP.NET AJAX**.

Each vulnerability below was reported to Progress Software through coordinated
disclosure and is fixed in **Telerik UI for ASP.NET AJAX 2026.2.708** and later.
See the official [Progress Telerik critical security bulletin](https://www.telerik.com/products/aspnet-ajax/documentation/knowledge-base/kb-security-critical-rce-chain-bulletin-july-2026)
for the vendor advisory.

## Disclaimer

The exploits and proof-of-concept code in this repository are published for
security research, defensive use, and authorised testing. All of the
vulnerabilities demonstrated here are already patched; we strongly recommend
updating Telerik UI for ASP.NET AJAX to the latest version.

## Vulnerabilities identified

All of the following were discovered during this research and are fixed in
2026.2.708. Severity is the vendor-assigned CVSS 3.1 rating.

### RadAsyncUpload — padding-oracle-to-RCE chain

| CVE | Vulnerability | Severity | CWE |
|---|---|---|---|
| [CVE-2026-13181](https://nvd.nist.gov/vuln/detail/CVE-2026-13181) | Unguarded type resolution via `AsyncUploadTypeName` | High (8.1) | CWE-470 |
| [CVE-2026-13182](https://nvd.nist.gov/vuln/detail/CVE-2026-13182) | Client-state decrypt-versus-parse padding oracle | High (7.5) | CWE-209 |
| [CVE-2026-13183](https://nvd.nist.gov/vuln/detail/CVE-2026-13183) | Upload metadata timing oracle | High (7.5) | CWE-208 |
| [CVE-2026-13184](https://nvd.nist.gov/vuln/detail/CVE-2026-13184) | Default HMAC key fallback | High (7.5) | CWE-321 |

### DialogHandler (RadEditor / RadFileExplorer)

| CVE | Vulnerability | Severity | CWE |
|---|---|---|---|
| [CVE-2026-13187](https://nvd.nist.gov/vuln/detail/CVE-2026-13187) | Dialog provider type tampering | High (8.1) | CWE-470 |
| [CVE-2026-13188](https://nvd.nist.gov/vuln/detail/CVE-2026-13188) | Dialog parameters tampering | Medium (5.9) | CWE-345 |

### Other controls

| CVE | Vulnerability | Severity | CWE |
|---|---|---|---|
| [CVE-2026-13189](https://nvd.nist.gov/vuln/detail/CVE-2026-13189) | RadSpell `DictionaryLanguage` path traversal | High (7.5) | CWE-36 |
| [CVE-2026-13192](https://nvd.nist.gov/vuln/detail/CVE-2026-13192) | RadEditor PDF export SSRF | Medium (6.5) | CWE-918 |
| [CVE-2026-14865](https://nvd.nist.gov/vuln/detail/CVE-2026-14865) | RadLayoutBuilder client-state XXE (denial of service) | Medium (5.3) | CWE-776 |
| [CVE-2026-14932](https://nvd.nist.gov/vuln/detail/CVE-2026-14932) | RadChart file read and deletion via hardcoded key | Medium (6.5) | CWE-321, CWE-22 |

## Proof of concepts

| Directory | CVEs | Description |
|---|---|---|
| [`radasyncupload_padding_oracle/`](radasyncupload_padding_oracle/) | CVE-2026-13181/13182/13183/13184 | Turns an unauthenticated AES-CBC padding oracle in `RadAsyncUpload` into remote code execution, chaining the decrypt-versus-parse oracle, a predictable default HMAC key, and a type-name deserialisation gadget. See the [tool README](radasyncupload_padding_oracle/telerik-rau-exploit/README.md) for usage. |

Further proof-of-concept code for the remaining findings will be added here over
time.

## Remediation

Update to **Telerik UI for ASP.NET AJAX 2026.2.708** or later, and follow the
security guidance published by Progress Telerik.

## License

Released under the [MIT License](../LICENSE).
