# Telerik Research

Proof-of-concept exploits and research artefacts from TantoSec's 2026 security
research into **Telerik UI for ASP.NET AJAX**.

Each vulnerability below was reported to Progress Software through coordinated
disclosure and is fixed across **Telerik UI for ASP.NET AJAX** releases
**2026.1.421**, **2026.2.708**, and **2026.3.812**.
See the official Progress Telerik critical security bulletins: the
[July 2026 multiple-vulnerabilities RCE chain bulletin](https://www.telerik.com/products/aspnet-ajax/documentation/knowledge-base/kb-security-critical-rce-chain-bulletin-july-2026)
and the [2026 Q3 RadImageEditor and RadEditor RCE chain bulletin](https://www.telerik.com/products/aspnet-ajax/documentation/knowledge-base/kb-security-radimageeditor-radeditor-rce-chain-bulletin-2026-q3).

## Disclaimer

The exploits and proof-of-concept code in this repository are published for
security research, defensive use, and authorised testing. All of the
vulnerabilities demonstrated here are already patched; we strongly recommend
updating Telerik UI for ASP.NET AJAX to the latest version.

## Vulnerabilities identified

Severity is the vendor-assigned CVSS 3.1 rating. Unless noted otherwise, fixes
ship in **2026.2.708**.

### RadAsyncUpload, padding-oracle-to-RCE chain

| CVE | Vulnerability | Severity | CWE |
|---|---|---|---|
| [CVE-2026-13181](https://nvd.nist.gov/vuln/detail/CVE-2026-13181) ([KB](https://www.telerik.com/products/aspnet-ajax/documentation/knowledge-base/kb-security-rau-asyncuploadtypename-deserialization-cve-2026-13181)) | Unguarded type resolution via `AsyncUploadTypeName` | High (8.1) | CWE-470 |
| [CVE-2026-13182](https://nvd.nist.gov/vuln/detail/CVE-2026-13182) ([KB](https://www.telerik.com/products/aspnet-ajax/documentation/knowledge-base/kb-security-rau-padding-oracle-cve-2026-13182)) | Client-state decrypt-versus-parse padding oracle | High (7.5) | CWE-209 |
| [CVE-2026-13183](https://nvd.nist.gov/vuln/detail/CVE-2026-13183) ([KB](https://www.telerik.com/products/aspnet-ajax/documentation/knowledge-base/kb-security-rau-timing-oracle-cve-2026-13183)) | Upload metadata timing oracle | High (7.5) | CWE-208 |
| [CVE-2026-13184](https://nvd.nist.gov/vuln/detail/CVE-2026-13184) ([KB](https://www.telerik.com/products/aspnet-ajax/documentation/knowledge-base/kb-security-rau-unauth-deserialization-chain-cve-2026-13184)) | Default HMAC key fallback | High (7.5) | CWE-321 |

### DialogHandler (RadEditor / RadFileExplorer)

| CVE | Vulnerability | Severity | CWE |
|---|---|---|---|
| [CVE-2026-13187](https://nvd.nist.gov/vuln/detail/CVE-2026-13187) ([KB](https://www.telerik.com/products/aspnet-ajax/documentation/knowledge-base/kb-security-dialoghandler-provider-type-tampering-cve-2026-13187)) | Dialog provider type tampering | High (8.1) | CWE-470 |
| [CVE-2026-13188](https://nvd.nist.gov/vuln/detail/CVE-2026-13188) ([KB](https://www.telerik.com/products/aspnet-ajax/documentation/knowledge-base/kb-security-dialoghandler-parameters-tampering-cve-2026-13188)) | Dialog parameters tampering | Medium (5.9) | CWE-345 |

### RadImageEditor (fixed in 2026.3.812)

| CVE | Vulnerability | Severity | CWE |
|---|---|---|---|
| [CVE-2026-18672](https://nvd.nist.gov/vuln/detail/CVE-2026-18672) ([KB](https://www.telerik.com/products/aspnet-ajax/documentation/knowledge-base/kb-security-rie-path-traversal-cve-2026-18672)) | Unauthenticated file read via `RadImageEditor` client-state cache poisoning | High (7.5) | CWE-22 |
| [CVE-2026-19219](https://nvd.nist.gov/vuln/detail/CVE-2026-19219) ([KB](https://www.telerik.com/products/aspnet-ajax/documentation/knowledge-base/kb-security-dialoghandler-uploadpaths-tampering-cve-2026-19219)) | DialogHandler `UploadPaths` tampering leading to RCE | High (8.1) | CWE-345 |

### RadFilter (collision, fixed in 2026.1.421)

CVE-2026-6023 was reported by another researcher before our submission to
Progress. We independently discovered the same vulnerability and include our
proof of concept for completeness.

| CVE | Vulnerability | Severity | CWE |
|---|---|---|---|
| [CVE-2026-6023](https://nvd.nist.gov/vuln/detail/CVE-2026-6023) | `RadFilter` JSON deserialisation RCE via `TypeNameHandling.Auto` | High (8.1) | CWE-502 |

### Other controls

| CVE | Vulnerability | Severity | CWE |
|---|---|---|---|
| [CVE-2026-13189](https://nvd.nist.gov/vuln/detail/CVE-2026-13189) ([KB](https://www.telerik.com/products/aspnet-ajax/documentation/knowledge-base/kb-security-spellchecker-dictionarylanguage-path-traversal-cve-2026-13189)) | RadSpell `DictionaryLanguage` path traversal | High (7.5) | CWE-36 |
| [CVE-2026-13192](https://nvd.nist.gov/vuln/detail/CVE-2026-13192) ([KB](https://www.telerik.com/products/aspnet-ajax/documentation/knowledge-base/kb-security-radeditor-pdf-export-ssrf-cve-2026-13192)) | RadEditor PDF export SSRF | Medium (6.5) | CWE-918 |
| [CVE-2026-14865](https://nvd.nist.gov/vuln/detail/CVE-2026-14865) ([KB](https://www.telerik.com/products/aspnet-ajax/documentation/knowledge-base/kb-security-rlb-xxe-injection-client-state-cve-2026-14865)) | RadLayoutBuilder client-state XXE (denial of service) | Medium (5.3) | CWE-776 |
| [CVE-2026-14932](https://nvd.nist.gov/vuln/detail/CVE-2026-14932) ([KB](https://www.telerik.com/products/aspnet-ajax/documentation/knowledge-base/kb-security-radchart-hardcoded-key-file-read-cve-2026-14932)) | RadChart file read and deletion via hardcoded key | Medium (6.5) | CWE-321, CWE-22 |

## Proof of concepts

| Directory | CVEs | Description |
|---|---|---|
| [`radasyncupload_padding_oracle/`](radasyncupload_padding_oracle/) | CVE-2026-13181/13182/13183/13184 | Turns an unauthenticated AES-CBC padding oracle in `RadAsyncUpload` into remote code execution, chaining the decrypt-versus-parse oracle, a predictable default HMAC key, and a type-name deserialisation gadget. See the [tool README](radasyncupload_padding_oracle/telerik-rau-exploit/README.md) for usage. |
| [`imageeditor_arbitrary_file_read/`](imageeditor_arbitrary_file_read/) | CVE-2026-18672, CVE-2026-19219 | Unauthenticated arbitrary file read via RadImageEditor download-cache poisoning, with two RCE escalation paths: forged ViewState (machineKey) and forged dialog UploadPaths (DialogParametersEncryptionKey). See the [README](imageeditor_arbitrary_file_read/README.md) for usage. |
| [`radfilter_json_deser/`](radfilter_json_deser/) | CVE-2026-6023 | Unauthenticated RCE via `TypeNameHandling.Auto` in `RadFilter.LoadSettings()`. Injects an `ObjectDataProvider` gadget through the `CookieStateStorageProvider` persistence cookie. See the [README](radfilter_json_deser/README.md) for usage. |
| [`radlayoutbuilder_xxe/`](radlayoutbuilder_xxe/) | CVE-2026-14865 | XXE file read via RadLayoutBuilder `_ClientState`. External entity resolution through `XmlDocument.LoadXml()` with no `XmlResolver` restriction, bypassing request validation via `ContentEncoder` percent-encoding. See the [README](radlayoutbuilder_xxe/README.md) for usage. |
| [`spellcheck_path_traversal/`](spellcheck_path_traversal/) | CVE-2026-13189 | Unauthenticated NTLMv2 hash capture via `SpellCheckHandler` UNC path injection. `Path.Combine` returns attacker-controlled UNC paths when `DictionaryLanguage` is absolute, triggering an outbound SMB connection. See the [README](spellcheck_path_traversal/README.md) for usage. |
| [`radeditor_pdf_ssrf/`](radeditor_pdf_ssrf/) | CVE-2026-13192 | Blind SSRF via RadEditor PDF export. The server-side PDF renderer fetches attacker-controlled image URLs with no private-IP validation. Pre-patch versions also leak NTLMv2 hashes via `DefaultCredentials`. See the [README](radeditor_pdf_ssrf/README.md) for usage. |
| [`radchart_image_file_read_and_delete/`](radchart_image_file_read_and_delete/) | CVE-2026-14932 | Unauthenticated file read and deletion via `ChartImage.axd`. A hardcoded AES key in `Telerik.Charting.dll` allows forging encrypted file paths, and directory traversal bypasses the handler's non-canonicalised path check. See the [README](radchart_image_file_read_and_delete/README.md) for usage. |

## Remediation

Update to **Telerik UI for ASP.NET AJAX 2026.3.812** or later, and follow the
security guidance published by Progress Telerik.

## License

Released under the [MIT License](../LICENSE).
