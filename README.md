# Telerik Research

Security research into **Telerik UI for ASP.NET AJAX** by [TantoSec](https://tantosec.com).

This repository collects proof-of-concept exploits, write-ups, and other research
artefacts produced by our work on Telerik UI for ASP.NET AJAX, separated by year
of focus.

## Contents

| Year | Focus |
|---|---|
| [`2026/`](2026/) | RadAsyncUpload padding-oracle-to-RCE chain, DialogHandler type/parameter tampering, RadSpell path traversal, RadEditor PDF export SSRF, RadLayoutBuilder XXE, and RadChart file read/delete. All disclosed to Progress Software and fixed in 2026.2.708. |

See each year's `README.md` for the full list of vulnerabilities, CVE
identifiers, and proof-of-concept usage.

## Disclaimer

The exploits and proof-of-concept code in this repository are published for
security research, defensive use, and authorised testing. All of the
vulnerabilities demonstrated here are already patched; we strongly recommend
updating Telerik UI for ASP.NET AJAX to the latest version.

## License

Released under the [MIT License](LICENSE).
