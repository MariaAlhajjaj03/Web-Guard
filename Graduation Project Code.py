#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Web Guard - Comprehensive Security Scanner (Graduation Project Edition)
Authors: Maria Alhajjaj, Amer Farraj, Abdallah Alzoubi.
Supervisor: Dr. Ahmad AlHwaitat

⚠️ Use only on systems/apps you own or have explicit permission to test.

This tool supports:
- DAST (Safe Passive by default) + Optional Active tests (LOCAL/PRIVATE ONLY, GET params only)
- SAST (Static analysis for code folders)
- SCA  (Dependency hygiene checks for requirements.txt)

PDF Theme: Black / Red / White (Professional Pentest Style)
"""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import os
import re
import sys
import time
import ipaddress
from urllib.parse import urljoin, urlparse, urlsplit, urlunsplit, parse_qs, urlencode

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from bs4 import BeautifulSoup
from tqdm import tqdm

from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from reportlab.lib import colors
from reportlab.lib.utils import ImageReader

from colorama import Fore, Style, init
init(autoreset=True)

# ================= CONFIG =================

DEFAULT_USER_AGENT = "Mozilla/5.0"
MAX_CRAWL_DEPTH = 3
LOGO_FILE = "webguard_logo.png"  # optional

JUICE_SEEDS = [
    "/",
    "/#/search",
    "/#/login",
    "/#/basket",
    "/rest/products",
    "/rest/category",
    "/rest/language",
    "/api/Challenges",
    "/api/Feedbacks",
    "/api/Products",
]

SQL_ERROR_KEYWORDS = [
    "sql syntax", "syntax error", "sqlite", "mysql", "mariadb", "postgres",
    "odbc", "jdbc", "unterminated", "unclosed quotation", "near \"select\"",
    "warning: sqlite", "pg::", "psql:"
]

# ================= UI / BANNER =================

def print_banner():
    banner = f"""
{Fore.RED}{Style.BRIGHT}
██╗    ██╗███████╗██████╗      ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗
██║    ██║██╔════╝██╔══██╗    ██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗
██║ █╗ ██║█████╗  ██████╔╝    ██║  ███╗██║   ██║███████║██████╔╝██║  ██║
██║███╗██║██╔══╝  ██╔══██╗    ██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║
╚███╔███╔╝███████╗██████╔╝    ╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝
 ╚══╝╚══╝ ╚══════╝╚═════╝      ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝
{Style.RESET_ALL}
        Web Guard - Security Scanner
        Graduation Project Edition
        --------------------------------
        Safe-DAST (Passive) + Optional Active (LOCAL ONLY) + SAST + SCA
"""
    print(banner)

def interactive_menu():
    print("\n" + "=" * 72)
    print(" Web Guard - Interactive Menu ".center(72))
    print("=" * 72)
    print("1) DAST Scan  - Scan a web app by URL (recommended)")
    print("   • Crawling + passive checks + optional local active tests")
    print("\n2) SAST Scan  - Scan source code folder (static analysis)")
    print("   • Finds secrets, dangerous functions, weak crypto, debug exposure")
    print("\n3) SCA  Scan  - Scan dependencies (requirements.txt)")
    print("   • Finds unpinned packages and risky dependency sources (URLs/VCS)")
    print("\n0) Exit")
    print("=" * 72)

    choice = input("Select option: ").strip()
    if choice == "0":
        print("Bye 👋")
        sys.exit(0)

    if choice == "1":
        url = input("Target URL (e.g. http://localhost:3000): ").strip()
        if not url:
            print("[-] No URL provided.")
            return None

        print("\nScan type:")
        print("1) passive (safe)")
        print("2) sqli (active - LOCAL/private only)")
        print("3) xss  (active - LOCAL/private only)")
        print("4) all  (active - LOCAL/private only)")
        st = input("Choose [1-4] (default=1): ").strip() or "1"
        scan_map = {"1": "passive", "2": "sqli", "3": "xss", "4": "all"}
        scan = scan_map.get(st, "passive")

        active = False
        if scan != "passive":
            ans = input("Enable active tests? (LOCAL/private ONLY) [y/N]: ").strip().lower()
            active = (ans == "y")

        workers_in = input("Workers (default=8): ").strip()
        workers = 8
        if workers_in.isdigit():
            workers = max(1, min(32, int(workers_in)))

        return {"mode": "dast", "url": url, "workers": workers, "scan": scan, "active": active}

    if choice == "2":
        path = input("Source code folder path (e.g. ./project): ").strip()
        if not path:
            print("[-] No path provided.")
            return None
        return {"mode": "sast", "path": path}

    if choice == "3":
        req = input("requirements.txt path (e.g. ./requirements.txt): ").strip()
        if not req:
            print("[-] No requirements path provided.")
            return None
        return {"mode": "sca", "requirements": req}

    print("[-] Invalid choice.")
    return None

# ================= HELPERS =================

def setup_session():
    s = requests.Session()
    s.headers.update({"User-Agent": DEFAULT_USER_AGENT})
    retries = Retry(total=2, backoff_factor=0.3, status_forcelist=(500, 502))
    s.mount("http://", HTTPAdapter(max_retries=retries))
    s.mount("https://", HTTPAdapter(max_retries=retries))
    return s

def try_get(session, url, timeout=7):
    try:
        return session.get(url, timeout=timeout, allow_redirects=True)
    except Exception:
        return None

def get_origin(url: str) -> str:
    p = urlsplit(url)
    return f"{p.scheme}://{p.netloc}"

def same_origin(a: str, b: str) -> bool:
    return urlsplit(a).netloc == urlsplit(b).netloc

def is_juice_shop(session, base_url: str) -> bool:
    r = try_get(session, base_url)
    if not r:
        return False
    txt = (r.text or "").lower()
    return ("juice shop" in txt) or ("owasp juice shop" in txt)

def discover_endpoints_from_js(session, base_url: str, max_scripts=10, max_bytes=900_000) -> set[str]:
    endpoints = set()
    r = try_get(session, base_url)
    if not r:
        return endpoints

    soup = BeautifulSoup(r.text, "html.parser")
    scripts = []
    for s in soup.find_all("script", src=True):
        src = urljoin(base_url, s["src"])
        if same_origin(src, base_url):
            scripts.append(src)

    scripts = scripts[:max_scripts]
    ep_re = re.compile(r'/(rest|api)/[A-Za-z0-9_\-./?=&%]+')
    downloaded = 0

    for src in scripts:
        jsr = try_get(session, src, timeout=10)
        if not jsr or not jsr.text:
            continue
        downloaded += len(jsr.text.encode("utf-8", errors="ignore"))
        if downloaded > max_bytes:
            break

        for match in re.finditer(ep_re, jsr.text):
            path = match.group(0)
            if path.startswith("/rest/") or path.startswith("/api/"):
                endpoints.add(urljoin(get_origin(base_url), path))

    return endpoints

def normalize_url(u: str) -> str:
    try:
        parts = urlsplit(u)
        return urlunsplit((parts.scheme, parts.netloc, parts.path, parts.query, ""))
    except Exception:
        return u

def get_all_links(session, url):
    links = set()
    r = try_get(session, url)
    if not r:
        return links

    soup = BeautifulSoup(r.text, "html.parser")
    base = urlparse(url).netloc

    for a in soup.find_all("a", href=True):
        full = urljoin(url, a["href"])
        full = normalize_url(full)
        if urlparse(full).netloc == base:
            links.add(full)

    for f in soup.find_all("form"):
        action = f.get("action")
        if action:
            full = urljoin(url, action)
            full = normalize_url(full)
            if urlparse(full).netloc == base:
                links.add(full)

    return links

def extract_forms_from_html(html: str, page_url: str):
    forms = []
    if not html:
        return forms

    soup = BeautifulSoup(html, "html.parser")
    for f in soup.find_all("form"):
        action = f.get("action") or page_url
        action = urljoin(page_url, action)
        method = (f.get("method") or "get").strip().lower()

        inputs = []
        for inp in f.find_all("input"):
            name = inp.get("name")
            itype = (inp.get("type") or "text").strip().lower()
            inputs.append({
                "name": name,
                "type": itype,
                "minlength": inp.get("minlength"),
                "pattern": inp.get("pattern"),
                "autocomplete": inp.get("autocomplete"),
                "raw": dict(inp.attrs)
            })

        for ta in f.find_all("textarea"):
            name = ta.get("name")
            inputs.append({
                "name": name,
                "type": "textarea",
                "minlength": ta.get("minlength"),
                "pattern": ta.get("pattern"),
                "autocomplete": ta.get("autocomplete"),
                "raw": dict(ta.attrs)
            })

        forms.append({"action": action, "method": method, "inputs": inputs})
    return forms

# ================= SAFE ACTIVE GATE =================

def allow_active_dast(target_url: str) -> bool:
    host = urlsplit(target_url).hostname or ""
    if host in ("localhost", "127.0.0.1"):
        return True
    try:
        ip = ipaddress.ip_address(host)
        return ip.is_private or ip.is_loopback
    except Exception:
        return False

def extract_query_params(url: str) -> list[str]:
    try:
        qs = parse_qs(urlsplit(url).query, keep_blank_values=True)
        return [k for k in qs.keys() if k]
    except Exception:
        return []

def inject_query_param(url: str, param: str, payload: str) -> str:
    parts = urlsplit(url)
    qs = parse_qs(parts.query, keep_blank_values=True)
    qs[param] = [payload]
    new_query = urlencode(qs, doseq=True)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, new_query, ""))

def looks_like_sql_error(text: str) -> bool:
    t = (text or "").lower()
    return any(k in t for k in SQL_ERROR_KEYWORDS)

# ================= DAST (PASSIVE) =================

def scan_url_dast_safe(session, url):
    vulns = {
        "insecure_headers": [],
        "cookie_security": [],
        "csrf": [],
        "weak_passwords": [],
        "auth_issues": [],
        "misconfig": [],
        "info": [],
    }

    r = try_get(session, url)
    if not r:
        return vulns

    headers = {k.lower(): v for k, v in (r.headers or {}).items()}
    ct = (headers.get("content-type") or "").lower()

    required = [
        ("content-security-policy", "Content-Security-Policy", "Medium", 5.0,
         "Missing CSP header (helps mitigate XSS).",
         "Add a strong Content-Security-Policy and test against app functionality."),
        ("strict-transport-security", "Strict-Transport-Security", "Medium", 5.0,
         "Missing HSTS header on HTTPS (prevents SSL stripping).",
         "Enable HSTS (only if you fully support HTTPS)."),
        ("x-frame-options", "X-Frame-Options", "Low", 3.1,
         "Missing X-Frame-Options (clickjacking risk).",
         "Add X-Frame-Options: DENY or SAMEORIGIN, or use CSP frame-ancestors."),
        ("x-content-type-options", "X-Content-Type-Options", "Low", 2.7,
         "Missing X-Content-Type-Options (MIME sniffing risk).",
         "Add X-Content-Type-Options: nosniff."),
        ("referrer-policy", "Referrer-Policy", "Low", 2.5,
         "Missing Referrer-Policy (referrer leakage risk).",
         "Set Referrer-Policy (e.g., strict-origin-when-cross-origin)."),
        ("permissions-policy", "Permissions-Policy", "Low", 2.0,
         "Missing Permissions-Policy (browser feature control).",
         "Define a Permissions-Policy appropriate for the app."),
    ]

    fingerprint = []
    if "server" in headers:
        fingerprint.append("Server")
    if "x-powered-by" in headers:
        fingerprint.append("X-Powered-By")
    if fingerprint:
        vulns["insecure_headers"].append({
            "name": "Server Fingerprinting Headers Exposed",
            "severity": "Medium",
            "cvss_score": 5.0,
            "url": url,
            "details": "Server-identifying headers exposed: " + ", ".join(fingerprint),
            "fix": "Remove or minimize server-identifying headers (Server, X-Powered-By) at web server/app config."
        })

    is_https = urlsplit(url).scheme.lower() == "https"
    for key, shown, sev, cvss, details, fix in required:
        if key == "strict-transport-security":
            if is_https and key not in headers:
                vulns["insecure_headers"].append({
                    "name": f"Missing {shown}",
                    "severity": sev,
                    "cvss_score": cvss,
                    "url": url,
                    "details": details,
                    "fix": fix
                })
            continue
        if key not in headers:
            vulns["insecure_headers"].append({
                "name": f"Missing {shown}",
                "severity": sev,
                "cvss_score": cvss,
                "url": url,
                "details": details,
                "fix": fix
            })

    set_cookie = r.headers.get("Set-Cookie")
    if set_cookie:
        cookies_blob = set_cookie.lower()
        lacks_secure = (" secure" not in cookies_blob) and (is_https)
        lacks_httponly = (" httponly" not in cookies_blob)
        lacks_samesite = (" samesite" not in cookies_blob)

        if lacks_secure:
            vulns["cookie_security"].append({
                "name": "Cookie Missing Secure Flag",
                "severity": "Medium",
                "cvss_score": 5.0,
                "url": url,
                "details": "At least one cookie appears to be set without the Secure attribute on an HTTPS page.",
                "fix": "Set Secure on session cookies and sensitive cookies when using HTTPS."
            })
        if lacks_httponly:
            vulns["cookie_security"].append({
                "name": "Cookie Missing HttpOnly Flag",
                "severity": "Medium",
                "cvss_score": 5.0,
                "url": url,
                "details": "At least one cookie appears to be set without the HttpOnly attribute.",
                "fix": "Set HttpOnly on session cookies to reduce JavaScript access."
            })
        if lacks_samesite:
            vulns["cookie_security"].append({
                "name": "Cookie Missing SameSite Attribute",
                "severity": "Low",
                "cvss_score": 3.1,
                "url": url,
                "details": "At least one cookie appears to be set without SameSite.",
                "fix": "Set SameSite=Lax/Strict (or None+Secure if cross-site is required)."
            })

    if "text/html" in ct:
        forms = extract_forms_from_html(r.text, url)
        for form in forms:
            if form["method"] == "post":
                token_names = {"csrf", "token", "_token", "csrf_token", "csrfmiddlewaretoken", "xsrf", "xsrftoken"}
                has_token = any((i.get("name") or "").lower() in token_names for i in form["inputs"] if i.get("name"))
                if not has_token:
                    vulns["csrf"].append({
                        "name": "Possible Missing CSRF Protection",
                        "severity": "Medium",
                        "cvss_score": 6.0,
                        "url": form["action"],
                        "details": "POST form detected without an obvious CSRF token field (heuristic).",
                        "fix": "Include anti-CSRF tokens in all state-changing requests and validate them server-side."
                    })

    vulns["info"].append({
        "name": "Endpoint Reachable",
        "severity": "Info",
        "cvss_score": 0.0,
        "url": url,
        "details": f"HTTP {r.status_code} | Content-Type: {r.headers.get('Content-Type','')}",
        "fix": "N/A"
    })
    return vulns

# ================= ACTIVE DAST (LOCAL ONLY) =================

def active_test_url_params(session, url: str, scan: str):
    out = {"active_sqli": [], "active_xss": []}
    params = extract_query_params(url)
    if not params:
        return out

    baseline = try_get(session, url, timeout=10)
    if not baseline or baseline.text is None:
        return out

    base_len = len(baseline.text or "")

    for p in params:
        if scan in ("sqli", "all"):
            payloads = ["'", "\"", "' OR '1'='1"]
            for pay in payloads:
                test_url = inject_query_param(url, p, pay)
                r = try_get(session, test_url, timeout=10)
                if not r or r.text is None:
                    continue
                t = r.text or ""
                big_delta = abs(len(t) - base_len) > 900
                if looks_like_sql_error(t) or big_delta:
                    evidence = "SQL error keyword detected" if looks_like_sql_error(t) else "Large response length delta"
                    out["active_sqli"].append({
                        "name": "Possible SQL Injection (Active - Local Only)",
                        "severity": "High",
                        "cvss_score": 7.5,
                        "url": url,
                        "details": f"Parameter '{p}' shows SQLi indicators. Evidence: {evidence}.",
                        "fix": "Use parameterized queries/ORM, validate inputs, and handle errors securely."
                    })
                    break

        if scan in ("xss", "all"):
            marker = "wgXSS_12345"
            pay = f'"><{marker}>'
            test_url = inject_query_param(url, p, pay)
            r = try_get(session, test_url, timeout=10)
            if r and r.text and marker in r.text:
                out["active_xss"].append({
                    "name": "Possible Reflected XSS (Active - Local Only)",
                    "severity": "High",
                    "cvss_score": 7.2,
                    "url": url,
                    "details": "Unique marker reflected in the HTTP response body.",
                    "fix": "Escape/encode output, validate input, use safe templating, and enforce CSP."
                })
    return out

# ================= SAST =================

def iter_code_files(root_path: str):
    exts = {
        ".py", ".php", ".js", ".ts", ".java", ".cs", ".rb", ".go",
        ".html", ".htm", ".env", ".config", ".ini", ".yaml", ".yml", ".json"
    }
    for base, dirs, files in os.walk(root_path):
        skip = {"node_modules", ".git", "__pycache__", ".venv", "venv", "dist", "build"}
        dirs[:] = [d for d in dirs if d not in skip]
        for fn in files:
            p = os.path.join(base, fn)
            _, ext = os.path.splitext(fn.lower())
            if ext in exts or fn.lower() in (".env", "dockerfile"):
                yield p

def sast_scan_path(path: str):
    results = {
        "hardcoded_secrets": [],
        "dangerous_functions": [],
        "insecure_crypto": [],
        "debug_exposure": [],
    }

    secret_patterns = [
        (re.compile(r"(?i)\b(api[_-]?key|secret|token|passwd|password)\b\s*[:=]\s*['\"][^'\"]{6,}['\"]"), "Hardcoded secret-like value"),
    ]
    dangerous_patterns = [
        (re.compile(r"\beval\s*\("), "Use of eval()"),
        (re.compile(r"\bexec\s*\("), "Use of exec()"),
        (re.compile(r"subprocess\.(Popen|call|run)\(.*shell\s*=\s*True", re.IGNORECASE), "subprocess with shell=True"),
        (re.compile(r"os\.system\s*\("), "Use of os.system()"),
    ]
    crypto_patterns = [
        (re.compile(r"\bmd5\s*\(", re.IGNORECASE), "Weak hash: MD5"),
        (re.compile(r"\bsha1\s*\(", re.IGNORECASE), "Weak hash: SHA1"),
    ]
    debug_patterns = [
        (re.compile(r"\bdebug\s*=\s*True\b"), "Debug mode enabled"),
        (re.compile(r"console\.log\s*\("), "console.log present (possible info exposure)"),
    ]

    for fpath in iter_code_files(path):
        try:
            with open(fpath, "r", encoding="utf-8", errors="ignore") as fp:
                for i, line in enumerate(fp, start=1):
                    ln = line.strip()
                    for rx, msg in secret_patterns:
                        if rx.search(ln):
                            results["hardcoded_secrets"].append({
                                "name": "Hardcoded Secret (SAST)",
                                "severity": "High",
                                "cvss_score": 7.8,
                                "url": f"{fpath}:{i}",
                                "details": f"{msg} detected in source code line {i}.",
                                "fix": "Move secrets to env vars / secrets manager. Remove them from code and rotate exposed secrets."
                            })
                    for rx, msg in dangerous_patterns:
                        if rx.search(ln):
                            results["dangerous_functions"].append({
                                "name": "Potentially Dangerous Function (SAST)",
                                "severity": "High",
                                "cvss_score": 7.0,
                                "url": f"{fpath}:{i}",
                                "details": f"{msg} detected at line {i}.",
                                "fix": "Avoid dynamic execution. Use safe allowlists and validate all inputs."
                            })
                    for rx, msg in crypto_patterns:
                        if rx.search(ln):
                            results["insecure_crypto"].append({
                                "name": "Weak Cryptography Usage (SAST)",
                                "severity": "Medium",
                                "cvss_score": 5.3,
                                "url": f"{fpath}:{i}",
                                "details": f"{msg} detected at line {i}.",
                                "fix": "Use modern algorithms (SHA-256, bcrypt/argon2 where appropriate)."
                            })
                    for rx, msg in debug_patterns:
                        if rx.search(ln):
                            results["debug_exposure"].append({
                                "name": "Debug/Logging Exposure (SAST)",
                                "severity": "Low",
                                "cvss_score": 3.7,
                                "url": f"{fpath}:{i}",
                                "details": f"{msg} detected at line {i}.",
                                "fix": "Disable debug in production and reduce sensitive logging."
                            })
        except Exception:
            continue
    return results

# ================= SCA =================

def parse_requirements_line(line: str):
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    if line.startswith("-r") or line.startswith("--requirement"):
        return {"type": "include", "raw": line}
    if "git+" in line or "http://" in line or "https://" in line:
        return {"type": "url", "raw": line}
    m = re.match(r"^\s*([A-Za-z0-9_.-]+)\s*(.*)$", line)
    if not m:
        return {"type": "unknown", "raw": line}
    name = m.group(1)
    spec = (m.group(2) or "").strip()
    return {"type": "pkg", "name": name, "spec": spec, "raw": line}

def sca_scan_requirements(req_file: str):
    results = {"dependency_hygiene": [], "dependency_sources": []}
    if not os.path.exists(req_file):
        results["dependency_hygiene"].append({
            "name": "Requirements File Not Found (SCA)",
            "severity": "High",
            "cvss_score": 7.0,
            "url": req_file,
            "details": "requirements file path does not exist.",
            "fix": "Provide a valid requirements.txt path for dependency scanning."
        })
        return results

    try:
        with open(req_file, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except Exception:
        results["dependency_hygiene"].append({
            "name": "Requirements Read Error (SCA)",
            "severity": "High",
            "cvss_score": 7.0,
            "url": req_file,
            "details": "Could not read requirements file.",
            "fix": "Ensure file permissions and encoding are correct."
        })
        return results

    for idx, line in enumerate(lines, start=1):
        p = parse_requirements_line(line)
        if not p:
            continue

        if p["type"] == "include":
            results["dependency_sources"].append({
                "name": "Requirements Include Detected (SCA)",
                "severity": "Low",
                "cvss_score": 2.0,
                "url": f"{req_file}:{idx}",
                "details": f"Requirements file includes another file: {p['raw']}",
                "fix": "Ensure included files are also reviewed and pinned."
            })
            continue

        if p["type"] == "url":
            results["dependency_sources"].append({
                "name": "URL/VCS Dependency Detected (SCA)",
                "severity": "Medium",
                "cvss_score": 5.0,
                "url": f"{req_file}:{idx}",
                "details": f"Dependency installed from URL/VCS: {p['raw']}",
                "fix": "Prefer pinned versions from trusted registries. Review tags/hashes and provenance."
            })
            continue

        if p["type"] == "pkg":
            name = p["name"]
            spec = p["spec"]
            if not spec:
                results["dependency_hygiene"].append({
                    "name": "Unpinned Dependency Version (SCA)",
                    "severity": "Medium",
                    "cvss_score": 5.0,
                    "url": f"{req_file}:{idx}",
                    "details": f"Package '{name}' has no version constraint (line {idx}).",
                    "fix": "Pin versions (==) or set safe ranges to control patching and reproducibility."
                })
            else:
                if "==" not in spec:
                    results["dependency_hygiene"].append({
                        "name": "Non-Pinned Dependency Constraint (SCA)",
                        "severity": "Low",
                        "cvss_score": 3.1,
                        "url": f"{req_file}:{idx}",
                        "details": f"Package '{name}' uses a range/constraint: '{spec}'.",
                        "fix": "Consider pinning exact versions for production builds or lock dependencies with a lockfile."
                    })
    return results

# ================= REPORTING (JSON) =================

def save_report_json(data, filename):
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4)

# ================= REPORTING (PDF - IMPROVED TOP 5) =================

def save_report_pdf(data, meta: dict, filename: str, report_type: str):
    # Theme
    BLACK = colors.HexColor("#0B0F14")
    RED = colors.HexColor("#E10600")
    WHITE = colors.HexColor("#FFFFFF")

    # Stronger contrast grays (fix your point #2)
    TEXT = colors.HexColor("#111827")
    SUBTEXT = colors.HexColor("#374151")   # darker than before
    MUTED = colors.HexColor("#6B7280")     # still readable
    LIGHT = colors.HexColor("#F5F7FA")
    BORDER = colors.HexColor("#E5E7EB")

    def safe_str(x):
        return "" if x is None else str(x)

    def wrap_text(text, max_chars):
        text = safe_str(text).strip()
        if not text:
            return [""]
        lines = []
        while len(text) > max_chars:
            cut = text.rfind(" ", 0, max_chars)
            if cut == -1:
                cut = max_chars
            lines.append(text[:cut].strip())
            text = text[cut:].strip()
        if text:
            lines.append(text)
        return lines

    def severity_fill(sev: str):
        s = safe_str(sev).lower()
        if s == "critical":
            return colors.HexColor("#7F1D1D")
        if s == "high":
            return colors.HexColor("#B91C1C")
        if s == "medium":
            return colors.HexColor("#B45309")
        if s == "low":
            return colors.HexColor("#1D4ED8")
        return colors.HexColor("#374151")

    def sev_rank(s):
        s = safe_str(s).lower()
        if s == "critical":
            return 0
        if s == "high":
            return 1
        if s == "medium":
            return 2
        if s == "low":
            return 3
        return 4

    def calc_summary(d):
        counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
        total = 0
        for arr in d.values():
            for f in arr:
                total += 1
                sev = safe_str(f.get("severity", "Info")).title()
                if sev not in counts:
                    sev = "Info"
                counts[sev] += 1
        return total, counts

    def security_score(counts):
        score = 100
        score -= counts.get("Critical", 0) * 18
        score -= counts.get("High", 0) * 12
        score -= counts.get("Medium", 0) * 6
        score -= counts.get("Low", 0) * 2
        if score < 0:
            score = 0
        if score > 100:
            score = 100
        return score

    # (3) Default professional details + recommendation if missing
    DEFAULT_KB = {
        "Missing Content-Security-Policy": (
            "The Content-Security-Policy (CSP) header is not set. CSP reduces the impact of XSS by restricting where scripts, styles, and other resources can load from.",
            "Implement a strict CSP (start with report-only), then enforce. Use nonces/hashes for scripts, restrict default-src, and validate against application functionality."
        ),
        "Missing Referrer-Policy": (
            "The Referrer-Policy header is not set. This can leak sensitive URL data (tokens/paths) to external sites via the Referer header.",
            "Set Referrer-Policy to a secure value such as 'strict-origin-when-cross-origin' or 'no-referrer' based on business requirements."
        ),
        "Missing X-Frame-Options": (
            "The X-Frame-Options header is missing, which may allow clickjacking by framing the site in a malicious page.",
            "Set X-Frame-Options to DENY or SAMEORIGIN. Prefer CSP 'frame-ancestors' for modern control."
        ),
        "Missing X-Content-Type-Options": (
            "The X-Content-Type-Options header is missing. This can allow MIME-sniffing attacks in certain contexts.",
            "Set X-Content-Type-Options: nosniff on all responses where appropriate."
        ),
        "Missing Permissions-Policy": (
            "The Permissions-Policy header is missing. This header limits access to powerful browser features.",
            "Add a Permissions-Policy restricting features (camera, microphone, geolocation, etc.) based on the application's needs."
        ),
        "Missing Strict-Transport-Security": (
            "HSTS is not enabled on HTTPS. Without HSTS, users may be exposed to downgrade/SSL-stripping in some scenarios.",
            "Enable HSTS with an appropriate max-age once HTTPS is stable. Consider includeSubDomains and preload carefully."
        ),
        "Server Fingerprinting Headers Exposed": (
            "Server-identifying headers such as 'Server' or 'X-Powered-By' are exposed, which can help attackers profile the technology stack.",
            "Remove or minimize server-identifying headers at reverse proxy / web server and application configuration."
        ),
    }

    def normalize_title(name: str) -> str:
        return safe_str(name).strip()

    def enrich_details_fix(name: str, details: str, fix: str):
        title = normalize_title(name)
        if (not details or details.strip() == "" or details.strip().upper() == "N/A") or (not fix or fix.strip() == "" or fix.strip().upper() == "N/A"):
            if title in DEFAULT_KB:
                d, f = DEFAULT_KB[title]
                if not details or details.strip() == "" or details.strip().upper() == "N/A":
                    details = d
                if not fix or fix.strip() == "" or fix.strip().upper() == "N/A":
                    fix = f
        return details, fix

    def try_draw_logo(c, x, y_top, max_w, max_h):
        if not os.path.exists(LOGO_FILE):
            return False
        try:
            img = ImageReader(LOGO_FILE)
            iw, ih = img.getSize()
            scale = min(max_w / float(iw), max_h / float(ih))
            w = iw * scale
            h = ih * scale
            c.drawImage(img, x, y_top - h, width=w, height=h, mask="auto")
            return True
        except Exception:
            return False

    def footer(c, page_num):
        width, _ = letter
        c.setStrokeColor(colors.HexColor("#1F2937"))
        c.setLineWidth(1)
        c.line(55, 52, width - 55, 52)
        c.setFillColor(MUTED)
        c.setFont("Helvetica", 9)
        c.drawString(55, 36, "Web Guard • Pentest-Style Report • Academic Use")
        c.drawRightString(width - 55, 36, f"Page {page_num}")

    def header_bar(c, title):
        width, height = letter
        c.setFillColor(BLACK)
        c.rect(0, height - 60, width, 60, stroke=0, fill=1)
        c.setFillColor(RED)
        c.rect(0, height - 62, width, 4, stroke=0, fill=1)

        c.setFillColor(WHITE)
        c.setFont("Helvetica-Bold", 14)
        c.drawString(55, height - 40, "WEB GUARD")

        c.setFillColor(colors.HexColor("#D1D5DB"))
        c.setFont("Helvetica", 10)
        c.drawString(145, height - 40, safe_str(title))

        tgt = safe_str(meta.get("target", ""))
        if tgt:
            c.setFillColor(WHITE)
            c.setFont("Helvetica", 9)
            c.drawRightString(width - 55, height - 40, tgt[:70] + ("..." if len(tgt) > 70 else ""))

    def new_page(c, page_num, title=""):
        c.showPage()
        header_bar(c, title)
        footer(c, page_num)

    # ---------- prepare findings ----------
    total, counts = calc_summary(data)
    score = security_score(counts)

    # Flatten
    all_findings = []
    for cat, arr in data.items():
        for f in arr:
            ff = dict(f)
            ff["_category"] = cat
            all_findings.append(ff)

    all_findings.sort(key=lambda x: (sev_rank(x.get("severity")), -float(x.get("cvss_score") or 0.0)))

    # (1) IMPROVE TOP 5 -> Deduplicate / Aggregate by (name + severity)
    agg = {}
    for f in all_findings:
        name = normalize_title(f.get("name", "Unknown"))
        sev = safe_str(f.get("severity", "Info")).title()
        key = (name, sev)
        if key not in agg:
            agg[key] = {
                "name": name,
                "severity": sev,
                "cvss": float(f.get("cvss_score") or 0.0),
                "category": safe_str(f.get("_category", "")),
                "urls": set(),
                "details": safe_str(f.get("details", "")),
                "fix": safe_str(f.get("fix", "")),
            }
        agg[key]["urls"].add(safe_str(f.get("url", "")))
        # keep max cvss
        cv = float(f.get("cvss_score") or 0.0)
        if cv > agg[key]["cvss"]:
            agg[key]["cvss"] = cv
        # prefer non-empty details/fix
        if safe_str(f.get("details", "")).strip():
            agg[key]["details"] = safe_str(f.get("details", ""))
        if safe_str(f.get("fix", "")).strip():
            agg[key]["fix"] = safe_str(f.get("fix", ""))

    top_agg = list(agg.values())
    top_agg.sort(key=lambda x: (sev_rank(x["severity"]), -x["cvss"], -len(x["urls"])))
    top_5 = top_agg[:5]

    # enrich top_5 details/fix
    for item in top_5:
        d, f = enrich_details_fix(item["name"], item.get("details", ""), item.get("fix", ""))
        item["details"] = d
        item["fix"] = f

    # ---------- PDF ----------
    c = canvas.Canvas(filename, pagesize=letter)
    width, height = letter
    page_num = 1

    # COVER
    c.setFillColor(BLACK)
    c.rect(0, 0, width, height, stroke=0, fill=1)
    c.setFillColor(RED)
    c.rect(0, height - 20, width, 20, stroke=0, fill=1)
    c.rect(0, 0, width, 14, stroke=0, fill=1)

    logo_ok = try_draw_logo(c, x=55, y_top=height - 35, max_w=220, max_h=60)
    if not logo_ok:
        c.setFillColor(WHITE)
        c.setFont("Helvetica-Bold", 22)
        c.drawString(55, height - 65, "WEB GUARD")

    c.setFillColor(WHITE)
    c.setFont("Helvetica-Bold", 30)
    c.drawString(55, height - 120, "SECURITY ASSESSMENT REPORT")

    c.setFillColor(colors.HexColor("#D1D5DB"))
    c.setFont("Helvetica", 13)
    c.drawString(55, height - 145, "Professional Pentest-Style Report • Black/Red Theme")

    # info card
    card_x, card_w = 55, width - 110
    card_y_top, card_h = height - 200, 170
    c.setFillColor(WHITE)
    c.roundRect(card_x, card_y_top - card_h, card_w, card_h, 14, stroke=0, fill=1)

    c.setFillColor(TEXT)
    c.setFont("Helvetica-Bold", 12)
    c.drawString(card_x + 18, card_y_top - 30, "Target")
    c.drawString(card_x + 18, card_y_top - 58, "Report Type")
    c.drawString(card_x + 18, card_y_top - 86, "Generated")
    c.drawString(card_x + 18, card_y_top - 114, "Scope")

    c.setFillColor(RED)
    c.setFont("Helvetica-Bold", 12)
    tgt_lines = wrap_text(meta.get("target", ""), 70)
    c.drawString(card_x + 120, card_y_top - 30, tgt_lines[0] if tgt_lines else "")

    c.setFillColor(TEXT)
    c.setFont("Helvetica-Bold", 12)
    c.drawString(card_x + 120, card_y_top - 58, safe_str(report_type).upper())

    c.setFont("Helvetica", 11)
    c.drawString(card_x + 120, card_y_top - 86, safe_str(meta.get("generated", "")))

    c.setFont("Helvetica", 11)
    c.drawString(card_x + 120, card_y_top - 114, f"URLs Scanned: {safe_str(meta.get('urls_scanned', '0'))}  |  Duration: {safe_str(meta.get('duration', ''))}")

    # score
    score_x, score_y, score_w, score_h = 55, 130, width - 110, 90
    c.setFillColor(colors.HexColor("#111827"))
    c.roundRect(score_x, score_y, score_w, score_h, 16, stroke=0, fill=1)
    c.setFillColor(WHITE)
    c.setFont("Helvetica-Bold", 18)
    c.drawString(score_x + 18, score_y + 54, "Security Score")
    c.setFont("Helvetica-Bold", 40)
    c.setFillColor(RED if score < 60 else (colors.HexColor("#F59E0B") if score < 80 else colors.HexColor("#10B981")))
    c.drawRightString(score_x + score_w - 18, score_y + 38, f"{score}/100")

    footer(c, page_num)

    # PAGE 2: DASHBOARD
    page_num += 1
    new_page(c, page_num, title="Executive Dashboard")

    y = height - 90
    c.setFillColor(WHITE)
    c.setFont("Helvetica-Bold", 18)
    c.drawString(55, y, "Executive Dashboard")
    y -= 18
    c.setFillColor(RED)
    c.rect(55, y, width - 110, 3, stroke=0, fill=1)
    y -= 28

    # severity cards
    card_gap = 12
    card_h = 60
    card_w = (width - 110 - card_gap * 4) / 5.0
    sx = 55
    sev_order = ["Critical", "High", "Medium", "Low", "Info"]
    sev_color = {
        "Critical": colors.HexColor("#7F1D1D"),
        "High": colors.HexColor("#B91C1C"),
        "Medium": colors.HexColor("#B45309"),
        "Low": colors.HexColor("#1D4ED8"),
        "Info": colors.HexColor("#374151"),
    }

    for i, sname in enumerate(sev_order):
        x = sx + i * (card_w + card_gap)
        c.setFillColor(WHITE)
        c.roundRect(x, y - card_h, card_w, card_h, 12, stroke=0, fill=1)
        c.setFillColor(sev_color[sname])
        c.rect(x, y - 6, card_w, 6, stroke=0, fill=1)
        c.setFillColor(TEXT)
        c.setFont("Helvetica-Bold", 11)
        c.drawString(x + 10, y - 24, sname.upper())
        c.setFont("Helvetica-Bold", 22)
        c.setFillColor(RED if sname in ("Critical", "High") else TEXT)
        c.drawString(x + 10, y - 50, str(counts.get(sname, 0)))

    y -= 90

    # quick summary
    c.setFillColor(WHITE)
    c.setFont("Helvetica-Bold", 13)
    c.drawString(55, 170, "Quick Summary")
    c.setFillColor(LIGHT)
    c.roundRect(55, 95, width - 110, 70, 14, stroke=0, fill=1)
    c.setFillColor(TEXT)
    c.setFont("Helvetica", 11)
    c.drawString(70, 140, f"Total Findings: {total}")
    c.drawString(70, 120, f"Scan Type: {safe_str(meta.get('scan_type','PASSIVE'))}  |  Active: {safe_str(meta.get('active','NO'))}")
    c.drawString(70, 100, f"URLs Scanned: {safe_str(meta.get('urls_scanned','0'))}  |  Depth: {safe_str(meta.get('depth',''))}")

    # PAGE 3: TOP 5 IMPROVED (Details + Recommendation)
    page_num += 1
    new_page(c, page_num, title="Top Findings (Highest Priority)")

    y = height - 90
    c.setFillColor(WHITE)
    c.setFont("Helvetica-Bold", 18)
    c.drawString(55, y, "Top 5 Findings (Highest Priority)")
    y -= 18
    c.setFillColor(RED)
    c.rect(55, y, width - 110, 3, stroke=0, fill=1)
    y -= 24

    def badge(c, x, y, w, h, label, fill):
        c.setFillColor(fill)
        c.roundRect(x, y, w, h, 7, stroke=0, fill=1)
        c.setFillColor(WHITE)
        c.setFont("Helvetica-Bold", 9)
        c.drawCentredString(x + w / 2.0, y + 4, label)

    # Draw each Top finding as a pentest-style block
    for i, item in enumerate(top_5, start=1):
        if y < 210:
            page_num += 1
            new_page(c, page_num, title="Top Findings (Highest Priority)")
            y = height - 90

        name = item["name"]
        sev = item["severity"]
        cvss = item["cvss"]
        urls = sorted(list(item["urls"]))
        details = item["details"]
        fix = item["fix"]

        block_h = 145
        c.setFillColor(WHITE)
        c.roundRect(55, y - block_h, width - 110, block_h, 14, stroke=0, fill=1)

        # header line
        c.setFillColor(TEXT)
        c.setFont("Helvetica-Bold", 12)
        c.drawString(70, y - 26, f"{i}. {name}")

        badge(c, width - 160, y - 34, 90, 18, sev.upper(), severity_fill(sev))

        c.setFillColor(SUBTEXT)
        c.setFont("Helvetica-Bold", 9)
        c.drawString(70, y - 44, f"CVSS: {cvss:.1f}   |   Affected URLs: {len(urls)}")

        # Evidence URLs
        c.setFillColor(SUBTEXT)
        c.setFont("Helvetica-Bold", 9)
        c.drawString(70, y - 62, "Evidence (sample URLs):")
        c.setFillColor(RED)
        c.setFont("Helvetica", 9)
        sample = urls[:3] if urls else []
        yy = y - 62
        for u in sample:
            yy -= 12
            c.drawString(190, yy, u[:95] + ("..." if len(u) > 95 else ""))

        # Details
        c.setFillColor(SUBTEXT)
        c.setFont("Helvetica-Bold", 9)
        c.drawString(70, y - 104, "Details:")
        c.setFillColor(TEXT)
        c.setFont("Helvetica", 9)
        d_lines = wrap_text(details, 95)[:2]
        c.drawString(190, y - 104, d_lines[0] if d_lines else "")
        if len(d_lines) > 1:
            c.drawString(190, y - 116, d_lines[1])

        # Recommendation
        c.setFillColor(SUBTEXT)
        c.setFont("Helvetica-Bold", 9)
        c.drawString(70, y - 132, "Recommendation:")
        c.setFillColor(TEXT)
        c.setFont("Helvetica", 9)
        f_lines = wrap_text(fix, 90)[:2]
        c.drawString(190, y - 132, f_lines[0] if f_lines else "")
        if len(f_lines) > 1:
            c.drawString(190, y - 144, f_lines[1])

        y -= (block_h + 14)

    # DETAILS PAGES (existing cards)
    page_num += 1
    new_page(c, page_num, title="Findings Details")

    y = height - 90
    c.setFillColor(WHITE)
    c.setFont("Helvetica-Bold", 18)
    c.drawString(55, y, "Findings Details")
    y -= 18
    c.setFillColor(RED)
    c.rect(55, y, width - 110, 3, stroke=0, fill=1)
    y -= 22

    def draw_card(c, x, y_top, w, h, f, idx):
        name = safe_str(f.get("name", "Unknown"))
        sev = safe_str(f.get("severity", "Info")).title()
        cvss = safe_str(f.get("cvss_score", ""))
        url = safe_str(f.get("url", ""))
        details = safe_str(f.get("details", ""))
        fix = safe_str(f.get("fix", ""))

        details, fix = enrich_details_fix(name, details, fix)

        c.setFillColor(WHITE)
        c.roundRect(x, y_top - h, w, h, 14, stroke=0, fill=1)

        c.setFillColor(severity_fill(sev))
        c.roundRect(x, y_top - 18, w, 18, 14, stroke=0, fill=1)

        c.setFillColor(WHITE)
        c.setFont("Helvetica-Bold", 10)
        c.drawString(x + 12, y_top - 13, f"{idx}. {sev.upper()}  |  CVSS: {cvss}")

        c.setFillColor(TEXT)
        c.setFont("Helvetica-Bold", 12)
        c.drawString(x + 12, y_top - 38, name[:78] + ("..." if len(name) > 78 else ""))

        c.setFillColor(SUBTEXT)
        c.setFont("Helvetica-Bold", 9)
        c.drawString(x + 12, y_top - 54, "Location:")
        c.setFillColor(RED)
        c.setFont("Helvetica", 9)
        loc_lines = wrap_text(url, 92)[:2]
        c.drawString(x + 70, y_top - 54, loc_lines[0] if loc_lines else "")
        if len(loc_lines) > 1:
            c.drawString(x + 70, y_top - 66, loc_lines[1])

        c.setFillColor(SUBTEXT)
        c.setFont("Helvetica-Bold", 9)
        c.drawString(x + 12, y_top - 84, "Details:")
        c.setFillColor(TEXT)
        c.setFont("Helvetica", 9)
        d_lines = wrap_text(details, 102)[:3]
        yy = y_top - 84
        for j, ln in enumerate(d_lines):
            c.drawString(x + 70, yy - (j * 12), ln)

        c.setFillColor(SUBTEXT)
        c.setFont("Helvetica-Bold", 9)
        c.drawString(x + 12, y_top - 126, "Recommendation:")
        c.setFillColor(TEXT)
        c.setFont("Helvetica", 9)
        f_lines = wrap_text(fix, 102)[:3]
        yy2 = y_top - 126
        for j, ln in enumerate(f_lines):
            c.drawString(x + 110, yy2 - (j * 12), ln)

    categories = [(k, v) for k, v in data.items() if v]
    idx_global = 1

    for cat, findings in categories:
        if y < 160:
            page_num += 1
            new_page(c, page_num, title="Findings Details")
            y = height - 90

        c.setFillColor(colors.HexColor("#111827"))
        c.roundRect(55, y - 26, width - 110, 26, 10, stroke=0, fill=1)
        c.setFillColor(WHITE)
        c.setFont("Helvetica-Bold", 11)
        c.drawString(68, y - 18, f"CATEGORY: {safe_str(cat).upper()}")
        y -= 38

        for f in findings:
            if y < 190:
                page_num += 1
                new_page(c, page_num, title="Findings Details")
                y = height - 90
            draw_card(c, 55, y, width - 110, 150, f, idx_global)
            y -= 162
            idx_global += 1

    c.save()

# ================= MAIN RUNNERS =================

def run_dast(target_url: str, workers: int, scan: str, active: bool):
    start = time.time()
    session = setup_session()

    if not target_url.startswith(("http://", "https://")):
        target_url = "http://" + target_url

    origin = get_origin(target_url)
    crawled = set()
    queue = []

    crawled.add(normalize_url(target_url))
    queue.append(normalize_url(target_url))

    if is_juice_shop(session, origin):
        print(f"{Fore.CYAN}[i] Juice Shop detected → adding seeds + JS endpoint discovery{Style.RESET_ALL}")
        for p in JUICE_SEEDS:
            u = normalize_url(urljoin(origin, p))
            if u not in crawled:
                crawled.add(u)
                queue.append(u)

        js_eps = discover_endpoints_from_js(session, origin)
        for u in sorted(js_eps):
            u = normalize_url(u)
            if u not in crawled:
                crawled.add(u)
                queue.append(u)

    depth = 0
    while depth < MAX_CRAWL_DEPTH:
        next_q = []
        for u in tqdm(queue, desc="Crawling"):
            for l in get_all_links(session, u):
                l = normalize_url(l)
                if l not in crawled:
                    crawled.add(l)
                    next_q.append(l)
        queue = next_q
        depth += 1

    urls_list = sorted(list(crawled))

    results = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        for r in ex.map(lambda u: scan_url_dast_safe(session, u), urls_list):
            for k, v in r.items():
                if v:
                    results.setdefault(k, []).extend(v)

    if active and scan in ("sqli", "xss", "all"):
        if allow_active_dast(origin):
            print(f"{Fore.MAGENTA}[!] Active tests enabled (LOCAL/PRIVATE ONLY) → GET params only{Style.RESET_ALL}")
            active_hits = {"active_sqli": [], "active_xss": []}
            cand = [u for u in urls_list if urlsplit(u).query]
            with concurrent.futures.ThreadPoolExecutor(max_workers=min(workers, 8)) as ex:
                for out in ex.map(lambda u: active_test_url_params(session, u, scan), cand):
                    for k, v in out.items():
                        if v:
                            active_hits.setdefault(k, []).extend(v)
            for k, v in active_hits.items():
                if v:
                    results.setdefault(k, []).extend(v)
        else:
            print(f"{Fore.YELLOW}[i] Active disabled: target is NOT local/private. Passive scan only.{Style.RESET_ALL}")

    stamp = time.strftime("%Y%m%d_%H%M%S")
    pdf_name = f"webguard_dast_report_{stamp}.pdf"
    json_name = f"webguard_dast_report_{stamp}.json"

    meta = {
        "target": origin,
        "generated": time.strftime("%Y-%m-%d %H:%M:%S"),
        "scan_type": scan.upper(),
        "active": "YES" if active else "NO",
        "urls_scanned": len(crawled),
        "duration": f"{int(time.time() - start)}s",
        "depth": MAX_CRAWL_DEPTH,
    }

    save_report_pdf(results, meta, pdf_name, "dast")
    save_report_json(results, json_name)

    total_findings = sum(len(v) for v in results.values())

    print("\n" + "=" * 72)
    print(" Scan Completed Successfully ✅ ".center(72))
    print("=" * 72)
    print(f"[+] Target        : {origin}")
    print(f"[+] Mode          : DAST")
    print(f"[+] Scan Type     : {scan.upper()}")
    print(f"[+] Active        : {'YES' if active else 'NO'}")
    print(f"[+] URLs Scanned  : {len(crawled)}")
    print(f"[+] Total Findings: {total_findings}")
    print(f"[+] PDF Report    : {pdf_name}")
    print(f"[+] JSON Report   : {json_name}")
    print("=" * 72 + "\n")

def run_sast(path: str):
    stamp = time.strftime("%Y%m%d_%H%M%S")
    pdf_name = f"webguard_sast_report_{stamp}.pdf"
    json_name = f"webguard_sast_report_{stamp}.json"

    results = sast_scan_path(path)
    meta = {
        "target": path,
        "generated": time.strftime("%Y-%m-%d %H:%M:%S"),
        "scan_type": "SAST",
        "active": "NO",
        "urls_scanned": 0,
        "duration": "",
        "depth": "",
    }
    save_report_pdf(results, meta, pdf_name, "sast")
    save_report_json(results, json_name)

    total_findings = sum(len(v) for v in results.values())
    print("\n" + "=" * 72)
    print(" Scan Completed Successfully ✅ ".center(72))
    print("=" * 72)
    print(f"[+] Mode          : SAST")
    print(f"[+] Path          : {path}")
    print(f"[+] Total Findings: {total_findings}")
    print(f"[+] PDF Report    : {pdf_name}")
    print(f"[+] JSON Report   : {json_name}")
    print("=" * 72 + "\n")

def run_sca(req: str):
    stamp = time.strftime("%Y%m%d_%H%M%S")
    pdf_name = f"webguard_sca_report_{stamp}.pdf"
    json_name = f"webguard_sca_report_{stamp}.json"

    results = sca_scan_requirements(req)
    meta = {
        "target": req,
        "generated": time.strftime("%Y-%m-%d %H:%M:%S"),
        "scan_type": "SCA",
        "active": "NO",
        "urls_scanned": 0,
        "duration": "",
        "depth": "",
    }
    save_report_pdf(results, meta, pdf_name, "sca")
    save_report_json(results, json_name)

    total_findings = sum(len(v) for v in results.values())
    print("\n" + "=" * 72)
    print(" Scan Completed Successfully ✅ ".center(72))
    print("=" * 72)
    print(f"[+] Mode          : SCA")
    print(f"[+] Requirements  : {req}")
    print(f"[+] Total Findings: {total_findings}")
    print(f"[+] PDF Report    : {pdf_name}")
    print(f"[+] JSON Report   : {json_name}")
    print("=" * 72 + "\n")

# ================= MAIN =================

def main():
    print_banner()

    # Interactive mode (no args): keep looping + rescan (your point #5)
    if len(sys.argv) == 1:
        while True:
            cfg = interactive_menu()
            if not cfg:
                continue

            mode = cfg.get("mode")
            if mode == "dast":
                run_dast(cfg["url"], cfg.get("workers", 8), cfg.get("scan", "passive"), cfg.get("active", False))
            elif mode == "sast":
                run_sast(cfg["path"])
            elif mode == "sca":
                run_sca(cfg["requirements"])

            again = input("Re-scan? [y/N]: ").strip().lower()
            if again != "y":
                print("Done ✅")
                return

    # CLI mode
    parser = argparse.ArgumentParser(description="Web Guard Scanner (DAST/SAST/SCA)")
    sub = parser.add_subparsers(dest="mode")

    dast = sub.add_parser("dast", help="DAST scan (passive by default, optional active LOCAL ONLY)")
    dast.add_argument("-u", "--url", required=True, help="Target URL (e.g. http://localhost:3000)")
    dast.add_argument("-w", "--workers", type=int, default=8, help="Number of workers (default=8)")
    dast.add_argument("--scan", choices=["passive", "sqli", "xss", "all"], default="passive",
                      help="Scan type. Active requires --active and local/private target.")
    dast.add_argument("--active", action="store_true",
                      help="Enable Active tests (LOCAL/PRIVATE ONLY, GET params only).")

    sast = sub.add_parser("sast", help="SAST scan a source code folder")
    sast.add_argument("-p", "--path", required=True, help="Path to source code folder")

    sca = sub.add_parser("sca", help="SCA scan requirements.txt")
    sca.add_argument("-r", "--requirements", required=True, help="Path to requirements.txt")

    args = parser.parse_args()

    if args.mode == "dast":
        workers = max(1, min(32, int(args.workers)))
        run_dast(args.url, workers, args.scan, bool(args.active))
    elif args.mode == "sast":
        run_sast(args.path)
    elif args.mode == "sca":
        run_sca(args.requirements)
    else:
        print("[-] Please choose a mode: dast / sast / sca")
        sys.exit(1)

if __name__ == "__main__":
    main()