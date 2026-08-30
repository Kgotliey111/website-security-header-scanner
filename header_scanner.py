#!/usr/bin/env python3
"""
Website Security Header Scanner
Fetches headers, checks them, grades the site, and analyzes cookie security flags.
"""

import sys
from urllib.parse import urlparse
import requests

SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "points": 15,
        "description": "Forces browsers to use HTTPS, preventing downgrade "
                        "attacks and cookie hijacking over plain HTTP.",
        "check": lambda v: v is not None,
    },
    "Content-Security-Policy": {
        "points": 20,
        "description": "Restricts which sources scripts/styles/images can "
                        "load from, mitigating XSS and data injection attacks.",
        "check": lambda v: v is not None,
    },
    "X-Frame-Options": {
        "points": 15,
        "description": "Prevents the site from being embedded in an <iframe>, "
                        "protecting against clickjacking attacks.",
        "check": lambda v: v is not None and v.upper() in ("DENY", "SAMEORIGIN"),
    },
    "X-Content-Type-Options": {
        "points": 10,
        "description": "Stops browsers from MIME-sniffing a response away "
                        "from its declared content type, blocking certain "
                        "drive-by download attacks.",
        "check": lambda v: v is not None and v.lower() == "nosniff",
    },
    "Referrer-Policy": {
        "points": 10,
        "description": "Controls how much referrer information (URL data) "
                        "is leaked when navigating away from the site.",
        "check": lambda v: v is not None,
    },
    "Permissions-Policy": {
        "points": 10,
        "description": "Restricts which browser features (camera, mic, "
                        "geolocation, etc.) the page and its embedded content "
                        "can access.",
        "check": lambda v: v is not None,
    },
}

HTTPS_REDIRECT_POINTS = 20
COOKIE_POINTS = 15


def fetch_headers(url: str, timeout: int = 10) -> dict:
    try:
        resp = requests.get(url, timeout=timeout, allow_redirects=True)
        try:
            raw_cookies = resp.raw.headers.getlist("Set-Cookie")
        except Exception:
            raw_cookies = []
        return {
            "headers": resp.headers,
            "raw_cookies": raw_cookies,
            "final_url": resp.url,
            "status_code": resp.status_code,
            "error": None,
        }
    except requests.exceptions.RequestException as e:
        return {"error": str(e)}


def check_https_redirect(url: str, timeout: int = 10) -> bool:
    parsed = urlparse(url)
    http_url = url.replace("https://", "http://", 1) if parsed.scheme == "https" else url
    try:
        resp = requests.get(http_url, timeout=timeout, allow_redirects=True)
        return resp.url.startswith("https://")
    except requests.exceptions.RequestException:
        return False


def analyze_cookies(raw_cookies: list) -> dict:
    """Parse Set-Cookie lines and check for Secure, HttpOnly, SameSite flags."""
    cookies = []
    for line in raw_cookies:
        parts = [p.strip() for p in line.split(";")]
        name = parts[0].split("=", 1)[0]
        attrs = parts[1:]
        attrs_lower = [a.lower() for a in attrs]

        has_secure = any(a == "secure" for a in attrs_lower)
        has_httponly = any(a == "httponly" for a in attrs_lower)
        samesite_val = None
        for a in attrs:
            if a.lower().startswith("samesite"):
                samesite_val = a.split("=", 1)[1].strip() if "=" in a else "(no value)"

        cookies.append({
            "name": name,
            "secure": has_secure,
            "httponly": has_httponly,
            "samesite": samesite_val,
        })

    if not cookies:
        return {"cookies": [], "points": COOKIE_POINTS, "max_points": COOKIE_POINTS}

    per_cookie_max = 3
    total = sum(int(c["secure"]) + int(c["httponly"]) + int(c["samesite"] is not None) for c in cookies)
    points = round((total / (per_cookie_max * len(cookies))) * COOKIE_POINTS)
    return {"cookies": cookies, "points": points, "max_points": COOKIE_POINTS}


def score_headers(headers) -> dict:
    results = {}
    for name, rule in SECURITY_HEADERS.items():
        value = headers.get(name)
        passed = rule["check"](value)
        results[name] = {
            "present": value is not None,
            "value": value,
            "passed": passed,
            "points": rule["points"] if passed else 0,
            "max_points": rule["points"],
            "description": rule["description"],
        }
    return results


def grade_from_score(score: int, max_score: int) -> str:
    pct = (score / max_score) * 100
    if pct >= 90:
        return "A"
    elif pct >= 75:
        return "B"
    elif pct >= 60:
        return "C"
    elif pct >= 40:
        return "D"
    else:
        return "F"


def scan_url(url: str) -> dict:
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    fetch_result = fetch_headers(url)
    if fetch_result.get("error"):
        return {"url": url, "error": fetch_result["error"]}

    header_results = score_headers(fetch_result["headers"])
    cookie_results = analyze_cookies(fetch_result.get("raw_cookies", []))
    https_ok = check_https_redirect(url)

    header_score = sum(r["points"] for r in header_results.values())
    max_score = (
        sum(r["max_points"] for r in header_results.values())
        + HTTPS_REDIRECT_POINTS
        + COOKIE_POINTS
    )
    total_score = header_score + (HTTPS_REDIRECT_POINTS if https_ok else 0) + cookie_results["points"]
    grade = grade_from_score(total_score, max_score)

    return {
        "url": url,
        "header_results": header_results,
        "cookie_results": cookie_results,
        "https_redirect": https_ok,
        "score": total_score,
        "max_score": max_score,
        "grade": grade,
        "error": None,
    }


def main():
    if len(sys.argv) < 2:
        print("Usage: python header_scanner.py <url>")
        sys.exit(1)

    result = scan_url(sys.argv[1])
    if result.get("error"):
        print(f"Error scanning {result['url']}: {result['error']}")
        return

    print(f"\n{result['url']}")
    print(f"Score: {result['score']}/{result['max_score']}   Grade: {result['grade']}")
    print(f"HTTPS redirect: {'YES' if result['https_redirect'] else 'NO'}\n")

    print("Security header check:")
    for name, r in result["header_results"].items():
        status = "PASS" if r["passed"] else ("PRESENT BUT WEAK" if r["present"] else "MISSING")
        print(f"  {name}: {status} (value: {r['value']})")

    cookies = result["cookie_results"]["cookies"]
    if cookies:
        print(f"\nCookie flags ({result['cookie_results']['points']}/{result['cookie_results']['max_points']} pts):")
        for c in cookies:
            print(f"  {c['name']}: Secure={c['secure']} HttpOnly={c['httponly']} SameSite={c['samesite']}")
    else:
        print("\nNo cookies set by this site.")


if __name__ == "__main__":
    main()