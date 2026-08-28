#!/usr/bin/env python3
"""
Website Security Header Scanner
Fetches HTTP response headers and checks them against security best practices.
"""

import sys
import requests

# ---------------------------------------------------------------------------
# Header definitions: what we check for, why it matters, and how to score it
# ---------------------------------------------------------------------------

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


def fetch_headers(url: str, timeout: int = 10) -> dict:
    """Fetch response headers for a URL, following redirects."""
    try:
        resp = requests.get(url, timeout=timeout, allow_redirects=True)
        return {
            "headers": resp.headers,
            "final_url": resp.url,
            "status_code": resp.status_code,
            "error": None,
        }
    except requests.exceptions.RequestException as e:
        return {"error": str(e)}


def score_headers(headers) -> dict:
    """Evaluate headers against SECURITY_HEADERS, return per-header results."""
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


def main():
    if len(sys.argv) < 2:
        print("Usage: python header_scanner.py <url>")
        sys.exit(1)

    url = sys.argv[1]
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    result = fetch_headers(url)
    if result.get("error"):
        print(f"Error fetching {url}: {result['error']}")
        return

    print(f"Status code: {result['status_code']}")
    print(f"Final URL: {result['final_url']}\n")

    header_results = score_headers(result["headers"])
    print("Security header check:")
    for name, r in header_results.items():
        status = "PASS" if r["passed"] else ("PRESENT BUT WEAK" if r["present"] else "MISSING")
        print(f"  {name}: {status} (value: {r['value']})")


if __name__ == "__main__":
    main()