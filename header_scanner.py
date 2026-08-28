#!/usr/bin/env python3
"""
Website Security Header Scanner
Fetches HTTP response headers for a given URL and displays them raw.
"""

import sys
import requests


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
    print("Raw headers:")
    for k, v in result["headers"].items():
        print(f"  {k}: {v}")


if __name__ == "__main__":
    main()