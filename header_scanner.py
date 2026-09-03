#!/usr/bin/env python3
"""
Website Security Header Scanner
Checks a site's HTTP response headers against security best practices
and produces a graded report.
"""

import argparse
import csv
import sys
from urllib.parse import urlparse

import requests
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()

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

HTTPS_REDIRECT_POINTS = 20  # separately checked, not a header dict entry
COOKIE_POINTS = 15  # separately checked, split across all cookies found


def fetch_headers(url: str, timeout: int = 10) -> dict:
    """Fetch response headers for a URL, following redirects."""
    try:
        resp = requests.get(url, timeout=timeout, allow_redirects=True)
        # response.headers merges repeated headers with commas, which mangles
        # Set-Cookie (commas appear inside Expires=... dates). Pull the raw,
        # un-merged Set-Cookie lines instead via the underlying urllib3 response.
        try:
            raw_cookies = resp.raw.headers.getlist("Set-Cookie")
        except Exception:
            raw_cookies = []
        return {
            "headers": resp.headers,
            "raw_cookies": raw_cookies,
            "final_url": resp.url,
            "status_code": resp.status_code,
            "history": resp.history,
            "error": None,
        }
    except requests.exceptions.RequestException as e:
        return {"error": str(e)}


def check_https_redirect(url: str, timeout: int = 10) -> bool:
    """Check whether the HTTP version of the site redirects to HTTPS."""
    parsed = urlparse(url)
    if parsed.scheme == "https":
        http_url = url.replace("https://", "http://", 1)
    else:
        http_url = url

    try:
        resp = requests.get(http_url, timeout=timeout, allow_redirects=True)
        return resp.url.startswith("https://")
    except requests.exceptions.RequestException:
        return False


def analyze_cookies(raw_cookies: list) -> dict:
    """
    Parse raw Set-Cookie header lines and check each cookie for the three
    key security flags: Secure, HttpOnly, and SameSite.
    """
    cookies = []
    for line in raw_cookies:
        # First segment before ';' is "name=value"; rest are attributes
        parts = [p.strip() for p in line.split(";")]
        name = parts[0].split("=", 1)[0]
        attrs = parts[1:]
        attrs_lower = [a.lower() for a in attrs]

        has_secure = any(a == "secure" for a in attrs_lower)
        has_httponly = any(a == "httponly" for a in attrs_lower)
        samesite_val = None
        for a in attrs:
            if a.lower().startswith("samesite"):
                if "=" in a:
                    samesite_val = a.split("=", 1)[1].strip()
                else:
                    samesite_val = "(no value)"

        cookies.append({
            "name": name,
            "secure": has_secure,
            "httponly": has_httponly,
            "samesite": samesite_val,  # None if attribute absent entirely
            "raw": line,
        })

    if not cookies:
        # No cookies set at all - nothing to penalize, treat as full marks
        return {"cookies": [], "points": COOKIE_POINTS, "max_points": COOKIE_POINTS}

    # Average the per-cookie compliance across all cookies set by the site
    per_cookie_max = 3  # Secure + HttpOnly + SameSite
    total = 0
    for c in cookies:
        total += int(c["secure"]) + int(c["httponly"]) + int(c["samesite"] is not None)

    points = round((total / (per_cookie_max * len(cookies))) * COOKIE_POINTS)
    return {"cookies": cookies, "points": points, "max_points": COOKIE_POINTS}


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
    """Run a full scan on a single URL and return a results dict."""
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    fetch_result = fetch_headers(url)
    if fetch_result.get("error"):
        return {"url": url, "error": fetch_result["error"]}

    headers = fetch_result["headers"]
    header_results = score_headers(headers)
    cookie_results = analyze_cookies(fetch_result.get("raw_cookies", []))

    https_ok = check_https_redirect(url)
    header_score = sum(r["points"] for r in header_results.values())
    max_score = (
        sum(r["max_points"] for r in header_results.values())
        + HTTPS_REDIRECT_POINTS
        + COOKIE_POINTS
    )
    total_score = (
        header_score
        + (HTTPS_REDIRECT_POINTS if https_ok else 0)
        + cookie_results["points"]
    )
    grade = grade_from_score(total_score, max_score)

    return {
        "url": url,
        "final_url": fetch_result["final_url"],
        "status_code": fetch_result["status_code"],
        "header_results": header_results,
        "cookie_results": cookie_results,
        "https_redirect": https_ok,
        "score": total_score,
        "max_score": max_score,
        "grade": grade,
        "error": None,
    }


# ---------------------------------------------------------------------------
# Output formatting
# ---------------------------------------------------------------------------

GRADE_COLORS = {
    "A": "bright_green",
    "B": "green",
    "C": "yellow",
    "D": "dark_orange",
    "F": "red",
}


def print_report(result: dict, verbose: bool = True):
    if result.get("error"):
        console.print(f"[red]Error scanning {result['url']}: {result['error']}[/red]")
        return

    grade = result["grade"]
    color = GRADE_COLORS.get(grade, "white")

    console.print(Panel(
        f"[bold]{result['url']}[/bold]\n"
        f"Score: {result['score']}/{result['max_score']}   "
        f"Grade: [bold {color}]{grade}[/bold {color}]   "
        f"HTTPS redirect: {'✅' if result['https_redirect'] else '❌'}",
        title="Scan Result",
        border_style=color,
    ))

    table = Table(show_header=True, header_style="bold cyan")
    table.add_column("Header")
    table.add_column("Status")
    table.add_column("Value", overflow="fold")
    if verbose:
        table.add_column("Why it matters")

    for name, r in result["header_results"].items():
        status = "[green]✅ Pass[/green]" if r["passed"] else (
            "[yellow]⚠ Weak[/yellow]" if r["present"] else "[red]❌ Missing[/red]"
        )
        value = r["value"] if r["value"] else "-"
        row = [name, status, value]
        if verbose:
            row.append(r["description"])
        table.add_row(*row)

    console.print(table)

    print_cookie_report(result.get("cookie_results"), verbose=verbose)


def print_cookie_report(cookie_results: dict, verbose: bool = True):
    if not cookie_results:
        return

    cookies = cookie_results["cookies"]
    if not cookies:
        console.print("[dim]No cookies set by this site.[/dim]\n")
        return

    console.print(
        f"\n[bold cyan]Cookie flags[/bold cyan] "
        f"({cookie_results['points']}/{cookie_results['max_points']} pts)"
    )

    table = Table(show_header=True, header_style="bold cyan")
    table.add_column("Cookie")
    table.add_column("Secure")
    table.add_column("HttpOnly")
    table.add_column("SameSite")

    def flag(ok: bool) -> str:
        return "[green]✅[/green]" if ok else "[red]❌[/red]"

    for c in cookies:
        table.add_row(
            c["name"],
            flag(c["secure"]),
            flag(c["httponly"]),
            f"[green]{c['samesite']}[/green]" if c["samesite"] else "[red]❌[/red]",
        )

    console.print(table)

    if verbose:
        console.print(
            "[dim]Secure: cookie only sent over HTTPS. HttpOnly: blocks "
            "JavaScript access (mitigates XSS cookie theft). SameSite: "
            "restricts cross-site sending (mitigates CSRF).[/dim]\n"
        )


def write_csv(results: list, path: str):
    fieldnames = (
        ["url", "grade", "score", "max_score", "https_redirect"]
        + list(SECURITY_HEADERS.keys())
        + ["cookies_checked", "cookies_secure", "cookies_httponly", "cookies_samesite"]
    )
    with open(path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for r in results:
            if r.get("error"):
                writer.writerow({"url": r["url"], "grade": "ERROR"})
                continue
            row = {
                "url": r["url"],
                "grade": r["grade"],
                "score": r["score"],
                "max_score": r["max_score"],
                "https_redirect": r["https_redirect"],
            }
            for name, hr in r["header_results"].items():
                row[name] = "Pass" if hr["passed"] else ("Present-Weak" if hr["present"] else "Missing")

            cookies = r.get("cookie_results", {}).get("cookies", [])
            row["cookies_checked"] = len(cookies)
            row["cookies_secure"] = sum(1 for c in cookies if c["secure"])
            row["cookies_httponly"] = sum(1 for c in cookies if c["httponly"])
            row["cookies_samesite"] = sum(1 for c in cookies if c["samesite"])

            writer.writerow(row)
    console.print(f"[green]CSV report written to {path}[/green]")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Scan a website's HTTP security headers and grade its configuration."
    )
    parser.add_argument("urls", nargs="*", help="One or more URLs to scan")
    parser.add_argument("-f", "--file", help="File containing a list of URLs (one per line)")
    parser.add_argument("-o", "--output", help="Write results to a CSV file at this path")
    parser.add_argument("-q", "--quiet", action="store_true", help="Hide 'why it matters' explanations")
    args = parser.parse_args()

    urls = list(args.urls)
    if args.file:
        with open(args.file) as f:
            urls.extend(line.strip() for line in f if line.strip())

    if not urls:
        parser.error("Provide at least one URL, or use -f to supply a file of URLs.")

    all_results = []
    for url in urls:
        console.print(f"\n[bold blue]Scanning {url}...[/bold blue]")
        result = scan_url(url)
        print_report(result, verbose=not args.quiet)
        all_results.append(result)

    if args.output:
        write_csv(all_results, args.output)


if __name__ == "__main__":
    main()