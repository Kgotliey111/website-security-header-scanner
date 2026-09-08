# Final Report: Website Security Header Scanner

**Author:** Seroba Kgotlelelo Makoa
**Course:** Cyber Security
**Date:** 08/09/2026

## 1. Executive Summary
This project is a Python command-line tool that scans any public website's
HTTP response headers and cookies, checks them against established web
security best practices, and produces a graded (A-F) report. The goal was
to demonstrate practical understanding of web security configuration by
building something that identifies real, common misconfigurations on live
websites — using only publicly visible HTTP responses, with no
exploitation involved.

## 2. What the Tool Checks

**Security headers (6 checked, weighted by importance):**
- `Strict-Transport-Security` (HSTS) — forces HTTPS, preventing downgrade
  attacks and cookie hijacking over plain HTTP
- `Content-Security-Policy` (CSP) — restricts which sources scripts,
  styles, and images can load from, mitigating XSS and injection attacks
- `X-Frame-Options` — prevents the site being embedded in an iframe,
  protecting against clickjacking
- `X-Content-Type-Options` — stops browsers from MIME-sniffing responses,
  blocking certain drive-by download attacks
- `Referrer-Policy` — controls how much referrer information leaks when
  navigating away from the site
- `Permissions-Policy` — restricts which browser features (camera, mic,
  geolocation) a page can access

**Other checks:**
- Whether HTTP requests redirect to HTTPS
- Cookie security flags: `Secure`, `HttpOnly`, and `SameSite`

Each check is weighted by security importance and combined into an
overall score out of 115, mapped to an A-F letter grade.

## 3. Architecture

The tool is a single Python script (`header_scanner.py`) built around a
small number of focused functions:

- `fetch_headers()` — makes the HTTP request and retrieves headers/cookies
- `score_headers()` — evaluates each header against the ruleset
- `check_https_redirect()` — separately verifies HTTP-to-HTTPS redirection
- `analyze_cookies()` — parses raw `Set-Cookie` lines and checks security
  flags per cookie
- `scan_url()` — orchestrates a full scan and computes the final grade
- `print_report()` — renders a formatted, color-coded report using the
  `rich` library
- `main()` — the CLI entry point, built with `argparse`, supporting
  single or multiple URLs, file input, CSV export, and a quiet mode

## 4. Development Process

The project was built incrementally over three days, with each stage
committed to git separately to show genuine progressive development:

- **Day 1:** core HTTP fetching, then security header pass/fail checks
- **Day 2:** A-F scoring and grading logic, HTTPS redirect detection,
  cookie security flag analysis, and formatted colored terminal output
  using the `rich` library
- **Day 3:** a full CLI interface (multiple URLs, file input, CSV export,
  quiet mode), testing against multiple real sites, and this report

## 5. Test Results

The scanner was tested against four real, publicly accessible websites.

| Site | Grade | Score | Key findings |
|------|-------|-------|---------------|
| github.com | B | 103/115 | All headers pass except Permissions-Policy (missing). HTTPS redirect works. Cookie `_octo` is missing HttpOnly. |
| stackoverflow.com | B | 100/115 | Strong header coverage, but Strict-Transport-Security (HSTS) is missing. Cookie flags fully compliant (15/15). |
| wikipedia.org | F | 35/115 | HTTPS redirect works, but ALL 6 security headers are missing. No cookies set on homepage. |
| example.com | F | 15/115 | No HTTPS redirect and all 6 security headers missing — worst result of the sites tested. |

## 6. Discussion

**Large platforms still have gaps.** Even well-resourced, security-conscious
sites like GitHub and Stack Overflow — both of which scored a B — have
specific, identifiable gaps: GitHub is missing the Permissions-Policy
header and has one cookie without the HttpOnly flag; Stack Overflow is
missing HSTS entirely. This shows that even mature platforms don't
achieve a perfect security header configuration.

**Popularity does not equal security header adoption.** Wikipedia, one of
the most visited websites in the world, sets none of the six security
headers checked by this tool, despite correctly redirecting HTTP to
HTTPS. This was a genuinely unexpected finding and illustrates that
traffic volume and security header hygiene are not correlated.

**A key limitation: header-based scanning can't see JavaScript-set
cookies.** During testing, several major platforms (Wikipedia, Instagram,
LinkedIn, Amazon, and others) set zero cookies via the HTTP `Set-Cookie`
header on an anonymous homepage request. Modern websites frequently set
cookies via JavaScript after the page loads rather than in the initial
HTTP response, which is invisible to any purely header-based scanner like
this one. This is an inherent limitation worth acknowledging: a "no
cookies detected" result does not necessarily mean a site sets no
cookies at all — only that none were set in the raw HTTP response.

**Grades varied significantly (F to B),** even among sites tested, showing
that security header adoption is inconsistent across the web, including
among major, well-resourced organizations.

## 7. Lessons Learned

- Building a real scanning tool surfaced genuinely interesting,
  real-world findings rather than hypothetical ones — for example, the
  specific missing `HttpOnly` flag on GitHub's `_octo` cookie was a
  finding I would not have predicted going in.
- Weighting checks by security importance (rather than treating every
  header equally) makes the resulting grade more meaningful — a missing
  CSP header, for instance, is more consequential than a missing
  Referrer-Policy, so it was weighted accordingly.
- Real-world testing exposes edge cases that don't show up in
  documentation alone, such as the JavaScript cookie-setting limitation
  discovered during testing.

## 8. Tools & References

- Python 3, `requests` (HTTP client), `rich` (terminal formatting)
- OWASP Secure Headers Project — reference for header best practices
- securityheaders.com — inspiration for the scoring/grading approach