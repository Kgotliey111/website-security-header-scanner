# Website Security Header Scanner

## Overview
A Python command-line tool that scans a website's HTTP response headers
and cookies, checking them against security best practices, and produces
a graded (A-F) report — similar to tools like securityheaders.com.

**Goal:** demonstrate practical understanding of web security configuration
by building a tool that identifies real, common misconfigurations on live
websites — no exploitation involved, only publicly visible HTTP responses.

## What It Checks

**Security headers:**
- `Strict-Transport-Security` (HSTS) — forces HTTPS
- `Content-Security-Policy` (CSP) — mitigates XSS/injection attacks
- `X-Frame-Options` — prevents clickjacking
- `X-Content-Type-Options` — prevents MIME-sniffing attacks
- `Referrer-Policy` — controls referrer info leakage
- `Permissions-Policy` — restricts browser feature access

**Other checks:**
- HTTP → HTTPS redirect
- Cookie security flags: `Secure`, `HttpOnly`, `SameSite`

Each check is weighted and combined into an overall score and A-F grade.

## Installation
```bash
pip install -r requirements.txt
```

## Usage
```bash
# Scan a single site
python3 header_scanner.py github.com

# Scan multiple sites
python3 header_scanner.py github.com wikipedia.org example.com

# Scan a list of sites from a file, export results to CSV
python3 header_scanner.py -f sites.txt -o results.csv

# Quiet mode (hide "why it matters" explanations)
python3 header_scanner.py -q github.com
```

## Example Output
```
Scan Result
https://github.com
Score: 90/115   Grade: A   HTTPS redirect: ✅

Header                      Status    Value
Strict-Transport-Security   ✅ Pass   max-age=31536000; includeSubdomains
Content-Security-Policy     ✅ Pass   default-src 'none'; ...
X-Frame-Options              ✅ Pass   ...
...

Cookie flags (13/15 pts)
Cookie       Secure   HttpOnly   SameSite
_gh_sess     ✅       ✅         Lax
_octo        ✅       ❌         Lax
logged_in    ✅       ✅         Lax
```

## Repository Structure
```
header_scanner.py    main script
requirements.txt     Python dependencies
docs/                test notes and final report
screenshots/          evidence of scans run against real sites
README.md            this file
```

## Key Findings (from testing)
- Well-established sites (e.g. GitHub) generally score highly, but still
  have gaps — GitHub's `_octo` cookie is missing `HttpOnly`, for example.
- Several major sites do not set any cookies via the HTTP `Set-Cookie`
  header on an anonymous homepage request — many rely on JavaScript to
  set cookies instead, which this scanner (and similar header-based
  tools) cannot see. This is a real limitation of any purely
  HTTP-header-based scanner.
- Grades varied significantly across sites tested, showing that security
  header adoption is inconsistent even among popular websites.

## Ethics & Scope
This tool only reads publicly available HTTP response headers — the same
information any browser receives when visiting a site. It performs no
exploitation, authentication bypass, or unauthorized access of any kind,
and is safe to run against any public website.

## Author
[Your name] — [Course / elective name] — [Date]
