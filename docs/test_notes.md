# Test Results

Scanner tested against 4 real, publicly accessible websites.

| Site | Grade | Score | Key findings |
|------|-------|-------|---------------|
| github.com | B | 103/115 | All headers pass except Permissions-Policy (missing). HTTPS redirect works. Cookie `_octo` is missing HttpOnly. |
| stackoverflow.com | B | 100/115 | Strong header coverage, but Strict-Transport-Security (HSTS) is missing. Cookie flags fully compliant (15/15). |
| wikipedia.org | F | 35/115 | HTTPS redirect works, but ALL 6 security headers are missing. No cookies set on homepage. |
| example.com | F | 15/115 | No HTTPS redirect and all 6 security headers missing — worst result of the sites tested. |

## Observations

- Large, security-conscious platforms (GitHub, Stack Overflow) implement most
  recommended headers, but even they have gaps — GitHub is missing
  Permissions-Policy and has one cookie without HttpOnly; Stack Overflow is
  missing HSTS entirely.
- Wikipedia, despite being one of the most visited sites in the world, sets
  none of the six security headers checked. This shows that traffic and
  popularity don't necessarily correlate with security header adoption.
- example.com, a minimal reference/demo site, unsurprisingly scored worst —
  it doesn't even redirect HTTP to HTTPS.
- Several sites set no cookies at all on an anonymous homepage GET request
  (this was also observed for other big platforms during earlier testing,
  such as Instagram, LinkedIn, Amazon). Many modern sites set cookies via
  JavaScript rather than the HTTP Set-Cookie header, which is a real
  limitation of any header-based scanner like this one — it cannot see
  cookies that are set client-side after the page loads.
- Grades varied significantly (F to B) across sites tested, showing that
  security header adoption is inconsistent even among major, well-resourced
  websites.