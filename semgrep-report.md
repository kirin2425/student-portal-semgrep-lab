# Lab 6 - SAST Scan Report (Semgrep)

- **Tool:** Semgrep (Static Application Security Testing)
- **Target file:** `app_secure.py`
- **Scan date:** 2026-07-02 13:25
- **Total findings:** 4

## Findings by Severity

| Severity | Count |
|----------|-------|
| WARNING | 4 |

## Affected Files

- `app_secure.py` - 4 finding(s)

## Most Important Rule IDs

- `raw-html-format` (2)
- `render-template-string` (1)
- `debug-enabled` (1)

## Detailed Findings

### 1. raw-html-format  (WARNING)

- **Location:** `app_secure.py` line 276
- **Rule ID:** `python.django.security.injection.raw-html-format.raw-html-format`
- **CWE:** ["CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')"]
- **OWASP:** ['A07:2017 - Cross-Site Scripting (XSS)', 'A03:2021 - Injection', 'A05:2025 - Injection']
- **ASVS:** n/a
- **Description:** Detected user input flowing into a manually constructed HTML string. You may be accidentally bypassing secure methods of rendering HTML by manually constructing HTML and this could create a cross-site scripting vulnerability, which could let attackers steal sensitive user data. To be sure this is safe, check that the HTML is rendered safely. Otherwise, use templates (`django.shortcuts.render`) which will safely render HTML instead.
- **Remediation:** Review and remediate.

### 2. raw-html-format  (WARNING)

- **Location:** `app_secure.py` line 276
- **Rule ID:** `python.flask.security.injection.raw-html-concat.raw-html-format`
- **CWE:** ["CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')"]
- **OWASP:** ['A07:2017 - Cross-Site Scripting (XSS)', 'A03:2021 - Injection', 'A05:2025 - Injection']
- **ASVS:** n/a
- **Description:** Detected user input flowing into a manually constructed HTML string. You may be accidentally bypassing secure methods of rendering HTML by manually constructing HTML and this could create a cross-site scripting vulnerability, which could let attackers steal sensitive user data. To be sure this is safe, check that the HTML is rendered safely. Otherwise, use templates (`flask.render_template`) which will safely render HTML instead.
- **Remediation:** Review and remediate.

### 3. render-template-string  (WARNING)

- **Location:** `app_secure.py` line 277
- **Rule ID:** `python.flask.security.audit.render-template-string.render-template-string`
- **CWE:** ["CWE-96: Improper Neutralization of Directives in Statically Saved Code ('Static Code Injection')"]
- **OWASP:** ['A03:2021 - Injection', 'A05:2025 - Injection']
- **ASVS:** n/a
- **Description:** Found a template created with string formatting. This is susceptible to server-side template injection and cross-site scripting attacks.
- **Remediation:** Replace render_template_string(user_input) with render_template() using a static file; pass data as context so Jinja2 auto-escapes it.

### 4. debug-enabled  (WARNING)

- **Location:** `app_secure.py` line 283
- **Rule ID:** `python.flask.security.audit.debug-enabled.debug-enabled`
- **CWE:** ['CWE-489: Active Debug Code']
- **OWASP:** A06:2017 - Security Misconfiguration
- **ASVS:** n/a
- **Description:** Detected Flask app with debug=True. Do not deploy to production with this flag enabled as it will leak sensitive information. Instead, consider using Flask configuration variables or setting 'debug' using system environment variables.
- **Remediation:** Set debug=False (or remove the argument) outside local development; never expose the Werkzeug debugger on a reachable host.

## Remediation Focus (priority order)

1. Fix WARNING-level injection/misconfig issues first (SSTI via render_template_string, debug mode).
2. Harden configuration (enforce a strong SECRET_KEY).
3. Remove raw HTML string building in favour of templates.
