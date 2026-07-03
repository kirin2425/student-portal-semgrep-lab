"""
generate_report.py  --  Lab 6 Task 1
Reads semgrep-results.json and produces a clean, detailed report
(both a human-readable .md and a structured summary .json) covering:
  - total findings
  - findings by severity
  - affected files
  - most important rule IDs
  - short remediation focus per finding
"""

import json
import os
from collections import Counter
from datetime import datetime

HERE = os.path.dirname(os.path.abspath(__file__))
RAW = os.path.join(HERE, "semgrep-results.json")

SEVERITY_ORDER = {"ERROR": 0, "WARNING": 1, "INFO": 2}

REMEDIATION = {
    "render-template-string":
        "Replace render_template_string(user_input) with render_template() "
        "using a static file; pass data as context so Jinja2 auto-escapes it.",
    "debug-enabled":
        "Set debug=False (or remove the argument) outside local development; "
        "never expose the Werkzeug debugger on a reachable host.",
    "hardcoded-secret":
        "Require SECRET_KEY from the environment and fail to start if it is "
        "missing; never ship a predictable default key.",
    "raw-html-build":
        "Stop building HTML by string concatenation; render through a Jinja2 "
        "template so output is escaped.",
}


def short_id(check_id):
    return check_id.split(".")[-1]


def main():
    with open(RAW) as f:
        data = json.load(f)

    results = data.get("results", [])
    total = len(results)

    sev_counts = Counter(r["extra"]["severity"] for r in results)
    files = Counter(r["path"] for r in results)
    rule_counts = Counter(short_id(r["check_id"]) for r in results)

    findings = []
    for r in sorted(results, key=lambda x: SEVERITY_ORDER.get(
            x["extra"]["severity"], 9)):
        rid = short_id(r["check_id"])
        findings.append({
            "rule_id": r["check_id"],
            "short_rule": rid,
            "severity": r["extra"]["severity"],
            "file": r["path"],
            "line": r["start"]["line"],
            "message": " ".join(r["extra"]["message"].split()),
            "cwe": r["extra"]["metadata"].get("cwe", "n/a"),
            "owasp": r["extra"]["metadata"].get("owasp", "n/a"),
            "asvs": r["extra"]["metadata"].get("asvs", "n/a"),
            "remediation": REMEDIATION.get(rid, "Review and remediate."),
        })

    summary = {
        "scanned_at": datetime.now().strftime("%Y-%m-%d %H:%M"),
        "tool": "Semgrep (SAST)",
        "target": "app_secure.py",
        "total_findings": total,
        "by_severity": dict(sev_counts),
        "affected_files": dict(files),
        "top_rule_ids": [r for r, _ in rule_counts.most_common()],
        "findings": findings,
    }

    # ---- write structured summary JSON ----
    with open(os.path.join(HERE, "semgrep-summary.json"), "w") as f:
        json.dump(summary, f, indent=2)

    # ---- write human-readable Markdown report ----
    md = []
    md.append("# Lab 6 - SAST Scan Report (Semgrep)\n")
    md.append(f"- **Tool:** Semgrep (Static Application Security Testing)")
    md.append(f"- **Target file:** `app_secure.py`")
    md.append(f"- **Scan date:** {summary['scanned_at']}")
    md.append(f"- **Total findings:** {total}\n")

    md.append("## Findings by Severity\n")
    md.append("| Severity | Count |")
    md.append("|----------|-------|")
    for sev in ["ERROR", "WARNING", "INFO"]:
        if sev in sev_counts:
            md.append(f"| {sev} | {sev_counts[sev]} |")
    md.append("")

    md.append("## Affected Files\n")
    for fpath, c in files.items():
        md.append(f"- `{fpath}` - {c} finding(s)")
    md.append("")

    md.append("## Most Important Rule IDs\n")
    for rid, c in rule_counts.most_common():
        md.append(f"- `{rid}` ({c})")
    md.append("")

    md.append("## Detailed Findings\n")
    for i, fnd in enumerate(findings, 1):
        md.append(f"### {i}. {fnd['short_rule']}  ({fnd['severity']})\n")
        md.append(f"- **Location:** `{fnd['file']}` line {fnd['line']}")
        md.append(f"- **Rule ID:** `{fnd['rule_id']}`")
        md.append(f"- **CWE:** {fnd['cwe']}")
        md.append(f"- **OWASP:** {fnd['owasp']}")
        md.append(f"- **ASVS:** {fnd['asvs']}")
        md.append(f"- **Description:** {fnd['message']}")
        md.append(f"- **Remediation:** {fnd['remediation']}\n")

    md.append("## Remediation Focus (priority order)\n")
    md.append("1. Fix WARNING-level injection/misconfig issues first "
              "(SSTI via render_template_string, debug mode).")
    md.append("2. Harden configuration (enforce a strong SECRET_KEY).")
    md.append("3. Remove raw HTML string building in favour of templates.")
    md.append("")

    with open(os.path.join(HERE, "semgrep-report.md"), "w") as f:
        f.write("\n".join(md))

    print(f"Total findings: {total}")
    print(f"By severity: {dict(sev_counts)}")
    print(f"Affected files: {dict(files)}")
    print(f"Top rule IDs: {[r for r,_ in rule_counts.most_common()]}")
    print("Wrote: semgrep-summary.json, semgrep-report.md")


if __name__ == "__main__":
    main()
