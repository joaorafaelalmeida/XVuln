#!/usr/bin/env python3
"""
filter_reports.py
-----------------
Filters and summarizes scanner reports for sending to LLaMA.
- Semgrep: keeps only 'error' level findings
- ZAP: keeps 'error' and 'warning' (discards 'note' and 'none')
- Trivy: keeps all (small file)
- Falco/Nmap: reads directly (small files)

Output: Reports/filtered/ folder with simplified versions
"""

import json
import os
import sys
from pathlib import Path

REPORTS_DIR = Path.cwd() / "reports"
FILTERED_DIR = REPORTS_DIR / "filtered"
FILTERED_DIR.mkdir(exist_ok=True)

def load_json(path):
    with open(path) as f:
        return json.load(f)

def save_json(data, path):
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
    size_kb = os.path.getsize(path) / 1024
    print(f"  ✅ Saved: {path.name} ({size_kb:.0f} KB)")

def summarize_sarif_finding(result, rules_map):
    """Converts a SARIF result into a clean, readable dictionary."""
    rule_id = result.get("ruleId", "unknown")
    rule = rules_map.get(rule_id, {})
    
    locations = result.get("locations", [])
    location_str = "N/A"
    if locations:
        loc = locations[0]
        phys = loc.get("physicalLocation", {})
        uri = phys.get("artifactLocation", {}).get("uri", "")
        region = phys.get("region", {})
        line = region.get("startLine", "")
        location_str = f"{uri}:{line}" if uri else "N/A"
    
    message = result.get("message", {}).get("text", "")
    # Truncates very long messages
    if len(message) > 300:
        message = message[:300] + "..."
    
    short_desc = rule.get("shortDescription", {}).get("text", rule_id)
    level = rule.get("defaultConfiguration", {}).get("level", result.get("level", "warning"))
    
    tags = rule.get("properties", {}).get("tags", [])
    cwe = next((t for t in tags if t.startswith("CWE-")), "")
    owasp = next((t for t in tags if t.startswith("OWASP-")), "")
    
    help_uri = rule.get("helpUri", "")
    
    return {
        "rule_id": rule_id,
        "level": level,
        "title": short_desc,
        "location": location_str,
        "message": message,
        "cwe": cwe,
        "owasp": owasp,
        "reference": help_uri
    }

# ─────────────────────────────────────────────
# 1. SEMGREP — filter 'error' only
# ─────────────────────────────────────────────
print("\n📂 Processing Semgrep...")
semgrep_files = list(REPORTS_DIR.glob("*semgrep*.sarif"))
if semgrep_files:
    data = load_json(semgrep_files[0])
    filtered_findings = []
    
    for run in data.get("runs", []):
        rules_map = {r["id"]: r for r in run.get("tool", {}).get("driver", {}).get("rules", [])}
        for result in run.get("results", []):
            rule_id = result.get("ruleId", "")
            rule = rules_map.get(rule_id, {})
            level = rule.get("defaultConfiguration", {}).get("level", result.get("level", "warning"))
            if level == "error":
                filtered_findings.append(summarize_sarif_finding(result, rules_map))
    
    output = {
        "scanner": "semgrep",
        "filter": "error-level only",
        "total_before_filter": sum(len(run.get("results", [])) for run in data.get("runs", [])),
        "total_after_filter": len(filtered_findings),
        "findings": filtered_findings
    }
    save_json(output, FILTERED_DIR / "semgrep_filtered.json")
    print(f"  Reduced: {output['total_before_filter']} → {output['total_after_filter']} findings")
else:
    print("  ⚠️  Semgrep file not found")

# ─────────────────────────────────────────────
# 2. ZAP — filter 'error' and 'warning'
# ─────────────────────────────────────────────
print("\n📂 Processing ZAP...")
zap_files = list(REPORTS_DIR.glob("*zap*.json"))
if zap_files:
    data = load_json(zap_files[0])
    filtered_findings = []
    
    for run in data.get("runs", []):
        rules_map = {r["id"]: r for r in run.get("tool", {}).get("driver", {}).get("rules", [])}
        for result in run.get("results", []):
            level = result.get("level", "none")
            if level in ("error", "warning"):
                filtered_findings.append(summarize_sarif_finding(result, rules_map))
    
    total = sum(len(run.get("results", [])) for run in data.get("runs", []))
    output = {
        "scanner": "zap",
        "filter": "error and warning only",
        "total_before_filter": total,
        "total_after_filter": len(filtered_findings),
        "findings": filtered_findings
    }
    save_json(output, FILTERED_DIR / "zap_filtered.json")
    print(f"  Reduced: {total} → {len(filtered_findings)} findings")
else:
    print("  ⚠️  ZAP file not found")

# ─────────────────────────────────────────────
# 3. TRIVY — all findings (small file)
# ─────────────────────────────────────────────
print("\n📂 Processing Trivy...")
trivy_files = list(REPORTS_DIR.glob("*trivy*.sarif"))
if trivy_files:
    data = load_json(trivy_files[0])
    all_findings = []
    
    for run in data.get("runs", []):
        rules_map = {r["id"]: r for r in run.get("tool", {}).get("driver", {}).get("rules", [])}
        for result in run.get("results", []):
            all_findings.append(summarize_sarif_finding(result, rules_map))
    
    output = {
        "scanner": "trivy",
        "filter": "all findings",
        "total_findings": len(all_findings),
        "findings": all_findings
    }
    save_json(output, FILTERED_DIR / "trivy_filtered.json")
else:
    print("  ⚠️  Trivy file not found")

# ─────────────────────────────────────────────
# 4. FALCO — direct summary
# ─────────────────────────────────────────────
print("\n📂 Processing Falco...")
falco_files = list(REPORTS_DIR.glob("*falco*.sarif"))
if falco_files:
    with open(falco_files[0]) as f:
        content = f.read()
    # Falco can be JSON lines or JSON object
    try:
        falco_data = json.loads(content)
        # It's SARIF
        for run in falco_data.get("runs", []):
            rules_map = {r["id"]: r for r in run.get("tool", {}).get("driver", {}).get("rules", [])}
            findings = [summarize_sarif_finding(r, rules_map) for r in run.get("results", [])]
        output = {"scanner": "falco", "findings": findings}
    except:
        # It's JSON lines
        findings = []
        for line in content.strip().split("\n"):
            try:
                findings.append(json.loads(line))
            except:
                pass
        output = {"scanner": "falco", "raw_findings": findings}
    save_json(output, FILTERED_DIR / "falco_filtered.json")
else:
    # Try JSON format (non-SARIF)
    falco_json_files = list(REPORTS_DIR.glob("*falco*"))
    if falco_json_files:
        with open(falco_json_files[0]) as f:
            content = f.read()
        findings = []
        for line in content.strip().split("\n"):
            try:
                obj = json.loads(line)
                findings.append({
                    "rule": obj.get("rule", ""),
                    "priority": obj.get("priority", ""),
                    "output": obj.get("output", "")[:300],
                    "tags": obj.get("tags", []),
                    "time": obj.get("time", "")
                })
            except:
                pass
        output = {"scanner": "falco", "findings": findings}
        save_json(output, FILTERED_DIR / "falco_filtered.json")

# ─────────────────────────────────────────────
# 5. NMAP — summary from .nmap (readable text)
# ─────────────────────────────────────────────
print("\n📂 Processing Nmap...")
nmap_files = list(REPORTS_DIR.glob("*.nmap"))
if nmap_files:
    with open(nmap_files[0]) as f:
        nmap_text = f.read()
    output = {
        "scanner": "nmap",
        "raw_output": nmap_text
    }
    save_json(output, FILTERED_DIR / "nmap_filtered.json")
    print(f"  ✅ Saved: nmap_filtered.json")
else:
    print("  ⚠️  Nmap file not found")

# ─────────────────────────────────────────────
# Final summary
# ─────────────────────────────────────────────
print("\n" + "="*50)
print("✅ Filtering complete!")
print(f"📁 Filtered files in: {FILTERED_DIR}")
print()
for f in sorted(FILTERED_DIR.glob("*.json")):
    size_kb = f.stat().st_size / 1024
    print(f"  {f.name}: {size_kb:.0f} KB")
print()
print("➡️  Next step: run ./run_analysis.sh")