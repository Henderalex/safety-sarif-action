#!/usr/bin/env python3
"""Converter: safety -> SARIF

This script accepts Safety JSON output (or plain text) and converts it
into a minimal SARIF 2.1.0 structure suitable for GitHub Code Scanning.

Supported input: safety JSON output (the format produced by `safety -f json`).
If the input contains no findings, the SARIF will contain an empty runs[0].results list.
"""
import argparse
import json
import sys
from pathlib import Path

SARIF_VERSION = "2.1.0"

def safety_json_to_sarif(safety_json):
    # safety_json: parsed JSON from safety (list of vulnerabilities or dict with 'vulnerabilities')
    findings = []
    # Safety's JSON format may be a list of issues, or a dict depending on version
    items = []
    if isinstance(safety_json, dict):
        # some wrappers produce {'vulnerabilities': [...]} or {'vulnerabilities': {...}}
        if "vulnerabilities" in safety_json:
            maybe = safety_json["vulnerabilities"]
            if isinstance(maybe, list):
                items = maybe
            elif isinstance(maybe, dict):
                # map values
                items = list(maybe.values())
        elif "dependencies" in safety_json and "vulnerabilities" in safety_json:
            items = safety_json.get("vulnerabilities", [])
        else:
            # Unknown dict shape: try to find lists of dicts
            for v in safety_json.values():
                if isinstance(v, list):
                    items = v
                    break
    elif isinstance(safety_json, list):
        items = safety_json

    for it in items:
        # Each issue typically has: 'package_name', 'installed_version', 'advisory', 'vuln_id'
        pkg = it.get("package_name") or it.get("name") or "unknown"
        ver = it.get("installed_version") or it.get("version") or ""
        advisory = it.get("advisory") or it.get("description") or ""
        vuln_id = it.get("vuln_id") or it.get("id") or it.get("advisory_id") or "SAFETY-UNKNOWN"

        result = {
            "ruleId": str(vuln_id),
            "level": "warning",
            "message": {"text": f"{pkg} {ver}: {advisory}"},
            "locations": [],
        }
        findings.append(result)

    sarif = {
        "version": SARIF_VERSION,
        "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.5.json",
        "runs": [
            {
                "tool": {"driver": {"name": "safety", "informationUri": "https://pyup.io/safety/"}},
                "results": findings,
            }
        ],
    }
    return sarif

def convert_file(input_path: Path, output_path: Path):
    text = input_path.read_text(encoding="utf-8")
    # try parse JSON
    try:
        parsed = json.loads(text)
    except Exception:
        # No JSON: produce sarif with no results
        parsed = []

    sarif = safety_json_to_sarif(parsed)
    output_path.write_text(json.dumps(sarif, indent=2), encoding="utf-8")
    return len(sarif["runs"][0]["results"]) if sarif and sarif.get("runs") else 0

def main():
    ap = argparse.ArgumentParser(description="Convert Safety JSON to SARIF 2.1.0")
    ap.add_argument("--input", "-i", required=True, help="Input file path")
    ap.add_argument("--output", "-o", required=False, default="output.sarif", help="Output SARIF file")
    ap.add_argument("--tool", required=False, default="safety", help="Tool name (for future use)")
    args = ap.parse_args()

    inp = Path(args.input)
    out = Path(args.output)
    if not inp.exists():
        print(f"Input file not found: {inp}", file=sys.stderr)
        sys.exit(2)

    try:
        count = convert_file(inp, out)
        print(count)
        sys.exit(0)
    except Exception as e:
        print(f"Conversion failed: {e}", file=sys.stderr)
        sys.exit(3)

if __name__ == "__main__":
    main()
