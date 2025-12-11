#!/usr/bin/env python3
"""Converter: Safety -> SARIF 2.1.0.

Transforms Safety JSON output (from `safety scan --output json`) into SARIF that
GitHub Code Scanning can ingest.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"

SEVERITY_TO_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "moderate": "warning",
    "low": "note",
    "info": "note",
    "informational": "note",
}

def _load_safety_items(data) -> List[Dict]:
    """Return the list of vulnerability items from Safety JSON regardless of shape."""
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        if isinstance(data.get("vulnerabilities"), list):
            return data["vulnerabilities"]
        if isinstance(data.get("vulnerabilities"), dict):
            return list(data["vulnerabilities"].values())
        # Newer Safety versions may nest under "issues" or other keys.
        for val in data.values():
            if isinstance(val, list) and val and isinstance(val[0], dict):
                return val
    return []

def _to_level(severity: Optional[str], cvss_score: Optional[float]) -> str:
    if severity:
        sev = severity.strip().lower()
        if sev in SEVERITY_TO_LEVEL:
            return SEVERITY_TO_LEVEL[sev]
    if cvss_score is not None:
        if cvss_score >= 7.0:
            return "error"
        if cvss_score >= 4.0:
            return "warning"
        if cvss_score > 0:
            return "note"
    return "warning"

def _find_manifest_line(manifest: Optional[Path], package_name: str) -> Optional[int]:
    """Best-effort: find the first line in the manifest matching the package."""
    if not manifest or not manifest.exists():
        return None
    pkg = package_name.lower()
    try:
        for idx, line in enumerate(manifest.read_text(encoding="utf-8").splitlines(), start=1):
            stripped = line.split("#", 1)[0].strip().lower()
            if stripped.startswith(pkg):
                return idx
    except Exception:
        return None
    return None

def _build_rule(entry: Dict) -> Dict:
    vuln_id = str(entry.get("vuln_id") or entry.get("id") or entry.get("advisory_id") or "SAFETY-UNKNOWN")
    name = entry.get("package_name") or entry.get("name") or vuln_id
    advisory = entry.get("advisory") or entry.get("description") or "Dependency vulnerability"
    cwe = entry.get("cwe_ids") or entry.get("cwe") or []
    cve = entry.get("cve")
    props = {"tags": ["security", "dependency"], "precision": "high"}
    if entry.get("cvss_score") is not None:
        props["security-severity"] = str(entry["cvss_score"])
    if cwe:
        props["cwe"] = cwe
    if cve:
        props["cve"] = cve
    return {
        "id": vuln_id,
        "name": name,
        "shortDescription": {"text": advisory[:120] if len(advisory) > 120 else advisory},
        "fullDescription": {"text": advisory},
        "help": {"text": entry.get("solution") or advisory},
        "properties": props,
    }

def _build_result(entry: Dict, tool_name: str, manifest: Optional[Path]) -> Tuple[str, Dict]:
    pkg = entry.get("package_name") or entry.get("name") or "unknown"
    ver = entry.get("installed_version") or entry.get("version") or ""
    advisory = entry.get("advisory") or entry.get("description") or "Dependency vulnerability detected."
    vuln_id = str(entry.get("vuln_id") or entry.get("id") or entry.get("advisory_id") or "SAFETY-UNKNOWN")
    severity = entry.get("severity")
    cvss = None
    try:
        cvss = float(entry["cvss_score"]) if entry.get("cvss_score") is not None else None
    except (TypeError, ValueError):
        cvss = None
    level = _to_level(severity, cvss)

    locations: List[Dict] = []
    if manifest:
        location: Dict = {
            "physicalLocation": {
                "artifactLocation": {"uri": manifest.as_posix()},
            }
        }
        line_no = _find_manifest_line(manifest, pkg)
        if line_no:
            location["physicalLocation"]["region"] = {
                "startLine": line_no,
                "endLine": line_no,
            }
        locations.append(location)

    message_text = f"{pkg} {ver}: {advisory}"
    result = {
        "ruleId": vuln_id,
        "level": level,
        "message": {"text": message_text},
        "locations": locations,
        "properties": {
            "package": pkg,
            "version": ver,
            "tool": tool_name,
        },
    }
    return vuln_id, result

def safety_json_to_sarif(safety_json, *, tool_name: str, manifest_path: Optional[Path]) -> Dict:
    items = _load_safety_items(safety_json)
    rules: Dict[str, Dict] = {}
    results: List[Dict] = []

    for entry in items:
        rule_id, result = _build_result(entry, tool_name, manifest_path)
        results.append(result)
        if rule_id not in rules:
            rules[rule_id] = _build_rule(entry)

    sarif = {
        "version": SARIF_VERSION,
        "$schema": SARIF_SCHEMA,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": tool_name,
                        "informationUri": "https://github.com/pyupio/safety",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }
    return sarif

def convert_file(input_path: Path, output_path: Path, *, tool_name: str, manifest_path: Optional[Path]) -> int:
    data = json.loads(input_path.read_text(encoding="utf-8"))
    sarif = safety_json_to_sarif(data, tool_name=tool_name, manifest_path=manifest_path)
    output_path.write_text(json.dumps(sarif, indent=2), encoding="utf-8")
    if sarif.get("runs") and sarif["runs"][0].get("results"):
        return len(sarif["runs"][0]["results"])
    return 0

def main():
    ap = argparse.ArgumentParser(description="Convert Safety JSON to SARIF 2.1.0")
    ap.add_argument("--input", "-i", required=True, help="Input JSON file path (Safety output).")
    ap.add_argument("--output", "-o", required=False, default="output.sarif", help="Output SARIF file.")
    ap.add_argument("--tool", required=False, default="safety", help="Tool name to record in SARIF.")
    ap.add_argument(
        "--manifest",
        required=False,
        default=None,
        help="Path to the manifest (e.g., requirements.txt) for location hints.",
    )
    args = ap.parse_args()

    inp = Path(args.input)
    out = Path(args.output)
    manifest = Path(args.manifest) if args.manifest else None

    if not inp.exists():
        print(f"Input file not found: {inp}", file=sys.stderr)
        sys.exit(2)

    try:
        count = convert_file(inp, out, tool_name=args.tool, manifest_path=manifest)
        print(count)
        sys.exit(0)
    except json.JSONDecodeError as exc:
        print(f"Invalid JSON input: {exc}", file=sys.stderr)
        sys.exit(2)
    except Exception as exc:
        print(f"Conversion failed: {exc}", file=sys.stderr)
        sys.exit(3)

if __name__ == "__main__":
    main()
