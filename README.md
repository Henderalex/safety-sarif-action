# Safety → SARIF Action

Convert Safety JSON output into SARIF 2.1.0 for GitHub Code Scanning.

## Usage

Local conversion:

```bash
uv sync
uv run python converter.py --input safety-output.json --output result.sarif --manifest requirements.txt
```

In a workflow:

```yaml
- name: Run Safety
  run: safety scan --file requirements.txt --output json --continue-on-error > safety-output.json

- name: Convert to SARIF
  uses: Henderalex/safety-sarif-action@v1
  with:
    input_file: safety-output.json
    output_file: safety.sarif
    manifest: requirements.txt

- name: Upload
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: safety.sarif
```

## Inputs
- `input_file` (required): Path to Safety JSON output.
- `output_file` (optional): Destination SARIF path (default `output.sarif`).
- `manifest` (optional): Dependency manifest for location hints (e.g., `requirements.txt`).
- `tool` (optional): Tool label, default `safety`.

## Outputs
- `sarif_file`: Path to generated SARIF.
- `findings_count`: Number of findings emitted.

## Severity mapping
- critical/high → SARIF `error`
- medium/moderate → `warning`
- low/info → `note`
- CVSS: ≥7.0 `error`, 4.0–6.9 `warning`, >0 `note`

## Examples
See `examples/sample-input.json` and `examples/sample-output.sarif` for reference shapes.

If the input contains no findings, SARIF is emitted with an empty `runs[0].results` list.
