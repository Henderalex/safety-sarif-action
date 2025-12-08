# safety → SARIF

Small converter that turns Safety JSON output into a minimal SARIF 2.1.0 file suitable for GitHub Code Scanning.

Usage:

```
uv sync;

uv run python3 converter.py --input safety-output.json --output result.sarif;
```

If the input contains no findings, an empty SARIF with zero results is produced.
