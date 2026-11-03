"""Command-line interface for enrichment automation."""
from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path

from threatintel.engine import enrich_and_save, configured_keys
from threatintel.normalizer import IndicatorError


def read_indicators(path: Path) -> list[str]:
    if not path.exists() or not path.is_file():
        raise FileNotFoundError(f"Input file not found: {path}")
    if path.suffix.lower() == ".csv":
        with path.open("r", encoding="utf-8-sig", newline="") as handle:
            reader = csv.DictReader(handle)
            if not reader.fieldnames:
                return []
            candidates = {"indicator", "ioc", "value", "observable", "ip", "domain", "url", "hash"}
            column = next((name for name in reader.fieldnames if name.strip().lower() in candidates), reader.fieldnames[0])
            return [str(row.get(column, "")).strip() for row in reader if str(row.get(column, "")).strip()]
    return [line.strip() for line in path.read_text(encoding="utf-8-sig").splitlines() if line.strip() and not line.lstrip().startswith("#")]


def write_csv(path: Path, results: list[dict]) -> None:
    fieldnames = ["indicator", "normalized", "ioc_type", "risk_score", "verdict", "summary", "evidence", "sources"]
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for result in results:
            writer.writerow({
                "indicator": result["indicator"],
                "normalized": result["normalized"],
                "ioc_type": result["ioc_type"],
                "risk_score": result["risk_score"],
                "verdict": result["verdict"],
                "summary": result["summary"],
                "evidence": " | ".join(result["evidence"]),
                "sources": json.dumps(result["sources"], ensure_ascii=False),
            })


def main() -> int:
    parser = argparse.ArgumentParser(description="Normalize and enrich threat indicators. External lookups are disabled by default.")
    parser.add_argument("indicators", nargs="*", help="IOC values (quote URLs containing shell-sensitive characters)")
    parser.add_argument("--file", type=Path, help="Read indicators from .txt or .csv file")
    parser.add_argument("--external", action="store_true", help="Allow configured VirusTotal/AbuseIPDB lookups")
    parser.add_argument("--output", type=Path, help="Write results to a CSV file instead of the console")
    parser.add_argument("--json", action="store_true", help="Print full JSON results to stdout")
    args = parser.parse_args()

    raw_values = list(args.indicators)
    if args.file:
        try:
            raw_values.extend(read_indicators(args.file))
        except (OSError, UnicodeError) as exc:
            print(f"Input error: {exc}", file=sys.stderr)
            return 2
    raw_values = list(dict.fromkeys(v.strip() for v in raw_values if v.strip()))
    if not raw_values:
        parser.error("provide one or more indicators, or use --file path")

    keys = configured_keys()
    if args.external:
        print("External lookups enabled. Submitted indicators may be shared with third-party providers.", file=sys.stderr)
        if keys["virustotal"]:
            print("Note: VirusTotal public API users have a low request quota; large batches may be rate-limited.", file=sys.stderr)

    results = []
    for raw in raw_values:
        try:
            results.append(enrich_and_save(raw, allow_external=args.external))
        except IndicatorError as exc:
            print(f"Skipped {raw!r}: {exc}", file=sys.stderr)

    if not results:
        print("No valid indicators to process.", file=sys.stderr)
        return 1
    if args.output:
        try:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            write_csv(args.output, results)
            print(f"Wrote {len(results)} result(s) to {args.output}")
        except OSError as exc:
            print(f"Could not write output: {exc}", file=sys.stderr)
            return 2
    elif args.json:
        print(json.dumps(results, indent=2, ensure_ascii=False))
    else:
        print(f"{'IOC':45} {'TYPE':8} {'SCORE':>5}  VERDICT")
        print("-" * 75)
        for result in results:
            print(f"{result['normalized'][:45]:45} {result['ioc_type'][:8]:8} {result['risk_score']:>5}  {result['verdict']}")
            for evidence in result["evidence"]:
                print(f"    - {evidence}")
        print("\nResults are also saved in the local SQLite database.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
