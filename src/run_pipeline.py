"""
run_pipeline.py — CLI entry point for ThreatLens AI.

Usage:
  python src/run_pipeline.py --input data/synthetic_alerts.json
  python src/run_pipeline.py --input data/synthetic_alerts.json --reset-db
  python src/run_pipeline.py --help
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from datetime import datetime, timezone

# Ensure imports work from repo root
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dotenv import load_dotenv
load_dotenv()

from src.db import init_db
from src.pipeline.graph import build_pipeline


def main():
    parser = argparse.ArgumentParser(
        description="ThreatLens AI — Threat Intelligence Correlation Pipeline",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Generate synthetic data then run pipeline
  python src/data/generate_alerts.py --seed 42 --output data/synthetic_alerts.json
  python src/run_pipeline.py --input data/synthetic_alerts.json

  # Reset DB and re-run (fresh start)
  python src/run_pipeline.py --input data/synthetic_alerts.json --reset-db
        """
    )
    parser.add_argument(
        "--input", "-i",
        default="data/synthetic_alerts.json",
        help="Path to alert JSON file (default: data/synthetic_alerts.json)"
    )
    parser.add_argument(
        "--reset-db",
        action="store_true",
        help="Drop and recreate database tables before running"
    )
    parser.add_argument(
        "--output", "-o",
        default=None,
        help="Optional: save pipeline output JSON to this path"
    )
    args = parser.parse_args()

    if not os.path.exists(args.input):
        print(f"[ERROR] Input file not found: {args.input}")
        print("  Run: python src/data/generate_alerts.py --seed 42 --output data/synthetic_alerts.json")
        sys.exit(1)

    print("\n" + "█"*60)
    print("  ThreatLens AI — Threat Intelligence Pipeline")
    print(f"  Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("█"*60)

    # ── Init DB ───────────────────────────────────────────────────
    print(f"\n[setup] Initialising database (reset={args.reset_db})...")
    init_db(reset=args.reset_db)

    # ── Build & run pipeline ───────────────────────────────────────
    pipeline = build_pipeline()

    initial_state = {
        "input_file": args.input,
        "raw_alerts": [],
        "alerts":     [],
        "clusters":   [],
        "briefs":     [],
        "errors":     [],
        "stage":      "init",
    }

    t0 = time.time()
    final_state = pipeline.invoke(initial_state)
    elapsed     = time.time() - t0

    # ── Print summary ─────────────────────────────────────────────
    alerts   = final_state.get("alerts",   [])
    clusters = final_state.get("clusters", [])
    briefs   = final_state.get("briefs",   [])
    errors   = final_state.get("errors",   [])

    # Compute stats
    true_threats  = [c for c in clusters if not c.get("is_false_positive")]
    false_pos     = [c for c in clusters if c.get("is_false_positive")]
    cross_source  = [c for c in clusters if len(c.get("source_types", [])) > 1]

    print("\n" + "="*60)
    print("  PIPELINE COMPLETE")
    print("="*60)
    print(f"  Alerts ingested    : {len(alerts)}")
    print(f"  Clusters formed    : {len(clusters)}")
    print(f"  ├─ True threats    : {len(true_threats)}")
    print(f"  ├─ False positives : {len(false_pos)}")
    print(f"  └─ Cross-source    : {len(cross_source)}")
    print(f"  BLUF briefs        : {len(briefs)}")
    print(f"  Errors             : {len(errors)}")
    print(f"  Elapsed            : {elapsed:.1f}s")
    print("="*60)

    # Top-5 threats
    sorted_threats = sorted(true_threats, key=lambda c: c.get("threat_score", 0), reverse=True) if true_threats else []
    if sorted_threats:
        print("\n  TOP THREATS:")
        for i, c in enumerate(sorted_threats[:5], 1):
            score  = c.get("threat_score", 0)
            srcs   = ", ".join(c.get("source_types", []))
            cnt    = c.get("alert_count", 1)
            sev    = c.get("max_severity", "?").upper()
            print(f"  {i}. [{sev}] score={score:.3f}  alerts={cnt}  sources={srcs}")

    # Verification assertions
    print("\n  VERIFICATION:")
    ok_correlation = len(cross_source) > 0
    ok_fp_scoring  = all(
        c.get("threat_score", 1.0) < 0.35
        for c in false_pos
    ) if false_pos else True
    ok_bluf        = all(b.get("bottom_line") for b in briefs) if briefs else True

    print(f"  ✓ Cross-source correlation : {'PASS' if ok_correlation else 'FAIL'} ({len(cross_source)} clusters)")
    print(f"  ✓ FP classifier scoring    : {'PASS' if ok_fp_scoring else 'FAIL'}")
    print(f"  ✓ BLUF briefs well-formed  : {'PASS' if ok_bluf else 'FAIL'} ({len(briefs)} briefs)")

    if not ok_correlation:
        print("  WARN: No cross-source clusters found — check CORRELATION_THRESHOLD in .env")

    # Save output if requested
    if args.output:
        output = {
            "run_at":    datetime.now(timezone.utc).isoformat(),
            "alerts":    len(alerts),
            "clusters":  len(clusters),
            "briefs":    len(briefs),
            "top_threats": sorted_threats[:10],
        }
        os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
        with open(args.output, "w", encoding="utf-8") as fh:
            json.dump(output, fh, indent=2, default=str)
        print(f"\n  Output saved -> {args.output}")

    print("\n  Launch dashboard: streamlit run src/app.py")
    print("="*60 + "\n")

    return 0 if (ok_correlation and ok_fp_scoring and ok_bluf) else 1


if __name__ == "__main__":
    if hasattr(sys.stdout, "reconfigure"):
        getattr(sys.stdout, "reconfigure")(encoding="utf-8", errors="replace")
    sys.exit(main())
