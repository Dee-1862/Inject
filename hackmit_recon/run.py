"""CLI entry point.

    python -m hackmit_recon.run                 # static recon, console + JSON
    python -m hackmit_recon.run --render        # add headless rendered pass
    python -m hackmit_recon.run --depth 3       # crawl one level deeper
    python -m hackmit_recon.run --probe         # enable tiny endpoint probe
    python -m hackmit_recon.run --out runs/     # where to write artifacts

Designed to be run repeatedly by a scheduled Cursor background agent or cron.
Each run writes timestamped JSON, updates a snapshot, and prints what is NEW
since the previous run so the operator can alert when the site shifts.
"""

from __future__ import annotations

import argparse
import datetime as dt
import os

from . import config, crawl, report
from .render import render_findings


def main() -> None:
    parser = argparse.ArgumentParser(
        description="HackMIT puzzle entry-point finder (recon only)"
    )
    parser.add_argument("--render", action="store_true", help="add headless rendered-DOM pass")
    parser.add_argument("--depth", type=int, default=2, help="crawl depth (default 2)")
    parser.add_argument("--probe", action="store_true", help="enable small endpoint probe")
    parser.add_argument("--out", default="runs", help="output directory")
    parser.add_argument("--top", type=int, default=25, help="console: show top N findings")
    args = parser.parse_args()

    if args.depth < 0:
        parser.error("--depth must be >= 0")
    if args.top < 0:
        parser.error("--top must be >= 0")

    if args.probe:
        config.ENABLE_ENDPOINT_PROBE = True

    findings, stats = crawl.crawl(max_depth=args.depth)
    if args.render:
        findings.extend(render_findings())

    recon_report = report.to_report(findings, stats)

    stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    json_path = os.path.join(args.out, f"recon-{stamp}.json")
    report.save_json(recon_report, json_path)

    print(report.render_console(recon_report, top=args.top))
    print("\n--- change since last run ---")
    for note in report.diff_against_previous(
        recon_report, state_dir=os.path.join(args.out, ".state")
    ):
        print(note)
    print(f"\nfull report: {json_path}")


if __name__ == "__main__":
    main()
