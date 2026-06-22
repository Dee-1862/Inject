"""Scoring, de-duplication, snapshot diffing, and report rendering."""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
from collections import defaultdict
from dataclasses import asdict
from typing import Any

from .extract import Finding


# Findings of these kinds are the strongest "this is probably the seam" signals.
PRIORITY_KINDS = {
    "hidden_element": 5,
    "html_comment": 4,
    "suspicious_link": 4,
    "interactive_hint": 4,
    "rendered_interactive": 4,
    "render_network": 4,
    "robots_disallow": 3,
    "meta_redirect": 3,
    "custom_header": 3,
    "obfuscated_js": 2,
}


def _key(finding: Finding) -> str:
    raw = f"{finding.kind}|{finding.source_url}|{finding.evidence}"
    return hashlib.sha1(raw.encode()).hexdigest()[:12]


def score_and_rank(findings: list[Finding]) -> list[tuple[int, str, Finding]]:
    uniq: dict[str, Finding] = {}
    for finding in findings:
        uniq.setdefault(_key(finding), finding)

    items = []
    for key, finding in uniq.items():
        score = finding.weight + PRIORITY_KINDS.get(finding.kind, 0)
        items.append((score, key, finding))
    items.sort(key=lambda item: item[0], reverse=True)
    return items


def to_report(findings: list[Finding], stats: dict[str, int]) -> dict[str, Any]:
    ranked = score_and_rank(findings)
    by_kind: defaultdict[str, int] = defaultdict(int)
    for _, _, finding in ranked:
        by_kind[finding.kind] += 1

    return {
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "stats": stats,
        "kind_counts": dict(sorted(by_kind.items(), key=lambda item: -item[1])),
        "findings": [
            {"score": score, "id": key, **asdict(finding)}
            for score, key, finding in ranked
        ],
    }


def render_console(report: dict[str, Any], top: int = 25) -> str:
    lines: list[str] = []
    lines.append("=" * 70)
    lines.append("HackMIT puzzle entry-point recon - candidate seams")
    lines.append(f"generated: {report['generated_at']}")
    stats = report["stats"]
    lines.append(
        f"requests: {stats.get('total_requests')} | pages: {stats.get('pages_fetched')} "
        f"| assets: {stats.get('assets_fetched')}"
    )
    lines.append(
        "kind counts: "
        + ", ".join(f"{kind}={count}" for kind, count in report["kind_counts"].items())
    )
    lines.append("=" * 70)

    for idx, finding in enumerate(report["findings"][:top], 1):
        lines.append(f"[{idx:>2}] score={finding['score']:<3} {finding['kind']}")
        lines.append(f"     where: {finding['source_url']}")
        lines.append(f"     why:   {finding['detail']}")
        if finding["evidence"]:
            lines.append(f"     ev:    {finding['evidence']}")

    if len(report["findings"]) > top:
        lines.append(f"... and {len(report['findings']) - top} more (see JSON).")
    return "\n".join(lines)


def diff_against_previous(report: dict[str, Any], state_dir: str) -> list[str]:
    """Return human-readable notes about what is NEW vs the last run."""
    os.makedirs(state_dir, exist_ok=True)
    prev_path = os.path.join(state_dir, "last_ids.json")
    cur_ids = {finding["id"] for finding in report["findings"]}

    prev_ids: set[str] = set()
    if os.path.exists(prev_path):
        try:
            with open(prev_path, encoding="utf-8") as previous:
                prev_ids = set(json.load(previous))
        except Exception:
            prev_ids = set()

    new_ids = cur_ids - prev_ids
    gone_ids = prev_ids - cur_ids
    with open(prev_path, "w", encoding="utf-8") as current:
        json.dump(sorted(cur_ids), current)

    notes: list[str] = []
    if not prev_ids:
        notes.append("first run - no previous snapshot to diff against.")
        return notes
    if new_ids:
        notes.append(f"{len(new_ids)} NEW finding(s) since last run:")
        for finding in report["findings"]:
            if finding["id"] in new_ids:
                notes.append(
                    f"  + [{finding['kind']}] {finding['detail']} @ "
                    f"{finding['source_url']}"
                )
    if gone_ids:
        notes.append(f"{len(gone_ids)} finding(s) disappeared since last run.")
    if not new_ids and not gone_ids:
        notes.append("no change since last run.")
    return notes


def save_json(report: dict[str, Any], path: str) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as output:
        json.dump(report, output, indent=2)
