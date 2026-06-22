"""Website-only monitor for the likely HackMIT puzzle drop surfaces.

This is narrower than the recon crawler: it watches only artifacts served by
the live HackMIT/Plume sites that have proven relevant during reconnaissance:
the homepage bundle, Plume's public OpenAPI schema, and the documented
``hack-2026`` API collections. Each run writes a timestamped JSON snapshot and
diffs hashes against the previous run.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import time
from typing import Any

import requests

from . import config


TARGETS = [
    {
        "name": "hackmit_home",
        "url": "https://hackmit.org/",
        "kind": "html",
    },
    {
        "name": "hackmit_home_js",
        "url": "https://hackmit.org/assets/index-BPyxSBvk.js",
        "kind": "javascript",
    },
    {
        "name": "hackmit_home_css",
        "url": "https://hackmit.org/assets/index-DR-Ej0LX.css",
        "kind": "css",
    },
    {
        "name": "plume_openapi",
        "url": "https://plume.hackmit.org/openapi.json",
        "kind": "openapi",
    },
    {
        "name": "hack_2026_challenges",
        "url": "https://plume.hackmit.org/api/v3/hackathons/hack-2026/challenges",
        "kind": "json_collection",
    },
    {
        "name": "hack_2026_projects",
        "url": "https://plume.hackmit.org/api/v3/hackathons/hack-2026/projects",
        "kind": "json_collection",
    },
    {
        "name": "hack_2026_categories",
        "url": "https://plume.hackmit.org/api/v3/hackathons/hack-2026/categories",
        "kind": "json_collection",
    },
    {
        "name": "hack_2026_tracks",
        "url": "https://plume.hackmit.org/api/v3/hackathons/hack-2026/tracks",
        "kind": "json_collection",
    },
]

WATCH_TERMS = [
    "puzzle",
    "secret",
    "cipher",
    "riddle",
    "leaderboard",
    "admission",
    "challenge",
    "hack-2026",
    "application-hack-2026",
]


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


def _term_counts(text: str) -> dict[str, int]:
    return {
        term: len(re.findall(re.escape(term), text, flags=re.IGNORECASE))
        for term in WATCH_TERMS
    }


def _extract_homepage_puzzle_contexts(text: str) -> list[str]:
    contexts: list[str] = []
    for match in re.finditer(r"(?i)puzzle|leaderboard|admission|challenge", text):
        start = max(0, match.start() - 180)
        end = min(len(text), match.end() + 260)
        snippet = text[start:end].strip().replace("\n", " ")
        if snippet not in contexts:
            contexts.append(snippet)
        if len(contexts) >= 12:
            break
    return contexts


def _openapi_summary(text: str) -> dict[str, Any]:
    try:
        spec = json.loads(text)
    except json.JSONDecodeError:
        return {"parse_error": "not valid JSON"}

    relevant_paths: dict[str, list[str]] = {}
    for path, operations in spec.get("paths", {}).items():
        low = path.lower()
        if any(term in low for term in ("puzzle", "leader", "challenge", "hackathon", "project")):
            relevant_paths[path] = sorted(operations.keys())

    return {
        "title": spec.get("info", {}).get("title"),
        "version": spec.get("info", {}).get("version"),
        "path_count": len(spec.get("paths", {})),
        "relevant_paths": relevant_paths,
    }


def _json_collection_summary(text: str) -> dict[str, Any]:
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return {"parse_error": "not valid JSON"}

    summary: dict[str, Any] = {"type": type(data).__name__}
    if isinstance(data, list):
        summary["count"] = len(data)
        summary["sample"] = data[:3]
    elif isinstance(data, dict):
        summary["keys"] = sorted(data.keys())[:20]
        summary["sample"] = {key: data[key] for key in sorted(data.keys())[:5]}
    return summary


def _summarize(kind: str, text: str) -> dict[str, Any]:
    summary: dict[str, Any] = {
        "bytes": len(text.encode("utf-8", errors="replace")),
        "term_counts": _term_counts(text),
    }
    if kind in {"html", "javascript"}:
        summary["contexts"] = _extract_homepage_puzzle_contexts(text)
    if kind == "openapi":
        summary["openapi"] = _openapi_summary(text)
    if kind == "json_collection":
        summary["json"] = _json_collection_summary(text)
    return summary


def collect_snapshot(delay_seconds: float = config.REQUEST_DELAY_SECONDS) -> dict[str, Any]:
    session = requests.Session()
    session.headers.update({"User-Agent": config.USER_AGENT})
    targets: list[dict[str, Any]] = []

    for idx, target in enumerate(TARGETS):
        if idx:
            time.sleep(delay_seconds)
        try:
            response = session.get(target["url"], timeout=config.REQUEST_TIMEOUT_SECONDS)
            text = response.text
            item = {
                "name": target["name"],
                "url": target["url"],
                "kind": target["kind"],
                "status": response.status_code,
                "content_type": response.headers.get("Content-Type", ""),
                "sha256": sha256_text(text),
                "summary": _summarize(target["kind"], text),
            }
        except requests.RequestException as exc:
            item = {
                "name": target["name"],
                "url": target["url"],
                "kind": target["kind"],
                "status": 0,
                "content_type": "",
                "sha256": "",
                "error": str(exc),
                "summary": {},
            }
        targets.append(item)

    return {
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "targets": targets,
    }


def save_json(snapshot: dict[str, Any], path: str) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as output:
        json.dump(snapshot, output, indent=2)


def diff_against_previous(snapshot: dict[str, Any], state_dir: str) -> list[str]:
    os.makedirs(state_dir, exist_ok=True)
    prev_path = os.path.join(state_dir, "site_monitor_hashes.json")
    current = {
        item["name"]: {
            "sha256": item.get("sha256", ""),
            "status": item.get("status", 0),
            "summary": item.get("summary", {}),
        }
        for item in snapshot["targets"]
    }

    previous: dict[str, Any] = {}
    if os.path.exists(prev_path):
        try:
            with open(prev_path, encoding="utf-8") as prev:
                previous = json.load(prev)
        except Exception:
            previous = {}

    with open(prev_path, "w", encoding="utf-8") as out:
        json.dump(current, out, indent=2)

    if not previous:
        return ["first monitor run - no previous site snapshot to diff against."]

    notes: list[str] = []
    for name, cur in current.items():
        old = previous.get(name)
        if old is None:
            notes.append(f"+ new monitored target: {name}")
            continue
        if cur.get("status") != old.get("status"):
            notes.append(f"! {name} status changed {old.get('status')} -> {cur.get('status')}")
        if cur.get("sha256") != old.get("sha256"):
            notes.append(f"! {name} content hash changed")
            old_summary = old.get("summary", {})
            new_summary = cur.get("summary", {})
            old_json = old_summary.get("json", {})
            new_json = new_summary.get("json", {})
            if old_json or new_json:
                notes.append(f"  json summary: {old_json} -> {new_json}")

    for name in sorted(set(previous) - set(current)):
        notes.append(f"- monitored target removed: {name}")

    if not notes:
        notes.append("no monitored site changes since last run.")
    return notes


def render_console(snapshot: dict[str, Any], notes: list[str]) -> str:
    lines = [
        "=" * 70,
        "HackMIT website-only monitor",
        f"generated: {snapshot['generated_at']}",
        "=" * 70,
    ]
    for item in snapshot["targets"]:
        summary = item.get("summary", {})
        lines.append(f"{item['name']}: status={item['status']} sha256={item.get('sha256', '')[:16]}")
        lines.append(f"  url: {item['url']}")
        if item.get("error"):
            lines.append(f"  error: {item['error']}")
        terms = {k: v for k, v in summary.get("term_counts", {}).items() if v}
        if terms:
            lines.append(f"  term counts: {terms}")
        if "json" in summary:
            lines.append(f"  json: {summary['json']}")
        if "openapi" in summary:
            openapi = summary["openapi"]
            lines.append(
                "  openapi: "
                f"paths={openapi.get('path_count')} relevant={len(openapi.get('relevant_paths', {}))}"
            )
    lines.append("")
    lines.append("--- change since last monitor run ---")
    lines.extend(notes)
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="Monitor live HackMIT puzzle drop surfaces")
    parser.add_argument("--out", default="runs", help="output directory")
    parser.add_argument(
        "--delay",
        type=float,
        default=config.REQUEST_DELAY_SECONDS,
        help="delay between requests",
    )
    args = parser.parse_args()

    snapshot = collect_snapshot(delay_seconds=args.delay)
    stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    path = os.path.join(args.out, f"site-monitor-{stamp}.json")
    save_json(snapshot, path)
    notes = diff_against_previous(snapshot, state_dir=os.path.join(args.out, ".state"))
    print(render_console(snapshot, notes))
    print(f"\nfull report: {path}")


if __name__ == "__main__":
    main()
