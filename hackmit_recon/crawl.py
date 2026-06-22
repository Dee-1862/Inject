"""Bounded crawler.

Walks the seed pages, follows in-scope links to a shallow depth, pulls and
analyzes linked JS/CSS assets, checks a couple of well-known files, and
optionally probes a tiny endpoint wordlist. Everything is capped by the budgets
in config so a background run cannot snowball.
"""

from __future__ import annotations

from collections import deque
from urllib.parse import urljoin, urlparse

from . import config, extract
from .fetcher import PoliteFetcher


def _in_scope(url: str) -> bool:
    host = urlparse(url).netloc.lower()
    return any(
        host == suffix or host.endswith("." + suffix)
        for suffix in config.ALLOWED_HOST_SUFFIXES
    )


def crawl(max_depth: int = 2) -> tuple[list[extract.Finding], dict[str, int]]:
    fetcher = PoliteFetcher()
    findings: list[extract.Finding] = []
    seen_pages: set[str] = set()
    seen_assets: set[str] = set()
    pages_done = 0

    queue: deque[tuple[str, int]] = deque((seed, 0) for seed in config.SEEDS)

    while queue and pages_done < config.MAX_PAGES:
        url, depth = queue.popleft()
        if url in seen_pages or not _in_scope(url):
            continue
        seen_pages.add(url)

        res = fetcher.get(url)
        findings.extend(extract.analyze_headers(res.url, res.headers))
        if not res.ok or not res.text:
            if res.error:
                findings.append(
                    extract.Finding(
                        "fetch_note",
                        f"non-OK fetch ({res.status})",
                        res.error,
                        url,
                        weight=0,
                    )
                )
            continue
        pages_done += 1

        page_findings, links, assets = extract.analyze_html(res.url, res.text)
        findings.extend(page_findings)

        for asset in assets:
            if asset in seen_assets or not _in_scope(asset):
                continue
            if len(seen_assets) >= config.MAX_ASSETS:
                break
            seen_assets.add(asset)
            if asset.lower().split("?", 1)[0].endswith(
                (".js", ".css", ".json", ".txt", ".map")
            ):
                asset_res = fetcher.get(asset)
                findings.extend(extract.analyze_headers(asset_res.url, asset_res.headers))
                if asset_res.ok and asset_res.text:
                    findings.extend(extract.analyze_js(asset_res.url, asset_res.text))

        if depth < max_depth:
            for link in links:
                if link not in seen_pages and _in_scope(link):
                    queue.append((link, depth + 1))

    findings.extend(_check_well_known(fetcher))
    if config.ENABLE_ENDPOINT_PROBE:
        findings.extend(_probe_endpoints(fetcher))

    return findings, {
        "pages_fetched": pages_done,
        "assets_fetched": len(seen_assets),
        "total_requests": fetcher.count,
    }


def _check_well_known(fetcher: PoliteFetcher) -> list[extract.Finding]:
    out: list[extract.Finding] = []
    base = config.SEEDS[0]
    for path in ("robots.txt", "sitemap.xml", "humans.txt", ".well-known/security.txt"):
        url = urljoin(base, "/" + path)
        if not _in_scope(url):
            continue
        res = fetcher.get(url)
        if res.ok and res.text.strip():
            out.append(
                extract.Finding(
                    "well_known",
                    f"/{path} exists",
                    extract._trim(res.text, 300),
                    url,
                    weight=2,
                )
            )
            if path == "robots.txt":
                for line in res.text.splitlines():
                    if line.lower().startswith("disallow:"):
                        out.append(
                            extract.Finding(
                                "robots_disallow",
                                "robots.txt disallows a path",
                                extract._trim(line),
                                url,
                                weight=3,
                            )
                        )
    return out


def _probe_endpoints(fetcher: PoliteFetcher) -> list[extract.Finding]:
    """OFF by default. Confirms suspected paths; not a brute forcer."""
    out: list[extract.Finding] = []
    base = config.SEEDS[0]
    for word in config.ENDPOINT_WORDLIST:
        url = urljoin(base, "/" + word)
        if not _in_scope(url):
            continue
        res = fetcher.get(url)
        if res.ok:
            out.append(
                extract.Finding(
                    "endpoint_probe",
                    f"/{word} responded {res.status}",
                    extract._trim(res.text, 200),
                    url,
                    weight=2,
                )
            )
    return out
