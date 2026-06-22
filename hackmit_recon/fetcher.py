"""Polite, rate-limited fetcher.

One shared client enforces a per-host delay, caps retries, and caches responses
in-memory for the run so we never request the same URL twice. The whole point is
to be a good guest on someone else's server.
"""

from __future__ import annotations

import time
import urllib.robotparser
from dataclasses import dataclass
from urllib.parse import urlparse

import requests

from . import config


@dataclass
class Fetched:
    url: str
    status: int
    headers: dict[str, str]
    text: str
    ok: bool
    error: str = ""


class PoliteFetcher:
    def __init__(self) -> None:
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": config.USER_AGENT})
        self._last_hit: dict[str, float] = {}
        self._cache: dict[str, Fetched] = {}
        self._robots: dict[str, urllib.robotparser.RobotFileParser] = {}
        self.count = 0

    def _wait(self, host: str) -> None:
        last = self._last_hit.get(host, 0.0)
        gap = time.time() - last
        if gap < config.REQUEST_DELAY_SECONDS:
            time.sleep(config.REQUEST_DELAY_SECONDS - gap)
        self._last_hit[host] = time.time()

    def _allowed_by_robots(self, url: str) -> bool:
        if not config.RESPECT_ROBOTS:
            return True

        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        parser = self._robots.get(base)
        if parser is None:
            parser = urllib.robotparser.RobotFileParser()
            parser.set_url(base + "/robots.txt")
            try:
                parser.read()
            except Exception:
                pass
            self._robots[base] = parser

        try:
            return parser.can_fetch(config.USER_AGENT, url)
        except Exception:
            return True

    def get(self, url: str) -> Fetched:
        if url in self._cache:
            return self._cache[url]
        if self.count >= config.MAX_PAGES + config.MAX_ASSETS:
            return Fetched(url, 0, {}, "", False, "page/asset budget exhausted")
        if not self._allowed_by_robots(url):
            fetched = Fetched(url, 0, {}, "", False, "blocked by robots.txt")
            self._cache[url] = fetched
            return fetched

        host = urlparse(url).netloc
        last_err = ""
        for attempt in range(config.MAX_RETRIES + 1):
            self._wait(host)
            try:
                response = self.session.get(
                    url,
                    timeout=config.REQUEST_TIMEOUT_SECONDS,
                    allow_redirects=True,
                )
                self.count += 1
                content_type = response.headers.get("Content-Type", "")
                is_text_like = (
                    "text" in content_type
                    or "javascript" in content_type
                    or "json" in content_type
                    or content_type == ""
                )
                fetched = Fetched(
                    url=response.url,
                    status=response.status_code,
                    headers=dict(response.headers),
                    text=response.text if is_text_like else "",
                    ok=response.status_code < 400,
                )
                self._cache[url] = fetched
                return fetched
            except requests.RequestException as exc:
                last_err = str(exc)
                time.sleep(0.5 * (attempt + 1))

        fetched = Fetched(url, 0, {}, "", False, last_err or "request failed")
        self._cache[url] = fetched
        return fetched
