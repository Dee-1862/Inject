"""Static analysis of fetched content.

Given an HTML page or JS/CSS/text asset, surface anything that looks like a
puzzle seam: comments, hidden elements, odd links, encoded blobs, interaction
scaffolding, custom headers, and source maps. Each finding carries a short
reason so a human can decide. Nothing here tries to solve anything.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup, Comment

from . import config


@dataclass
class Finding:
    kind: str
    detail: str
    evidence: str
    source_url: str
    weight: int = 1


def _trim(s: str, n: int = 240) -> str:
    s = s.strip().replace("\n", "\\n")
    return s if len(s) <= n else s[:n] + " ..."


def analyze_html(url: str, html: str) -> tuple[list[Finding], set[str], set[str]]:
    """Return ``(findings, discovered_links, discovered_assets)`` for HTML."""
    findings: list[Finding] = []
    links: set[str] = set()
    assets: set[str] = set()
    soup = BeautifulSoup(html, "html.parser")

    # 1. HTML comments - classic hiding spot.
    for comment in soup.find_all(string=lambda t: isinstance(t, Comment)):
        text = str(comment)
        if text.strip():
            findings.append(
                Finding("html_comment", "HTML comment present", _trim(text), url, weight=3)
            )

    # 2. Hidden elements (inline style or hidden attrs).
    for el in soup.find_all(True):
        style = (el.get("style") or "").replace(" ", "").lower()
        if any(h.replace(" ", "") in style for h in config.HIDDEN_STYLE_HINTS):
            findings.append(
                Finding(
                    "hidden_element",
                    f"<{el.name}> hidden via inline style",
                    _trim(el.get_text(" ", strip=True) or str(el)),
                    url,
                    weight=4,
                )
            )
        if el.has_attr("hidden") or el.get("aria-hidden") == "true":
            txt = el.get_text(" ", strip=True)
            if txt:
                findings.append(
                    Finding(
                        "hidden_element",
                        f"<{el.name}> hidden attribute",
                        _trim(txt),
                        url,
                        weight=3,
                    )
                )

    # 3. Interaction scaffolding (drag/canvas/data-* puzzle hooks).
    for el in soup.find_all(True):
        attrs = " ".join(f"{k}={v}" for k, v in el.attrs.items()).lower()
        for hint in config.INTERACTIVE_HINTS:
            if hint in attrs:
                findings.append(
                    Finding(
                        "interactive_hint",
                        f"<{el.name}> has '{hint}' (possible interaction puzzle)",
                        _trim(str(el)),
                        url,
                        weight=4,
                    )
                )
                break
    if soup.find("canvas"):
        findings.append(
            Finding(
                "interactive_hint",
                "<canvas> present (often a rendered puzzle)",
                "",
                url,
                weight=2,
            )
        )

    # 4. Meta tags: refresh redirects and odd content.
    for meta in soup.find_all("meta"):
        raw = str(meta).lower()
        if "refresh" in raw and "http-equiv" in raw:
            findings.append(
                Finding("meta_redirect", "meta refresh redirect", _trim(str(meta)), url, weight=3)
            )

    # 5. Links and assets.
    for anchor in soup.find_all("a", href=True):
        target = urljoin(url, anchor["href"])
        links.add(target)
        if _is_suspicious_link(target, anchor.get_text(" ", strip=True)):
            findings.append(
                Finding(
                    "suspicious_link",
                    "link with puzzle-ish target/text",
                    _trim(f'{target} | text="{anchor.get_text(" ", strip=True)}"'),
                    url,
                    weight=3,
                )
            )

    for tag, attr in (
        ("script", "src"),
        ("link", "href"),
        ("img", "src"),
        ("source", "src"),
        ("audio", "src"),
    ):
        for el in soup.find_all(tag):
            val = el.get(attr)
            if val:
                assets.add(urljoin(url, val))

    # 6. Inline scripts get JS treatment.
    for script in soup.find_all("script"):
        if script.string:
            findings.extend(analyze_js(url + "#inline", script.string, inline=True))

    # 7. Odd fonts can mask ciphered text.
    if "@font-face" in html.lower():
        findings.append(
            Finding(
                "custom_font",
                "custom @font-face present (can mask ciphered text)",
                "",
                url,
                weight=1,
            )
        )

    return findings, links, assets


def _is_suspicious_link(target: str, text: str) -> bool:
    low = (target + " " + (text or "")).lower()
    if re.search(config.INTERESTING_REGEXES["puzzle_words"], low):
        return True
    path = urlparse(target).path
    # Long hash-like path segments, e.g. /suchsecret/<sha256>.jar.
    if re.search(r"/[0-9a-f]{16,}", path):
        return True
    return path.endswith((".jar", ".wasm", ".bin", ".pyc", ".map", ".zip"))


def analyze_js(url: str, code: str, inline: bool = False) -> list[Finding]:
    """Analyze JavaScript or text-like assets for suspicious patterns."""
    findings: list[Finding] = []

    # Minified / obfuscated heuristic: very long lines + low whitespace ratio.
    longest = max((len(line) for line in code.splitlines()), default=0)
    ws_ratio = (code.count(" ") + code.count("\n")) / max(len(code), 1)
    if longest > 500 and ws_ratio < 0.08 and len(code) > 800:
        findings.append(
            Finding(
                "obfuscated_js",
                "script looks minified/obfuscated (worth a manual un-minify)",
                f"longest_line={longest}, ws_ratio={ws_ratio:.3f}",
                url,
                weight=2,
            )
        )

    for name, pattern in config.INTERESTING_REGEXES.items():
        for match in re.finditer(pattern, code):
            snippet = match.group(0)
            if name == "rel_path" and len(snippet) < 4:
                continue
            findings.append(
                Finding(
                    f"js_{name}" if not inline else f"inline_{name}",
                    f"pattern '{name}' in script",
                    _trim(snippet, 160),
                    url,
                    weight=_pattern_weight(name),
                )
            )

    return findings


def _pattern_weight(name: str) -> int:
    return {
        "fetch_call": 3,
        "ws_call": 3,
        "jwt": 4,
        "sourcemap": 3,
        "puzzle_words": 3,
        "base64_blob": 2,
        "url_like": 1,
        "rel_path": 1,
        "hex_blob": 1,
        "meta_redirect": 2,
    }.get(name, 1)


def analyze_headers(url: str, headers: dict[str, str]) -> list[Finding]:
    """Surface custom response headers and puzzle-ish Link headers."""
    findings: list[Finding] = []
    for key, value in headers.items():
        key_lower = key.lower()
        if key_lower.startswith("x-") and key_lower not in (
            "x-frame-options",
            "x-content-type-options",
            "x-xss-protection",
            "x-cache",
            "x-served-by",
            "x-timer",
            "x-powered-by",
        ):
            findings.append(
                Finding(
                    "custom_header",
                    f"custom response header {key}",
                    _trim(f"{key}: {value}", 160),
                    url,
                    weight=3,
                )
            )
        if key_lower == "link" and "puzzle" in value.lower():
            findings.append(
                Finding("custom_header", "Link header mentions puzzle", _trim(value), url, weight=3)
            )
    return findings
