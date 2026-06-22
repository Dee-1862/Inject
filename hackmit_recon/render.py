"""Optional rendered-DOM pass.

Many puzzle entry points are JS-driven: dragging a logo, a dial, a canvas
interaction. A static fetch sees the scaffolding but not the post-render DOM or
the attached event behavior. This module loads the page in a headless browser,
dumps the rendered HTML, lists elements that look movable, and records network
requests fired on load. It still does not interact with or solve anything.
"""

from __future__ import annotations

from urllib.parse import urlparse

from . import config, extract


def render_findings(url: str | None = None) -> list[extract.Finding]:
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        return [
            extract.Finding(
                "render_skipped",
                "playwright not installed; skipping rendered pass",
                "pip install playwright && playwright install chromium",
                url or config.SEEDS[0],
                weight=0,
            )
        ]

    target = url or config.SEEDS[0]
    findings: list[extract.Finding] = []
    net_log: list[str] = []

    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            ctx = browser.new_context(user_agent=config.USER_AGENT)
            page = ctx.new_page()
            page.on("request", lambda req: net_log.append(f"{req.method} {req.url}"))
            page.on(
                "console",
                lambda msg: findings.append(
                    extract.Finding(
                        "console_msg",
                        "page console output",
                        extract._trim(msg.text, 200),
                        target,
                        weight=2,
                    )
                ),
            )

            try:
                page.goto(target, timeout=20000, wait_until="networkidle")
            except Exception as exc:
                findings.append(
                    extract.Finding(
                        "render_note",
                        "page load issue",
                        str(exc),
                        target,
                        weight=0,
                    )
                )

            html = page.content()
            rendered, _, _ = extract.analyze_html(target + "#rendered", html)
            findings.extend(rendered)

            interactive = page.evaluate(
                """() => {
                    const out = [];
                    document.querySelectorAll('*').forEach(el => {
                        const drag = el.draggable;
                        const cur = getComputedStyle(el).cursor;
                        if (drag || cur === 'grab' || cur === 'move' || el.tagName === 'CANVAS') {
                            out.push((el.tagName || '') + (el.id ? ('#' + el.id) : '') +
                                     (el.className ? ('.' + String(el.className).slice(0, 40)) : ''));
                        }
                    });
                    return out.slice(0, 30);
                }"""
            )
            for selector in interactive:
                findings.append(
                    extract.Finding(
                        "rendered_interactive",
                        "element looks draggable/movable/canvas after render",
                        selector,
                        target,
                        weight=3,
                    )
                )

            ctx.close()
            browser.close()
    except Exception as exc:
        findings.append(
            extract.Finding(
                "render_skipped",
                "rendered pass could not start",
                str(exc),
                target,
                weight=0,
            )
        )

    for entry in net_log:
        requested = entry.split(" ", 1)[-1]
        if requested.startswith("http") and not _is_hackmit_url(requested):
            findings.append(
                extract.Finding(
                    "render_network",
                    "page fetched an off-hackmit URL on load (possible next host)",
                    extract._trim(entry, 200),
                    target,
                    weight=3,
                )
            )

    return findings


def _is_hackmit_url(url: str) -> bool:
    host = urlparse(url).netloc.lower()
    return host == "hackmit.org" or host.endswith(".hackmit.org")
