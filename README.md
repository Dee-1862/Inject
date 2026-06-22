# HackMIT puzzle entry-point finder (recon only)

Finds where the HackMIT admissions puzzle is hidden on the live site. It does
not solve anything: finding the entry is itself the first puzzle, and this tool
automates the reconnaissance a human would do by hand (view-source, comb the
JS, watch the network tab, check odd headers and well-known files).

The 2026 puzzle is live on https://hackmit.org and the top 50 leaderboard
scorers get auto-admission, so this is built to run against that site now.

## What it looks for

- HTML comments
- Elements hidden via inline style or `hidden` / `aria-hidden`
- Interaction scaffolding: `draggable`, `canvas`, `data-puzzle` / `data-secret`
- Suspicious links: puzzle-ish words, long hash paths, `.jar` / `.wasm` /
  `.map` downloads
- `meta refresh` redirects and custom `@font-face`
- JS analysis: minified/obfuscated scripts, `fetch()` / `WebSocket` targets,
  base64/hex blobs, JWTs, `sourceMappingURL`
- Custom `X-*` response headers and puzzle-ish `Link` headers
- `robots.txt`, `sitemap.xml`, `humans.txt`, and `security.txt`, including
  `Disallow:` paths that hint at hidden areas
- With `--render`: post-JS DOM, draggable/movable elements, console output, and
  off-origin requests fired on load

Every finding is scored and ranked with a short reason for you to judge.

## Install and run

```bash
pip install -r requirements.txt

python -m hackmit_recon.run                 # static pass, prints ranked seams
python -m hackmit_recon.run --depth 3       # crawl one level deeper
python -m hackmit_recon.run --render        # add headless browser pass
python -m hackmit_recon.run --probe         # enable the tiny endpoint probe
```

Rendered pass needs Playwright:

```bash
pip install playwright
playwright install chromium
```

Output: a timestamped `runs/recon-*.json` plus a console summary. Re-running
prints what changed since last time.

## Be a good guest

This points at someone else's production server. Defaults are deliberately
gentle:

- About 1.2 seconds between requests, capped retries, hard page/asset budgets
- Same-origin plus `hackmit.org` subdomains only
- Active endpoint probing is off by default and, when on, is a tiny
  confirmation list rather than a fuzzer
- If you find the entry, stop scanning

The goal is to read what the site already serves you, cleverly, not to stress
their infrastructure.

## Why diff mode matters

A puzzle may drop or unlock stages at a moment in time. Instead of babysitting
the page, schedule this to run periodically; each run diffs against the last and
tells you the instant a new hidden link, comment, or redirect appears. See
`AGENT.md` for a Cursor background-agent setup.

## Scope

Recon surfaces candidates; it does not confirm the entry or solve anything.
Treat the ranked list as leads. The interesting last-mile judgment is yours.