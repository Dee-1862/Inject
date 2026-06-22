"""Central configuration for the recon pipeline.

Everything tunable lives here so the agent or operator can adjust scope and
politeness without touching crawler logic.
"""

from __future__ import annotations

# --- Targets -----------------------------------------------------------------
# Seed URLs to start from. The entry point to a HackMIT puzzle is historically
# hidden on the splash page, so the homepage is the primary seed.
SEEDS = [
    "https://hackmit.org/",
]

# Hosts we are allowed to crawl. Same-origin plus known HackMIT properties.
# Subdomains of hackmit.org are allowed because past command centers lived on
# odd subdomains. Add other domains manually only after a surfaced link warrants
# expanding scope.
ALLOWED_HOST_SUFFIXES = [
    "hackmit.org",
]

# --- Politeness --------------------------------------------------------------
USER_AGENT = "hackmit-recon/1.0 (puzzle entry-point finder; respectful crawler)"
REQUEST_DELAY_SECONDS = 1.2
REQUEST_TIMEOUT_SECONDS = 15
MAX_RETRIES = 2
MAX_PAGES = 40
MAX_ASSETS = 60

# Puzzle entries are sometimes hinted at from robots.txt. The default keeps the
# crawler bounded and slow while still allowing operators to inspect disallows.
RESPECT_ROBOTS = False

# Optional active endpoint probing. OFF by default. This is the only mode that
# sends requests the site did not link to, and the wordlist is intentionally
# tiny so it stays a confirmation aid rather than a fuzzer.
ENABLE_ENDPOINT_PROBE = False
ENDPOINT_WORDLIST = [
    "puzzle",
    "puzzles",
    "secret",
    "secrets",
    "hidden",
    "admin",
    "leaderboard",
    "submit",
    "begin",
    "start",
    "entry",
    "gate",
    "robots.txt",
    "sitemap.xml",
    "humans.txt",
    ".well-known/security.txt",
]

# --- Signal patterns ---------------------------------------------------------
# Regexes that tend to mark a puzzle seam. These are intentionally broad; the
# scorer weighs them. Findings are for a human to eyeball, not auto-acted-on.
INTERESTING_REGEXES = {
    "base64_blob": r"(?:[A-Za-z0-9+/]{40,}={0,2})",
    "hex_blob": r"(?:0x)?[0-9a-fA-F]{32,}",
    "url_like": r"https?://[^\s\"'<>)]+",
    "rel_path": r"[\"'(](/[A-Za-z0-9_\-./]{2,})[\"')]",
    "fetch_call": r"fetch\s*\(\s*[\"'`][^\"'`]+[\"'`]",
    "ws_call": r"new\s+WebSocket\s*\(",
    "jwt": r"eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}",
    "puzzle_words": (
        r"(?i)\b(puzzle|cipher|decode|decrypt|leaderboard|admission|hint|"
        r"riddle|congrats|gate ?keeper)\b"
    ),
    "meta_redirect": r"(?i)http-equiv\s*=\s*[\"']refresh[\"']",
    "sourcemap": r"//[#@]\s*sourceMappingURL=([^\s]+)",
}

# CSS/inline styles that hide content from a casual viewer but not from source.
HIDDEN_STYLE_HINTS = [
    "display:none",
    "display: none",
    "visibility:hidden",
    "visibility: hidden",
    "opacity:0",
    "opacity: 0",
    "font-size:0",
    "font-size: 0",
    "text-indent:-9999",
    "left:-9999",
    "position:absolute;left:-",
    "clip:rect(0",
    "height:0",
    "width:0",
]

# Attributes / element traits that hint at an interaction puzzle that a static
# fetch can see the scaffolding of.
INTERACTIVE_HINTS = [
    "draggable",
    "onmousedown",
    "onmousemove",
    "ondrag",
    "contenteditable",
    "data-puzzle",
    "data-secret",
    "data-answer",
    "data-key",
    "data-stage",
]
