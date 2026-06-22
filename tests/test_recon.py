from __future__ import annotations

import tempfile
import unittest

from hackmit_recon import crawl, extract, monitor, report


class ExtractTests(unittest.TestCase):
    def test_analyze_html_surfaces_comments_hidden_links_and_assets(self) -> None:
        html = """
        <html>
          <!-- knock knock -->
          <head><script src="/app.js"></script></head>
          <body>
            <a href="/puzzle">door</a>
            <p style="display: none">secret text</p>
            <canvas id="board"></canvas>
          </body>
        </html>
        """

        findings, links, assets = extract.analyze_html("https://hackmit.org/", html)

        kinds = {finding.kind for finding in findings}
        self.assertIn("html_comment", kinds)
        self.assertIn("hidden_element", kinds)
        self.assertIn("suspicious_link", kinds)
        self.assertIn("interactive_hint", kinds)
        self.assertIn("https://hackmit.org/puzzle", links)
        self.assertIn("https://hackmit.org/app.js", assets)

    def test_analyze_js_finds_fetch_and_sourcemap(self) -> None:
        findings = extract.analyze_js(
            "https://hackmit.org/app.js",
            'fetch("/stage-one");\n//# sourceMappingURL=app.js.map\n',
        )

        kinds = {finding.kind for finding in findings}
        self.assertIn("js_fetch_call", kinds)
        self.assertIn("js_sourcemap", kinds)


class CrawlTests(unittest.TestCase):
    def test_scope_allows_only_exact_domain_or_subdomain(self) -> None:
        self.assertTrue(crawl._in_scope("https://hackmit.org/"))
        self.assertTrue(crawl._in_scope("https://plume.hackmit.org/"))
        self.assertFalse(crawl._in_scope("https://evil-hackmit.org/"))
        self.assertFalse(crawl._in_scope("https://hackmit.org.evil.example/"))


class ReportTests(unittest.TestCase):
    def test_diff_against_previous_reports_new_findings(self) -> None:
        first = report.to_report(
            [extract.Finding("html_comment", "comment", "a", "https://hackmit.org/")],
            {"pages_fetched": 1, "assets_fetched": 0, "total_requests": 1},
        )
        second = report.to_report(
            [
                extract.Finding("html_comment", "comment", "a", "https://hackmit.org/"),
                extract.Finding("suspicious_link", "link", "/puzzle", "https://hackmit.org/"),
            ],
            {"pages_fetched": 1, "assets_fetched": 0, "total_requests": 1},
        )

        with tempfile.TemporaryDirectory() as tmp:
            first_notes = report.diff_against_previous(first, tmp)
            second_notes = report.diff_against_previous(second, tmp)

        self.assertEqual(first_notes, ["first run - no previous snapshot to diff against."])
        self.assertTrue(any("NEW finding" in note for note in second_notes))


class MonitorTests(unittest.TestCase):
    def test_monitor_hash_and_diff_detect_content_change(self) -> None:
        first = {
            "generated_at": "2026-01-01T00:00:00+00:00",
            "targets": [
                {
                    "name": "example",
                    "url": "https://example.test/a",
                    "kind": "json_collection",
                    "status": 200,
                    "sha256": monitor.sha256_text("[]"),
                    "summary": {"json": {"type": "list", "count": 0}},
                }
            ],
        }
        second = {
            "generated_at": "2026-01-01T00:01:00+00:00",
            "targets": [
                {
                    "name": "example",
                    "url": "https://example.test/a",
                    "kind": "json_collection",
                    "status": 200,
                    "sha256": monitor.sha256_text("[1]"),
                    "summary": {"json": {"type": "list", "count": 1}},
                }
            ],
        }

        with tempfile.TemporaryDirectory() as tmp:
            first_notes = monitor.diff_against_previous(first, tmp)
            second_notes = monitor.diff_against_previous(second, tmp)

        self.assertEqual(
            first_notes,
            ["first monitor run - no previous site snapshot to diff against."],
        )
        self.assertTrue(any("content hash changed" in note for note in second_notes))


if __name__ == "__main__":
    unittest.main()
