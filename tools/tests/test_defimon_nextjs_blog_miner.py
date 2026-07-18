"""Tests for tools/defimon-nextjs-blog-miner.py.

Hermetic tests validate build-id discovery, manifest route verification,
--max-posts capping, JSON-only output mode, and strict fixture-backed offline
execution.
"""

from __future__ import annotations

import importlib.util
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL = REPO_ROOT / "tools" / "defimon-nextjs-blog-miner.py"


def _load_tool():
    spec = importlib.util.spec_from_file_location("defimon_nextjs_blog_miner", str(TOOL))
    mod = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(mod)
    return mod


MINER = _load_tool()


def _build_fixture_payload(build_id: str, post_count: int = 3) -> dict:
    blog_html = f"""
    <html>
      <head>
        <script src=\"/_next/static/{build_id}/_buildManifest.js\"></script>
      </head>
      <body><h1>Defimon Blog</h1></body>
    </html>
    """.strip()

    build_manifest = {
        "pages": {
            "/": ["/"],
            "/blog": ["blog"],
            "/blog/[slug]": ["blog/[slug]"],
        },
        "some": "value",
    }
    build_payload = f"self.__BUILD_MANIFEST = {json.dumps(build_manifest)}"

    ssg_manifest = {
        "routes": [
            "/",
            "/blog",
            "/blog/[slug]",
        ]
    }
    ssg_payload = f"self.__SSG_MANIFEST = {json.dumps(ssg_manifest)}"

    posts = [
        {
            "slug": f"post-{i}",
            "title": f"Post {i}",
            "date": "2026-05-24",
            "impact": "theft",
        }
        for i in range(1, post_count + 1)
    ]
    index_payload = {"pageProps": {"posts": posts}}

    fixture: dict[str, dict | str] = {
        "https://defimon.xyz/blog": {
            "status_code": 200,
            "content_type": "text/html",
            "body": blog_html,
        },
        f"https://defimon.xyz/_next/static/{build_id}/_buildManifest.js": {
            "status_code": 200,
            "content_type": "application/javascript",
            "body": build_payload,
        },
        f"https://defimon.xyz/_next/static/{build_id}/_ssgManifest.js": {
            "status_code": 200,
            "content_type": "application/javascript",
            "content_type": "application/javascript",
            "body": ssg_payload,
        },
        f"https://defimon.xyz/_next/data/{build_id}/blog.json": {
            "status_code": 200,
            "content_type": "application/json",
            "body": json.dumps(index_payload),
        },
    }

    for post in posts:
        slug = post["slug"]
        post_url = (
            f"https://defimon.xyz/_next/data/{build_id}/blog/{slug}.json?slug={slug}"
        )
        fixture[post_url] = {
            "status_code": 200,
            "content_type": "application/json",
            "body": json.dumps(
                {
                    "pageProps": {
                        "post": {
                            "slug": slug,
                            "title": post["title"],
                            "content": f"Content for {slug}",
                        }
                    }
                }
            ),
        }

    return fixture


def _write_fixtures(payload: dict, tmpdir: str) -> Path:
    fixture_path = Path(tmpdir) / "defimon_nextjs_fixtures.json"
    fixture_path.write_text(json.dumps(payload), encoding="utf-8")
    return fixture_path


class TestDefimonNextjsBlogMiner(unittest.TestCase):
    def _run(self, args: list[str]) -> tuple[int, dict]:
        buf = io.StringIO()
        with mock.patch("sys.stdout", buf):
            rc = MINER.run(args)
        text = buf.getvalue().strip()
        return rc, json.loads(text)

    def test_extract_build_id_from_html(self) -> None:
        html = '<script src="/_next/static/abc123/_buildManifest.js"></script>'
        self.assertEqual(MINER.extract_build_id_from_blog_html(html), "abc123")

    def test_extract_routes_from_manifest(self) -> None:
        payload = 'self.__BUILD_MANIFEST = {"pages": {"/blog": [], "/blog/[slug]": [], "/other": []}}'
        routes = MINER.extract_manifest_routes(payload)
        self.assertEqual(routes, {"/blog", "/blog/[slug]"})

    def test_extract_routes_ignores_incidental_non_manifest_strings(self) -> None:
        payload = '{"note": "/blog/[slug]", "other": "/blog"}'
        self.assertEqual(MINER.extract_manifest_routes(payload), set())

    def test_happy_path_cap_posts_with_fixtures(self) -> None:
        build_id = "kkBUILD"
        with tempfile.TemporaryDirectory() as tmp:
            fixture_path = _write_fixtures(_build_fixture_payload(build_id, post_count=5), tmp)
            rc, report = self._run([
                "--inject-fixtures",
                str(fixture_path),
                "--json-only",
                "--max-posts",
                "2",
            ])
            self.assertEqual(rc, 0)
            self.assertEqual(report["status"], "ok")
            self.assertEqual(report["index"]["post_count"], 2)
            self.assertEqual(len(report["post_fetches"]), 2)
            self.assertEqual(report["requests_count"], 1 + 2 + 1 + 2)
            self.assertEqual(report["requested_urls"][:5], [
                "https://defimon.xyz/blog",
                f"https://defimon.xyz/_next/static/{build_id}/_buildManifest.js",
                f"https://defimon.xyz/_next/static/{build_id}/_ssgManifest.js",
                f"https://defimon.xyz/_next/data/{build_id}/blog.json",
                f"https://defimon.xyz/_next/data/{build_id}/blog/post-1.json?slug=post-1",
            ])

    def test_missing_routes_is_fatal(self) -> None:
        build_id = "badroutes"
        fixture = _build_fixture_payload(build_id)
        fixture[f"https://defimon.xyz/_next/static/{build_id}/_ssgManifest.js"] = {
            "status_code": 200,
            "content_type": "application/javascript",
            "body": "self.__SSG_MANIFEST = {\"routes\": [\"/\"]}",
        }
        fixture[f"https://defimon.xyz/_next/static/{build_id}/_buildManifest.js"] = {
            "status_code": 200,
            "content_type": "application/javascript",
            "body": "self.__BUILD_MANIFEST = {\"pages\": {\"/blog\": []}}",
        }
        with tempfile.TemporaryDirectory() as tmp:
            fixture_path = _write_fixtures(fixture, tmp)
            rc, report = self._run([
                "--inject-fixtures",
                str(fixture_path),
                "--json-only",
            ])
            self.assertEqual(rc, 2)
            self.assertEqual(report["status"], "failed")
            self.assertEqual(
                report["manifests"]["required_routes_present"],
                {"/blog": True, "/blog/[slug]": False},
            )
            self.assertTrue(any(row["severity"] == "fatal" for row in report["errors"]))

    def test_partial_errors_return_warn_status(self) -> None:
        build_id = "partial"
        fixture = _build_fixture_payload(build_id)
        post_url = f"https://defimon.xyz/_next/data/{build_id}/blog/post-2.json?slug=post-2"
        fixture[post_url]["body"] = json.dumps({"pageProps": {"post": {"slug": "post-2"}}})

        with tempfile.TemporaryDirectory() as tmp:
            fixture_path = _write_fixtures(fixture, tmp)
            rc, report = self._run([
                "--inject-fixtures",
                str(fixture_path),
                "--json-only",
                "--max-posts",
                "2",
            ])
            self.assertEqual(rc, 1)
            self.assertEqual(report["status"], "partial")
            warnings = [row for row in report["post_fetches"] if row["slug"] == "post-2"]
            self.assertEqual(len(warnings), 1)
            self.assertFalse(warnings[0]["has_content"])

    def test_offline_mode_does_not_call_network(self) -> None:
        build_id = "offline"
        fixture = _build_fixture_payload(build_id, post_count=1)
        with tempfile.TemporaryDirectory() as tmp:
            fixture_path = _write_fixtures(fixture, tmp)
            with mock.patch("urllib.request.urlopen") as urlopen:
                rc, report = self._run([
                    "--inject-fixtures",
                    str(fixture_path),
                    "--json-only",
                    "--max-posts",
                    "1",
                ])
            self.assertEqual(rc, 0)
            self.assertEqual(report["status"], "ok")
            urlopen.assert_not_called()

    def test_empty_fixture_file_stays_offline_and_fails(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            fixture_path = Path(tmp) / "empty.json"
            fixture_path.write_text("{}", encoding="utf-8")
            with mock.patch("urllib.request.urlopen") as urlopen:
                rc, report = self._run([
                    "--inject-fixtures",
                    str(fixture_path),
                    "--json-only",
                ])
            self.assertEqual(rc, 2)
            self.assertEqual(report["status"], "failed")
            self.assertIn("missing fixture", report["errors"][0]["reason"])
            urlopen.assert_not_called()

    def test_direct_api_rejects_negative_max_posts(self) -> None:
        with self.assertRaisesRegex(ValueError, "max_posts"):
            MINER.mine_defimon_blog(max_posts=-1, timeout_seconds=1, fixtures={}, strict_fixtures=True)


if __name__ == "__main__":
    unittest.main()
