from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "darknavy-web3-planner.py"


def _load_tool():
    spec = importlib.util.spec_from_file_location("_darknavy_web3_planner", str(TOOL))
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


class DarknavyWeb3PlannerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tool = _load_tool()

    def test_default_plan_covers_web3_through_page_8(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo_root = Path(tmp)
            plan = self.tool.build_plan(repo_root=repo_root)

        self.assertEqual(plan["schema"], "auditooor.darknavy_web3_planner.v1")
        self.assertTrue(plan["offline_first"])
        self.assertFalse(plan["network_performed"])
        self.assertEqual(plan["page_range"], {"start": 1, "end": 8, "max_supported": 8})
        self.assertEqual(len(plan["planned_urls"]), 8)
        self.assertEqual(plan["planned_urls"][0]["url"], "https://www.darknavy.org/web3/")
        self.assertEqual(plan["planned_urls"][-1]["url"], "https://www.darknavy.org/web3/page/8/")
        self.assertEqual(plan["expected_source_ids"][0], "darknavy_web3_page_1")
        self.assertEqual(plan["expected_source_ids"][-1], "darknavy_web3_page_8")
        self.assertTrue(plan["output_cursor_path"].endswith(".auditooor/external_intel_cursors/darknavy_web3.json"))
        self.assertEqual(len(plan["etl_task_rows"]), 8)
        self.assertEqual(plan["etl_task_rows"][0]["task_type"], "darknavy_web3_archive_page_fetch")

    def test_local_html_snippets_extract_article_links(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo_root = Path(tmp)
            html_dir = repo_root / "fixtures"
            html_dir.mkdir()
            (html_dir / "web3.html").write_text(
                """
                <html><body>
                <a href="/web3/exploits/bridge-eth-tbtc-usdc-drain/">Exploit Report</a>
                <a href="https://www.darknavy.org/category/web3/">Category</a>
                <a href="https://www.darknavy.org/web3/page/2/">Next</a>
                <a href="https://example.com/not-darknavy/">Other</a>
                <a href="/blog/">Blog</a>
                <a href="/zh/">Language</a>
                <a href="/web3/skills/contract-auditor/">Skill page</a>
                <a href="/web3/exploits/bridge-eth-tbtc-usdc-drain/#comments">Duplicate</a>
                </body></html>
                """,
                encoding="utf-8",
            )
            (html_dir / "page-2.html").write_text(
                """
                <html><body>
                <a href="https://www.darknavy.org/web3/exploits/web3-security-review/">Security Review</a>
                <a href="/tag/zero-knowledge/">Tag</a>
                </body></html>
                """,
                encoding="utf-8",
            )

            plan = self.tool.build_plan(
                repo_root=repo_root,
                start_page=1,
                end_page=2,
                local_html_dir=html_dir,
            )

        self.assertEqual(plan["fetch_mode"], "local_html")
        self.assertEqual(
            plan["article_urls"],
            [
                "https://www.darknavy.org/web3/exploits/bridge-eth-tbtc-usdc-drain/",
                "https://www.darknavy.org/web3/exploits/web3-security-review/",
            ],
        )
        self.assertEqual(plan["article_count"], 2)
        task_types = [row["task_type"] for row in plan["etl_task_rows"]]
        self.assertEqual(task_types.count("darknavy_web3_archive_page_fetch"), 2)
        self.assertEqual(task_types.count("darknavy_web3_article_fetch"), 2)
        article_rows = [row for row in plan["etl_task_rows"] if row["task_type"] == "darknavy_web3_article_fetch"]
        self.assertEqual(article_rows[0]["source_id"], "darknavy_web3_article_bridge-eth-tbtc-usdc-drain")
        self.assertEqual(article_rows[0]["discovered_from_source_id"], "darknavy_web3_page_1")

    def test_page_range_is_enforced(self) -> None:
        with self.assertRaises(ValueError):
            self.tool.planned_pages(1, 9)
        with self.assertRaises(ValueError):
            self.tool.planned_pages(0, 1)
        with self.assertRaises(ValueError):
            self.tool.planned_pages(3, 2)

        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            rc = self.tool.main(["--end-page", "9"])
        self.assertEqual(rc, 2)
        self.assertIn("PAGE-RANGE-ERROR", stderr.getvalue())

    def test_fetch_without_local_html_fails_closed(self) -> None:
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            rc = self.tool.main(["--fetch"])
        self.assertEqual(rc, 3)
        self.assertIn("FETCH-BLOCKED", stderr.getvalue())

    def test_cli_writes_plan_from_local_html(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            repo_root = Path(tmp)
            html_dir = repo_root / "html"
            html_dir.mkdir()
            out = repo_root / "out" / "plan.json"
            (html_dir / "1.html").write_text(
                '<a href="/web3/exploits/wallet-signature-bypass/">Wallet Signature Bypass</a>',
                encoding="utf-8",
            )

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                rc = self.tool.main(
                    [
                        "--repo-root",
                        str(repo_root),
                        "--local-html-dir",
                        str(html_dir),
                        "--end-page",
                        "1",
                        "--out",
                        str(out),
                        "--json",
                    ]
                )

            self.assertEqual(rc, 0)
            manifest = json.loads(out.read_text(encoding="utf-8"))
            printed = json.loads(stdout.getvalue())
            self.assertEqual(manifest["article_urls"], ["https://www.darknavy.org/web3/exploits/wallet-signature-bypass/"])
            self.assertEqual(printed["article_urls"], manifest["article_urls"])
            self.assertEqual(manifest["etl_task_count"], 2)


if __name__ == "__main__":
    unittest.main()
