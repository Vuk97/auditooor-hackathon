from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]
TOOL = REPO / "tools" / "dispatch_oos_preflight.py"


def _run(args: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(TOOL), *args],
        cwd=REPO,
        capture_output=True,
        text=True,
        timeout=20,
    )


class DispatchOosPreflightTests(unittest.TestCase):
    def test_bug_bounty_ai_fp_match_requires_extension_distinct(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            (ws / "BUG_BOUNTY.md").write_text(
                "\n".join(
                    [
                        "# Program Rules",
                        "",
                        "## AI-Tool False-Positive Patterns",
                        "",
                        "| Row | Pattern | Classification |",
                        "|---|---|---|",
                        "| 42 | Front-running / sandwich / MEV via public mempool against contracts using minOut or slippage | OOS |",
                        "",
                        "## Known Issues / Acknowledged Design Decisions",
                        "",
                        "| ID | Issue |",
                        "|---|---|",
                        "| SE-P1 | Slippage on two-step request and claim flows is acknowledged by design |",
                    ]
                ),
                encoding="utf-8",
            )
            (ws / "SEVERITY.md").write_text(
                "- Direct loss of funds\n- Front-running attacks only OOS\n",
                encoding="utf-8",
            )

            proc = _run(
                [
                    "--workspace",
                    str(ws),
                    "--candidate-json",
                    json.dumps(
                        {
                            "id": "S1",
                            "severity": "HIGH",
                            "title": "OriginVaultBase no slippage MEV public mempool candidate",
                            "cluster": "erc4626-functions-no-slippage",
                        }
                    ),
                ]
            )

            self.assertEqual(proc.returncode, 0, proc.stderr)
            payload = json.loads(proc.stdout)
            self.assertEqual(payload["verdict"], "needs-extension-distinct-argument")
            self.assertEqual(
                payload["recommended_severity"],
                "CANDIDATE-FOR-EXTENSION-DISTINCT-ARGUMENT",
            )
            self.assertEqual(payload["dryruns"]["ai_fp_dryrun"], "fail-ai-fp-catalog-match")
            self.assertTrue(any(m["category"] == "ai_fp" for m in payload["matches"]))
            self.assertIn("slippage", {t for m in payload["matches"] for t in m["overlap_terms"]})

    def test_existing_negative_poc_scan_surfaces_mustbefresh(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            test_dir = ws / "test"
            test_dir.mkdir()
            (test_dir / "EIP1153TransientAuthTest.t.sol").write_text(
                "\n".join(
                    [
                        "contract EIP1153TransientAuthTest {",
                        "  function test_VG_2_ReadSlot_MustBeFresh() public {",
                        "    // transient auth read slot must be fresh",
                        "  }",
                        "}",
                    ]
                ),
                encoding="utf-8",
            )

            proc = _run(
                [
                    "--workspace",
                    str(ws),
                    "--candidate-text",
                    "EIP1153 transient auth ReadSlot freshness bypass",
                    "--candidate-id",
                    "eip1153-transient-auth",
                    "--severity",
                    "HIGH",
                ]
            )

            self.assertEqual(proc.returncode, 0, proc.stderr)
            payload = json.loads(proc.stdout)
            hits = payload["existing_poc_hits"]
            self.assertEqual(len(hits), 1)
            self.assertTrue(hits[0]["negative_hint"])
            self.assertIn("MustBeFresh", hits[0]["excerpt"])

    def test_no_catalog_match_passes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            (ws / "BUG_BOUNTY.md").write_text("# Rules\n\nNo special catalog.\n", encoding="utf-8")

            proc = _run(
                [
                    "--workspace",
                    str(ws),
                    "--candidate-text",
                    "unrelated authorization state mutation",
                    "--severity",
                    "MEDIUM",
                ]
            )

            self.assertEqual(proc.returncode, 0, proc.stderr)
            payload = json.loads(proc.stdout)
            self.assertEqual(payload["verdict"], "pass-no-oos-catalog-match")
            self.assertEqual(payload["matches"], [])

    def test_consumes_existing_bug_bounty_oos_index(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            index_dir = ws / ".auditooor"
            index_dir.mkdir()
            (index_dir / "bug_bounty_oos_index.json").write_text(
                json.dumps(
                    {
                        "clauses": [
                            {
                                "clause": "AI-FP-row-42",
                                "category": "ai_fp",
                                "phrase": "MEV public mempool slippage false positive",
                                "source": "BUG_BOUNTY.md",
                                "line": 42,
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )

            proc = _run(
                [
                    "--workspace",
                    str(ws),
                    "--candidate-text",
                    "slippage MEV public mempool",
                    "--severity",
                    "HIGH",
                ]
            )

            self.assertEqual(proc.returncode, 0, proc.stderr)
            payload = json.loads(proc.stdout)
            self.assertEqual(payload["verdict"], "needs-extension-distinct-argument")
            self.assertEqual(payload["matches"][0]["clause_id"], "AI-FP-row-42")
            self.assertEqual(payload["matches"][0]["source"], "BUG_BOUNTY.md")


if __name__ == "__main__":
    unittest.main()
