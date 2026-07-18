from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]
PRIORITIZER = REPO / "tools" / "mining-prioritizer.py"
BRIEF_GENERATOR = REPO / "tools" / "mining-brief-generator.py"


class MiningPrioritizerCciaRustTests(unittest.TestCase):
    def test_mining_briefs_use_structured_attack_angle_dossier(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "structured"
            ws.mkdir()
            (ws / ".auditooor").mkdir()
            (ws / ".auditooor" / "ccia_attack_angles.json").write_text(
                json.dumps([
                    {
                        "id": "A-AUTH",
                        "severity": "HIGH",
                        "title": "Unauthenticated state write: Fake.claim",
                        "contracts": ["Fake"],
                        "line": 7,
                    }
                ])
                + "\n",
                encoding="utf-8",
            )
            (ws / "ccia_report.md").write_text("# lossy legacy report\n")
            out_dir = ws / "swarm" / "mining_briefs"
            result = subprocess.run(
                [sys.executable, str(BRIEF_GENERATOR), str(ws), "--top", "1", "--out-dir", str(out_dir)],
                cwd=REPO,
                capture_output=True,
                text=True,
                timeout=20,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            body = next(out_dir.glob("*.md")).read_text(encoding="utf-8")
            self.assertIn("**Target:** `Fake`", body)
            self.assertNotIn("**Target:** `UNKNOWN`", body)

    def test_empty_solidity_ccia_falls_back_to_ccia_rust_report(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "k2"
            ws.mkdir()
            (ws / "ccia_report.json").write_text(
                json.dumps({"ccia": {}, "attack_angles": []}) + "\n",
                encoding="utf-8",
            )
            (ws / "ccia_rust_report.json").write_text(
                json.dumps(
                    {
                        "workspace": str(ws),
                        "lang": "rust",
                        "total_files_scanned": 2,
                        "angles": [
                            {
                                "angle": "A-AUTH",
                                "confidence": "medium",
                                "file": "src/contracts/kinetic-router/src/router.rs",
                                "line": 42,
                                "reason": "state-changing entrypoint uses require_auth",
                                "snippet": "user.require_auth();",
                            },
                            {
                                "angle": "A-ROUNDING",
                                "confidence": "low",
                                "file": "src/contracts/shared/src/utils.rs",
                                "line": 77,
                                "reason": "division after multiplication",
                                "snippet": "x / y",
                            },
                        ],
                    }
                )
                + "\n",
                encoding="utf-8",
            )

            result = subprocess.run(
                [
                    sys.executable,
                    str(PRIORITIZER),
                    str(ws),
                    "--top",
                    "5",
                    "--json",
                    "--no-outcome-reweight",
                ],
                cwd=REPO,
                capture_output=True,
                text=True,
                timeout=20,
            )

            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            payload = json.loads(result.stdout)
            rows = payload["angles"] if isinstance(payload, dict) else payload
            self.assertGreaterEqual(len(rows), 2)
            self.assertEqual(rows[0]["id"], "A-AUTH")
            self.assertEqual(rows[0]["severity"], "HIGH")
            self.assertIn("kinetic-router", rows[0]["contracts"])
            self.assertIn("state-changing entrypoint", rows[0]["title"])

    def test_mining_brief_generator_uses_same_ccia_rust_fallback(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "k2"
            ws.mkdir()
            (ws / "ccia_report.json").write_text(
                json.dumps({"ccia": {}, "attack_angles": []}) + "\n",
                encoding="utf-8",
            )
            (ws / "ccia_rust_report.json").write_text(
                json.dumps(
                    {
                        "workspace": str(ws),
                        "lang": "rust",
                        "total_files_scanned": 1,
                        "angles": [
                            {
                                "angle": "A-ORACLE",
                                "confidence": "medium",
                                "file": "src/contracts/price-oracle/src/oracle.rs",
                                "line": 12,
                                "reason": "oracle read uses cached value",
                                "snippet": "read_price();",
                            }
                        ],
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            out_dir = ws / "swarm" / "mining_briefs"

            result = subprocess.run(
                [
                    sys.executable,
                    str(BRIEF_GENERATOR),
                    str(ws),
                    "--top",
                    "1",
                    "--out-dir",
                    str(out_dir),
                ],
                cwd=REPO,
                capture_output=True,
                text=True,
                timeout=20,
            )

            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            briefs = list(out_dir.glob("*.md"))
            self.assertEqual(len(briefs), 1)
            body = briefs[0].read_text(encoding="utf-8")
            self.assertIn("A-ORACLE", body)
            self.assertIn("price-oracle", body)

    def test_mining_brief_generator_inlines_bug_bounty_oos_preflight(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "k2"
            ws.mkdir()
            (ws / "BUG_BOUNTY.md").write_text(
                "\n".join(
                    [
                        "# Program Rules",
                        "",
                        "## AI-Tool False-Positive Patterns",
                        "",
                        "| Row | Pattern | Classification |",
                        "|---|---|---|",
                        "| 42 | Front-running / sandwich / MEV via public mempool using minOut or slippage | OOS |",
                    ]
                )
                + "\n",
                encoding="utf-8",
            )
            (ws / "SEVERITY.md").write_text("- Direct loss of funds\n", encoding="utf-8")
            (ws / "ccia_report.json").write_text(
                json.dumps({"ccia": {}, "attack_angles": []}) + "\n",
                encoding="utf-8",
            )
            (ws / "ccia_rust_report.json").write_text(
                json.dumps(
                    {
                        "workspace": str(ws),
                        "lang": "rust",
                        "total_files_scanned": 1,
                        "angles": [
                            {
                                "angle": "A-ORACLE",
                                "confidence": "medium",
                                "file": "src/contracts/origin-vault-base/src/lib.rs",
                                "line": 193,
                                "reason": "slippage and minOut MEV public mempool path",
                                "snippet": "claim_without_min_out();",
                            }
                        ],
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            out_dir = ws / "swarm" / "mining_briefs"

            result = subprocess.run(
                [
                    sys.executable,
                    str(BRIEF_GENERATOR),
                    str(ws),
                    "--top",
                    "1",
                    "--out-dir",
                    str(out_dir),
                ],
                cwd=REPO,
                capture_output=True,
                text=True,
                timeout=20,
            )

            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            body = next(out_dir.glob("*.md")).read_text(encoding="utf-8")
            self.assertIn("Brief-Time OOS / AI-FP / Known-Issue Preflight", body)
            self.assertIn("CANDIDATE-FOR-EXTENSION-DISTINCT-ARGUMENT", body)
            self.assertIn("fail-ai-fp-catalog-match", body)
            self.assertIn("Required Extension-Distinct Argument", body)


if __name__ == "__main__":
    unittest.main()
