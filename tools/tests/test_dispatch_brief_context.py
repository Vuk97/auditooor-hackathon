from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]


class DispatchBriefContextTest(unittest.TestCase):
    def test_accepts_non_checkbox_oos_and_severity_caps(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            (ws / "agent_outputs").mkdir()
            (ws / "OOS_CHECKLIST.md").write_text(
                "# OOS\n\n- **OOS-1**: private-key compromise is out.\n"
            )
            (ws / "SEVERITY_CAPS.md").write_text(
                "# Caps\n\n- **Critical — Smart Contract:** direct theft.\n"
            )
            (ws / "PRIOR_CONCERNS.md").write_text(
                "prior-concern: verifier routing must preserve policy\n"
            )
            contract = ws / "Verifier.sol"
            contract.write_text("contract Verifier {}\n")

            proc = subprocess.run(
                [
                    "bash",
                    str(REPO / "tools" / "agent-dispatch-enforced.sh"),
                    str(ws),
                    str(contract),
                    "check verifier routing",
                ],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )

            self.assertEqual(proc.returncode, 0, proc.stderr + proc.stdout)
            self.assertNotIn("brief missing blocks", proc.stdout)
            brief = next((ws / "agent_outputs").glob("brief_*.md"))
            text = brief.read_text()
            self.assertIn("OOS-1", text)
            self.assertIn("Critical", text)

    def test_dispatch_brief_includes_bug_bounty_oos_preflight(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            (ws / "agent_outputs").mkdir()
            (ws / "OOS_CHECKLIST.md").write_text(
                "# OOS\n\n- **OOS-1**: front-running is out of scope.\n",
                encoding="utf-8",
            )
            (ws / "SEVERITY_CAPS.md").write_text(
                "# Caps\n\n- **High**: direct theft only.\n",
                encoding="utf-8",
            )
            (ws / "PRIOR_CONCERNS.md").write_text(
                "prior-concern: slippage via public mempool is known OOS\n",
                encoding="utf-8",
            )
            (ws / "BUG_BOUNTY.md").write_text(
                "\n".join(
                    [
                        "# Program Rules",
                        "",
                        "## AI-Tool False-Positive Patterns",
                        "",
                        "| Row | Pattern | Classification |",
                        "|---|---|---|",
                        "| 42 | Front-running / sandwich / MEV via public mempool against slippage or minOut paths | OOS |",
                    ]
                ),
                encoding="utf-8",
            )
            contract = ws / "SlippageRouter.sol"
            contract.write_text("contract SlippageRouter {}\n", encoding="utf-8")

            proc = subprocess.run(
                [
                    "bash",
                    str(REPO / "tools" / "agent-dispatch-enforced.sh"),
                    str(ws),
                    str(contract),
                    "investigate slippage MEV public mempool minOut",
                ],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )

            self.assertEqual(proc.returncode, 0, proc.stderr + proc.stdout)
            brief = next((ws / "agent_outputs").glob("brief_*.md"))
            text = brief.read_text(encoding="utf-8")
            self.assertIn("Brief-Time OOS / AI-FP / Known-Issue Preflight", text)
            self.assertIn("fail-ai-fp-catalog-match", text)
            self.assertIn("CANDIDATE-FOR-EXTENSION-DISTINCT-ARGUMENT", text)
            self.assertIn("Required Extension-Distinct Argument", text)


if __name__ == "__main__":
    unittest.main()
