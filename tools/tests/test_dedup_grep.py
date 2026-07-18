"""Tests for tools/dedup-grep.py — PR #120 lesson 1.

Regression target: engagement-5 N1 depth-mine missed OZ-2025-L-02 because
the agent's dedup checked KNOWN_ISSUES.md summary only, not the full
prior_audits/*.txt corpus. dedup-grep.py is the helper that prevents this.
"""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]
TOOL = REPO / "tools" / "dedup-grep.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("dedup_grep", TOOL)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class DedupGrepTest(unittest.TestCase):
    def _ws(self, tmp: str) -> Path:
        ws = Path(tmp) / "ws"
        (ws / "prior_audits").mkdir(parents=True)
        return ws

    def test_finds_known_oz_l02_in_full_text(self) -> None:
        """Positive case — the regression that motivated the tool. A prior
        audit body discusses `disputeId` + `_fisherman` + 'Double Jeopardy'.
        A candidate brief about 'missing _fisherman in indexing-dispute
        disputeId hash' must surface those hits."""
        with tempfile.TemporaryDirectory() as tmp:
            ws = self._ws(tmp)
            (ws / "prior_audits" / "2025-05-OZ.txt").write_text(textwrap.dedent("""
                The Graph Horizon Audit — Low Severity

                L-2 Double Jeopardy. For indexing disputes, the smart contract
                requires uniqueness of the disputeId, which is composed of
                the _allocationId and _poi. However, for query disputes, the
                disputeId includes the fisherman which created the dispute,
                meaning multiple disputes could be created for the same fault.

                Update: Acknowledged, will resolve.
            """).strip())
            candidate = ws / "candidate.md"
            candidate.write_text(textwrap.dedent("""
                # H3 — Missing `_fisherman` in indexing-dispute disputeId hash

                **Mechanism.** `_createIndexingDisputeWithAllocation` computes
                `keccak256(_allocationId, _poi, _blockNumber)` — does not
                include the fisherman address. Front-runner can grief.
            """).strip())
            mod = _load_module()
            keywords = mod.extract_keywords(candidate.read_text())
            self.assertIn("disputeid", [k.lower() for k in keywords])
            self.assertIn("fisherman", [k.lower() for k in keywords])
            result = mod.grep_prior_audits(ws, keywords)
            self.assertGreater(result["hit_count"], 0)
            self.assertTrue(any("Double Jeopardy" in h["snippet"] for h in result["hits"]))

    def test_unrelated_prior_audit_yields_zero_hits(self) -> None:
        """Negative case — a candidate about something the prior audit never
        discussed must produce zero hits and exit 0 (not a hard error).
        Caller treats zero-hit as 'cleared summary-level dedup, but verify
        with broader keywords before promoting'."""
        with tempfile.TemporaryDirectory() as tmp:
            ws = self._ws(tmp)
            (ws / "prior_audits" / "irrelevant.txt").write_text(
                "This audit is exclusively about ERC721 royalty rounding."
            )
            candidate = ws / "candidate.md"
            candidate.write_text(
                "# Candidate — `Vault.sweep()` ERC4626 share inflation\n\n"
                "Mechanism: standard donation attack on freshly-deployed vault.\n"
            )
            mod = _load_module()
            keywords = mod.extract_keywords(candidate.read_text())
            result = mod.grep_prior_audits(ws, keywords)
            self.assertEqual(result["hit_count"], 0)

    def test_cli_json_output(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = self._ws(tmp)
            (ws / "prior_audits" / "audit.txt").write_text(
                "L-1 reentrancy in foo() — Acknowledged."
            )
            candidate = ws / "cand.md"
            candidate.write_text("# Candidate — `foo()` reentrancy\n")
            out = ws / "result.json"
            proc = subprocess.run(
                [sys.executable, str(TOOL), str(ws),
                 "--candidate", str(candidate), "--json", "--out", str(out)],
                capture_output=True, text=True, timeout=20,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            data = json.loads(out.read_text())
            self.assertGreater(data["hit_count"], 0)
            self.assertIn("foo", data["keywords"])

    def test_cli_explicit_keyword_overrides_auto(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = self._ws(tmp)
            (ws / "prior_audits" / "a.txt").write_text("xyzunique payload here.")
            proc = subprocess.run(
                [sys.executable, str(TOOL), str(ws),
                 "--keyword", "xyzunique", "--json"],
                capture_output=True, text=True, timeout=20,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            data = json.loads(proc.stdout)
            self.assertEqual(data["keywords"], ["xyzunique"])
            self.assertEqual(data["hit_count"], 1)

    def test_cli_missing_workspace_returns_error(self) -> None:
        proc = subprocess.run(
            [sys.executable, str(TOOL), "/no/such/path",
             "--keyword", "anything"],
            capture_output=True, text=True, timeout=20,
        )
        self.assertEqual(proc.returncode, 1)

    def test_cli_no_keywords_returns_argparse_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = self._ws(tmp)
            proc = subprocess.run(
                [sys.executable, str(TOOL), str(ws)],
                capture_output=True, text=True, timeout=20,
            )
            self.assertEqual(proc.returncode, 2)


if __name__ == "__main__":
    unittest.main()
