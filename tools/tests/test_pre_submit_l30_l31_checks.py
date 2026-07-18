#!/usr/bin/env python3
"""Regression coverage for pre-submit L30/L31 enforcement."""

from __future__ import annotations

import os
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
PRE_SUBMIT = ROOT / "tools" / "pre-submit-check.sh"


def _workspace(root: Path) -> Path:
    ws = root / "audits" / "demo"
    for lane in ("paste_ready", "staging", "packaged", "held"):
        (ws / "submissions" / lane).mkdir(parents=True, exist_ok=True)
    return ws


def _run(draft: Path, ws: Path) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["AUDITS_DIR"] = str(ws.parent)
    env["TARGET_PLATFORM"] = "auto"
    return subprocess.run(
        ["bash", str(PRE_SUBMIT), str(draft), "--severity", "High"],
        capture_output=True,
        text=True,
        env=env,
    )


def _base_draft(extra: str = "") -> str:
    return textwrap.dedent(
        f"""
        # Missing guard in Vault allows draining user funds

        **Severity:** High
        **Rubric:** Direct theft of user funds.
        **Dollar impact:** $500,000 of user funds.
        **Originality:** prior audit grep run completed.
        **In-scope:** source-level accounting bug.

        ## Impact

        Non-self impact demonstrated: victim LP funds are debited, and funds the attacker does not control are transferred.

        ## Impact Contract

        - Victim: vault LPs
        - Source proof: src/Vault.sol:90-138
        - Harness scaffold: poc-tests/VaultRacePlan.t.sol
        - selected_impact: Direct theft of user funds
        - severity_tier: High
        - listed_impact_proven: true
        - evidence_class: source_review
        - oos_traps: admin-only path excluded
        - stop_condition: stop if proof no longer drains funds

        {extra}
        """
    ).strip() + "\n"


class PreSubmitL30L31Tests(unittest.TestCase):
    def test_l30_missing_guard_without_enumerated_call_sites_blocks(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ws = _workspace(root)
            draft = ws / "submissions" / "paste_ready" / "candidate.md"
            draft.write_text(
                _base_draft(
                    "Root cause: missing guard `onlyOwner` on the withdrawal path."
                ),
                encoding="utf-8",
            )
            proc = _run(draft, ws)
            self.assertIn("48. L30-MISSING-GUARD-ENUMERATION blocked", proc.stdout, proc.stdout)

    def test_l30_enumerated_call_sites_section_passes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ws = _workspace(root)
            draft = ws / "submissions" / "paste_ready" / "candidate.md"
            draft.write_text(
                _base_draft(
                    """
                    Root cause: missing guard `onlyOwner` on the withdrawal path.

                    ## Enumerated Call Sites

                    | Site | Disposition |
                    |---|---|
                    | `src/Vault.sol:90` | real missing-guard exposure |
                    | `src/Vault.sol:140` | already covered by `onlyOwner` |
                    """
                ),
                encoding="utf-8",
            )
            proc = _run(draft, ws)
            self.assertIn("48. L30-MISSING-GUARD-ENUMERATION:", proc.stdout, proc.stdout)
            self.assertIn("enumerated_call_sites_present", proc.stdout, proc.stdout)

    def test_l31_duplicate_preflight_blocks_shared_file_and_fix(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ws = _workspace(root)
            prior = ws / "submissions" / "staging" / "prior.md"
            draft = ws / "submissions" / "paste_ready" / "candidate.md"
            prior.write_text(
                _base_draft(
                    "Affected file: `src/Vault.sol:90`. Fix reference: `deadbeef1234`."
                ),
                encoding="utf-8",
            )
            draft.write_text(
                _base_draft(
                    "Affected file: `src/Vault.sol:90`. Fix reference: `deadbeef1234`."
                ),
                encoding="utf-8",
            )
            proc = _run(draft, ws)
            self.assertIn("49. L31-DUPE-PREFLIGHT blocked", proc.stdout, proc.stdout)
            self.assertIn("verdict=duplicate", proc.stdout, proc.stdout)

    def test_l31_rebuttal_allows_operator_override(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ws = _workspace(root)
            prior = ws / "submissions" / "staging" / "prior.md"
            draft = ws / "submissions" / "paste_ready" / "candidate.md"
            prior.write_text(
                _base_draft(
                    "Affected file: `src/Vault.sol:90`. Fix reference: `deadbeef1234`."
                ),
                encoding="utf-8",
            )
            draft.write_text(
                _base_draft(
                    """
                    <!-- l31-rebuttal: prior different invariant; same file but fix does not cover this path -->
                    Affected file: `src/Vault.sol:90`. Fix reference: `deadbeef1234`.
                    """
                ),
                encoding="utf-8",
            )
            proc = _run(draft, ws)
            self.assertIn("49. L31-DUPE-PREFLIGHT:", proc.stdout, proc.stdout)
            self.assertIn("duplicate_with_operator_override", proc.stdout, proc.stdout)

    def test_l31_visible_rebuttal_allows_override_without_html_comment(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ws = _workspace(root)
            prior = ws / "submissions" / "staging" / "prior.md"
            draft = ws / "submissions" / "paste_ready" / "candidate.md"
            prior.write_text(
                _base_draft(
                    "Affected file: `src/Vault.sol:90`. Fix reference: `deadbeef1234`."
                ),
                encoding="utf-8",
            )
            draft.write_text(
                _base_draft(
                    """
                    l31_rebuttal: prior different invariant; same file but fix does not cover this path
                    Affected file: `src/Vault.sol:90`. Fix reference: `deadbeef1234`.
                    """
                ),
                encoding="utf-8",
            )
            proc = _run(draft, ws)
            self.assertNotIn("FINAL-PASTE-HYGIENE blocked", proc.stdout, proc.stdout)
            self.assertIn("49. L31-DUPE-PREFLIGHT:", proc.stdout, proc.stdout)
            self.assertIn("duplicate_with_operator_override", proc.stdout, proc.stdout)


if __name__ == "__main__":
    unittest.main(verbosity=2)
