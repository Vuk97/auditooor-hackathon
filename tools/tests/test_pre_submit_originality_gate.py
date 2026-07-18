#!/usr/bin/env python3
"""Regression coverage for Check 5 originality-before-proof integration."""
from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
PRE_SUBMIT = ROOT / "tools" / "pre-submit-check.sh"


def _inline_poc_block() -> str:
    lines = [
        "```solidity",
        "pragma solidity ^0.8.20;",
        "contract DemoTest {",
        "    function testExploit() public {",
        "        uint256 total = 0;",
    ]
    for idx in range(40):
        lines.append(f"        total += {idx + 1};")
    lines.extend(
        [
            "        assert(total > 0);",
            "    }",
            "}",
            "```",
        ]
    )
    return "\n".join(lines)


def _draft(originality_lines: list[str]) -> str:
    return "\n".join(
        [
            "# Replay bug in Vault allows draining user funds",
            "",
            "**Severity:** High",
            "**Rubric:** Direct theft of user funds.",
            "**Dollar impact:** $500,000 of user funds.",
            "**In-scope:** source-level accounting bug.",
            "",
            "## Impact",
            "",
            "The attacker drains user funds from the vault.",
            "",
            "## In-Scope Trigger / Root Cause",
            "",
            "A non-privileged attacker can replay `withdraw()` before accounting settles.",
            "",
            "## Proof of Concept",
            "",
            "PoC path: poc-tests/Demo.t.sol",
            "",
            _inline_poc_block(),
            "",
            "## Impact Contract",
            "",
            "- Victim: vault LPs",
            "- Source proof: src/Vault.sol:90-138",
            "- Harness scaffold: poc-tests/Demo.t.sol",
            "",
            "## Originality / Duplicate Review",
            "",
            *originality_lines,
            "",
        ]
    )


def _run(draft: Path) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["AUDITS_DIR"] = str(draft.parent / "audits")
    return subprocess.run(
        ["bash", str(PRE_SUBMIT), str(draft), "--severity", "High"],
        capture_output=True,
        text=True,
        env=env,
    )


class PreSubmitOriginalityGateTests(unittest.TestCase):
    def test_high_plus_explicit_fail_surfaces_check5_failure(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            draft = root / "fail.md"
            draft.write_text(
                _draft(
                    [
                        "- Originality-before-proof: FAIL",
                        "- duplicate of prior report R-17.",
                    ]
                ),
                encoding="utf-8",
            )
            proc = _run(draft)
            self.assertIn("5. originality-before-proof:", proc.stdout, proc.stdout)
            self.assertIn("Draft records an explicit duplicate/fail originality posture", proc.stdout, proc.stdout)

    def test_high_plus_explicit_pass_surfaces_check5_success(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            draft = root / "pass.md"
            draft.write_text(
                _draft(
                    [
                        "- Originality grep: zero hits across prior audit corpus.",
                        "- locally novel with no local submitted duplicate.",
                    ]
                ),
                encoding="utf-8",
            )
            proc = _run(draft)
            self.assertIn("5. originality-before-proof:", proc.stdout, proc.stdout)
            self.assertIn("bounded novel/no-hits", proc.stdout, proc.stdout)


if __name__ == "__main__":
    unittest.main(verbosity=2)
