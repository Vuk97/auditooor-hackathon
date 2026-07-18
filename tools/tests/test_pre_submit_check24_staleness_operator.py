#!/usr/bin/env python3
"""Check #24 regression for cross-contract staleness operator mismatch."""
from __future__ import annotations

import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
PRE_SUBMIT = ROOT / "tools" / "pre-submit-check.sh"


def _run_pre_submit(draft: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["bash", str(PRE_SUBMIT), str(draft), "--severity", "Medium"],
        capture_output=True,
        text=True,
    )


class Check24StalenessOperatorTests(unittest.TestCase):
    def test_flags_strict_inclusive_timestamp_boundary_pair(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            draft = Path(tmp) / "draft.md"
            draft.write_text(
                textwrap.dedent(
                    """
                    # Finding: inconsistent freshness boundary

                    NitroEnclaveVerifier rejects when
                    attestationTimestamp + MAX_AGE < block.timestamp.
                    TEEProverRegistry rejects when
                    attestationTimestamp + MAX_AGE <= block.timestamp.

                    The same attestation at the exact boundary is valid in one
                    contract and stale in the other.
                    """
                ).strip()
                + "\n"
            )

            proc = _run_pre_submit(draft)
            self.assertIn(
                "24. cross_contract_staleness_operator_mismatch",
                proc.stdout,
                proc.stdout,
            )
            self.assertIn("NitroEnclaveVerifier", proc.stdout)
            self.assertIn("TEEProverRegistry", proc.stdout)

    def test_same_operator_pair_is_not_flagged(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            draft = Path(tmp) / "draft.md"
            draft.write_text(
                textwrap.dedent(
                    """
                    # Finding: consistent freshness boundary

                    NitroEnclaveVerifier rejects when
                    attestationTimestamp + MAX_AGE <= block.timestamp.
                    TEEProverRegistry rejects when
                    attestationTimestamp + MAX_AGE <= block.timestamp.
                    """
                ).strip()
                + "\n"
            )

            proc = _run_pre_submit(draft)
            self.assertIn(
                "24. cross-contract staleness operators: no strict/inclusive mismatch detected",
                proc.stdout,
                proc.stdout,
            )
            self.assertNotIn("cross_contract_staleness_operator_mismatch", proc.stdout)


if __name__ == "__main__":
    unittest.main()
