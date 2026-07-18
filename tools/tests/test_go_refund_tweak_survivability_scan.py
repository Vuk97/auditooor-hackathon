#!/usr/bin/env python3
"""Regression tests for Go refund/key-tweak survivability advisory scanner."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
SCANNER = ROOT / "tools" / "go-refund-tweak-survivability-scan.py"


def _run(target: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run([sys.executable, str(SCANNER), str(target), "--json"], capture_output=True, text=True)


def _write_positive_workspace(root: Path) -> None:
    (root / "statechain").mkdir()
    (root / "statechain" / "model.go").write_text(
        textwrap.dedent(
            """
            package statechain

            type StatechainRecord struct {
                StatechainID string `db:"statechain_id"`
                VerifyingPubKey []byte `json:"verifying_pubkey" db:"verifying_pubkey"` // immutable verifier key
                RawRefundTx []byte `db:"raw_refund_tx"`
                SignedRefundTx []byte `db:"signed_refund_tx"`
            }

            func SaveRefundTx(id string, rawRefundTx []byte, signedRefundTx []byte) error {
                return refundRepo.Put(id, rawRefundTx, signedRefundTx)
            }
            """
        ).lstrip()
    )
    (root / "statechain" / "tweak.go").write_text(
        textwrap.dedent(
            """
            package statechain

            func ApplyAdditiveKeyShareTweak(keyShare []byte, tweak []byte) []byte {
                return append(keyShare, tweak...)
            }

            func UpdateKeyShareAfterTweak(id string, keyShare []byte) error {
                return shareStore.Update(id, keyShare)
            }
            """
        ).lstrip()
    )


def _walk_keys(value: Any) -> list[str]:
    if isinstance(value, dict):
        keys = list(value)
        for item in value.values():
            keys.extend(_walk_keys(item))
        return keys
    if isinstance(value, list):
        keys: list[str] = []
        for item in value:
            keys.extend(_walk_keys(item))
        return keys
    return []


class GoRefundTweakSurvivabilityScanTests(unittest.TestCase):
    def test_flags_cooccurrence_without_refund_revocation_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "statechain").mkdir()
            (root / "statechain" / "model.go").write_text(
                textwrap.dedent(
                    """
                    package statechain

                    type StatechainRecord struct {
                        StatechainID string `db:"statechain_id"`
                        VerifyingPubKey []byte `json:"verifying_pubkey" db:"verifying_pubkey"` // immutable verifier key
                        RawRefundTx []byte `db:"raw_refund_tx"`
                        SignedRefundTx []byte `db:"signed_refund_tx"`
                    }

                    func SaveRefundTx(id string, rawRefundTx []byte, signedRefundTx []byte) error {
                        return refundRepo.Put(id, rawRefundTx, signedRefundTx)
                    }
                    """
                ).lstrip()
            )
            (root / "statechain" / "tweak.go").write_text(
                textwrap.dedent(
                    """
                    package statechain

                    func ApplyAdditiveKeyShareTweak(keyShare []byte, tweak []byte) []byte {
                        return append(keyShare, tweak...)
                    }

                    func UpdateKeyShareAfterTweak(id string, keyShare []byte) error {
                        return shareStore.Update(id, keyShare)
                    }
                    """
                ).lstrip()
            )

            proc = _run(root)
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            out = json.loads(proc.stdout)
            self.assertEqual(out["posture"], "NOT_SUBMIT_READY")
            self.assertTrue(out["advisory_only"])
            self.assertFalse(out["submission_ready"])
            self.assertFalse(out["refund_invalidation_path_present"])
            self.assertEqual(len(out["findings"]), 1, out)

            finding = out["findings"][0]
            self.assertEqual(finding["pattern"], "go_refund_tweak_survivability_surface_without_refund_revocation")
            self.assertEqual(finding["posture"], "NOT_SUBMIT_READY")
            self.assertFalse(finding["refund_invalidation_path_present"])
            self.assertGreaterEqual(len(finding["evidence"]["verifying_key_schema"]), 1, finding)
            self.assertGreaterEqual(len(finding["evidence"]["key_share_tweak"]), 1, finding)
            self.assertGreaterEqual(len(finding["evidence"]["refund_tx_persistence"]), 1, finding)
            self.assertNotIn("severity", _walk_keys(out))

    def test_clean_when_refund_invalidation_path_is_present(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "wallet").mkdir()
            (root / "wallet" / "refunds.go").write_text(
                textwrap.dedent(
                    """
                    package wallet

                    type StatechainRecord struct {
                        VerifyingPubKey []byte `db:"verifying_pubkey"`
                        RawRefundTx []byte `db:"raw_refund_tx"`
                    }

                    func TweakKeyShare(keyShare []byte, tweak []byte) []byte {
                        return append(keyShare, tweak...)
                    }

                    func SaveRefundTransaction(id string, rawRefundTx []byte) error {
                        return db.Insert("refund_tx", id, rawRefundTx)
                    }

                    func RevokeRefundTx(id string) error {
                        return db.Delete("refund_tx", id)
                    }
                    """
                ).lstrip()
            )

            proc = _run(root)
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            out = json.loads(proc.stdout)
            self.assertEqual(out["findings"], [], out)
            self.assertTrue(out["cooccurrence_present"], out)
            self.assertTrue(out["refund_invalidation_path_present"], out)
            self.assertGreaterEqual(len(out["signals"]["refund_invalidation"]), 1, out)
            self.assertNotIn("severity", _walk_keys(out))

    def test_clean_when_only_refund_storage_exists(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "refunds.go").write_text(
                textwrap.dedent(
                    """
                    package wallet

                    func SaveRefundTx(id string, rawRefundTx []byte) error {
                        return refundRepo.Put(id, rawRefundTx)
                    }
                    """
                ).lstrip()
            )

            proc = _run(root)
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            out = json.loads(proc.stdout)
            self.assertEqual(out["findings"], [], out)
            self.assertFalse(out["cooccurrence_present"], out)

    def test_make_wrapper_writes_json_and_succeeds_on_advisory_findings(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_positive_workspace(root)

            proc = subprocess.run(
                ["make", "go-refund-tweak-survivability-scan", f"WS={root}"],
                cwd=ROOT,
                capture_output=True,
                text=True,
                timeout=15,
            )

            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            artifact = root / "audit" / "go-refund-tweak-survivability-scan.json"
            self.assertTrue(artifact.exists(), proc.stdout + proc.stderr)
            out = json.loads(artifact.read_text())
            self.assertTrue(out["findings"], out)
            self.assertEqual(out["posture"], "NOT_SUBMIT_READY")


if __name__ == "__main__":
    unittest.main()
