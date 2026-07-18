#!/usr/bin/env python3
"""Tests for tools/base-consensus-patch-scan.py."""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCANNER = ROOT / "tools" / "base-consensus-patch-scan.py"


def _write_source(workspace: Path, body: str) -> None:
    crate = workspace / "external" / "base" / "crates" / "consensus" / "protocol"
    crate.mkdir(parents=True, exist_ok=True)
    (crate / "Cargo.toml").write_text(
        textwrap.dedent(
            """
            [package]
            name = "synthetic"
            version = "0.1.0"
            edition = "2021"
            """
        ).lstrip()
    )
    src = crate / "src" / "attributes.rs"
    src.parent.mkdir(parents=True, exist_ok=True)
    src.write_text(body)


def _run(workspace: Path, extra_args: list[str] | None = None) -> subprocess.CompletedProcess[str]:
    cmd = [
        sys.executable,
        str(SCANNER),
        "--workspace",
        str(workspace),
        "--print-json",
    ]
    if extra_args:
        cmd.extend(extra_args)
    return subprocess.run(cmd, capture_output=True, text=True)


class BaseConsensusPatchScanTests(unittest.TestCase):
    def test_flags_first_tx_only_deposits_classifier(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write_source(
                ws,
                textwrap.dedent(
                    """
                    impl AttributesWithParent {
                        pub fn is_deposits_only(&self) -> bool {
                            self.attributes
                                .transactions
                                .iter()
                                .all(|tx| tx.first().is_some_and(|tx| tx[0] == OpTxType::Deposit as u8))
                        }
                    }
                    """
                ).lstrip(),
            )
            proc = _run(ws)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            payload = json.loads(proc.stdout)
            rows = payload["rows"]
            self.assertEqual(len(rows), 1, payload)
            self.assertEqual(
                rows[0]["pattern_id"],
                "base_deposits_only_option_iter_first_tx_only",
            )
            self.assertEqual(rows[0]["function"], "AttributesWithParent::is_deposits_only")
            self.assertEqual(rows[0]["patch_commit"], "0bbd206a")
            self.assertEqual(rows[0]["submission_posture"], "NOT_SUBMIT_READY")
            self.assertEqual(rows[0]["severity"], "none")
            self.assertIn("UnexpectedPayloadStatus", rows[0]["trigger_precondition_required"])

    def test_flattened_classifier_is_clean(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write_source(
                ws,
                textwrap.dedent(
                    """
                    impl AttributesWithParent {
                        pub fn is_deposits_only(&self) -> bool {
                            self.attributes
                                .transactions
                                .iter()
                                .flatten()
                                .all(|tx| tx.first().copied() == Some(OpTxType::Deposit as u8))
                        }
                    }
                    """
                ).lstrip(),
            )
            proc = _run(ws)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            payload = json.loads(proc.stdout)
            self.assertEqual(payload["rows"], [], payload)

    def test_does_not_flag_other_is_deposits_only_impls(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write_source(
                ws,
                textwrap.dedent(
                    """
                    struct OtherAttributes;

                    impl OtherAttributes {
                        pub fn is_deposits_only(&self) -> bool {
                            self.attributes
                                .transactions
                                .iter()
                                .all(|tx| tx.first().is_some_and(|tx| tx[0] == OpTxType::Deposit as u8))
                        }
                    }
                    """
                ).lstrip(),
            )
            proc = _run(ws)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            payload = json.loads(proc.stdout)
            self.assertEqual(payload["rows"], [], payload)

    def test_requires_exact_attributes_transaction_chain(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write_source(
                ws,
                textwrap.dedent(
                    """
                    impl AttributesWithParent {
                        pub fn is_deposits_only(&self) -> bool {
                            self.transactions
                                .iter()
                                .all(|tx| tx.first().is_some_and(|tx| tx[0] == OpTxType::Deposit as u8))
                        }
                    }
                    """
                ).lstrip(),
            )
            proc = _run(ws)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            payload = json.loads(proc.stdout)
            self.assertEqual(payload["rows"], [], payload)

    def test_ignores_regression_shape_inside_cfg_test_module(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write_source(
                ws,
                textwrap.dedent(
                    """
                    #[cfg(test)]
                    mod tests {
                        impl AttributesWithParent {
                            pub fn is_deposits_only(&self) -> bool {
                                self.attributes
                                    .transactions
                                    .iter()
                                    .all(|tx| tx.first().is_some_and(|tx| tx[0] == OpTxType::Deposit as u8))
                            }
                        }
                    }
                    """
                ).lstrip(),
            )
            proc = _run(ws)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            payload = json.loads(proc.stdout)
            self.assertEqual(payload["rows"], [], payload)

    def test_strict_fails_on_regression_row(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write_source(
                ws,
                textwrap.dedent(
                    """
                    impl AttributesWithParent {
                        pub fn is_deposits_only(&self) -> bool {
                            self.attributes.transactions.iter().all(|tx| {
                                tx.first().is_some_and(|tx| tx[0] == OpTxType::Deposit as u8)
                            })
                        }
                    }
                    """
                ).lstrip(),
            )
            proc = _run(ws, ["--strict"])
            self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)

    def test_writes_workspace_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write_source(
                ws,
                textwrap.dedent(
                    """
                    impl AttributesWithParent {
                        pub fn is_deposits_only(&self) -> bool {
                            self.attributes.transactions.iter().all(|tx| {
                                tx.first().is_some_and(|tx| tx[0] == OpTxType::Deposit as u8)
                            })
                        }
                    }
                    """
                ).lstrip(),
            )
            cmd = [sys.executable, str(SCANNER), "--workspace", str(ws)]
            proc = subprocess.run(cmd, capture_output=True, text=True)
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            self.assertTrue(
                (ws / "critical_hunt" / "consensus_patch_scan" / "base_consensus_patch_scan.json").is_file()
            )
            self.assertTrue(
                (ws / "critical_hunt" / "consensus_patch_scan" / "base_consensus_patch_scan.md").is_file()
            )


if __name__ == "__main__":
    unittest.main()
