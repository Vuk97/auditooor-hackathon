#!/usr/bin/env python3
"""Tests for tools/go-txid-chain-truth-scan.py."""
from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCANNER = ROOT / "tools" / "go-txid-chain-truth-scan.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("go_txid_chain_truth_scan", SCANNER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _write_go(path: Path, name: str, body: str) -> Path:
    target = path / name
    target.write_text(textwrap.dedent(body).strip() + "\n", encoding="utf-8")
    return target


class GoTxidChainTruthScanTests(unittest.TestCase):
    def test_flags_length_only_persist_then_block_match(self) -> None:
        module = _load_module()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            go_file = _write_go(
                ws,
                "vulnerable.go",
                """
                package scannerfixture

                import "bytes"

                var pendingTxids [][]byte

                func trackTxid(txid []byte, blockTxids [][]byte) bool {
                    if len(txid) != 32 {
                        return false
                    }

                    pendingTxids = append(pendingTxids, txid)

                    for _, blockTxid := range blockTxids {
                        if bytes.Equal(txid, blockTxid) {
                            return true
                        }
                    }
                    return false
                }
                """,
            )

            findings = module.scan_paths([ws])
            self.assertEqual(len(findings), 1, findings)
            finding = findings[0]
            self.assertEqual(Path(finding["file"]), go_file)
            self.assertEqual(finding["function"], "trackTxid")
            self.assertEqual(finding["pattern_id"], "go_txid_chain_truth_scan_seed")
            self.assertTrue(finding["advisory_only"])
            self.assertEqual(finding["submission_posture"], "NOT_SUBMIT_READY")

    def test_skips_when_raw_tx_input_validation_is_nearby(self) -> None:
        module = _load_module()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write_go(
                ws,
                "clean.go",
                """
                package scannerfixture

                import "bytes"

                var pendingTxids [][]byte

                func trackTxid(txid []byte, blockTxids [][]byte, rawTx []byte) bool {
                    if len(txid) != 32 {
                        return false
                    }

                    pendingTxids = append(pendingTxids, txid)
                    decoded := decodeRawTransaction(rawTx)
                    if !validateInputs(decoded) {
                        return false
                    }

                    for _, blockTxid := range blockTxids {
                        if bytes.Equal(txid, blockTxid) {
                            return true
                        }
                    }
                    return false
                }
                """,
            )

            findings = module.scan_paths([ws])
            self.assertEqual(findings, [], findings)

    def test_does_not_stitch_signals_across_functions(self) -> None:
        module = _load_module()
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write_go(
                ws,
                "split_signals.go",
                """
                package scannerfixture

                import "bytes"

                var pendingTxids [][]byte

                func checkLength(txid []byte) bool {
                    if len(txid) != 32 {
                        return false
                    }
                    return true
                }

                func trackTxid(txid []byte, blockTxids [][]byte) bool {
                    pendingTxids = append(pendingTxids, txid)
                    for _, blockTxid := range blockTxids {
                        if bytes.Equal(txid, blockTxid) {
                            return true
                        }
                    }
                    return false
                }
                """,
            )

            findings = module.scan_paths([ws])
            self.assertEqual(findings, [], findings)

    def test_cli_emits_json_without_severity_claims(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write_go(
                ws,
                "vulnerable.go",
                """
                package scannerfixture

                import "bytes"

                var pendingTxids [][]byte

                func trackTxid(txid []byte, blockTxids [][]byte) bool {
                    if len(txid) != 32 {
                        return false
                    }
                    pendingTxids = append(pendingTxids, txid)
                    for _, blockTxid := range blockTxids {
                        if bytes.Equal(txid, blockTxid) {
                            return true
                        }
                    }
                    return false
                }
                """,
            )

            proc = subprocess.run(
                [sys.executable, str(SCANNER), str(ws)],
                capture_output=True,
                text=True,
            )
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            payload = json.loads(proc.stdout)
            self.assertIn("findings", payload)
            self.assertEqual(len(payload["findings"]), 1, payload)
            self.assertNotIn("severity", payload["findings"][0], payload["findings"][0])

    def test_make_target_writes_workspace_audit_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write_go(
                ws,
                "vulnerable.go",
                """
                package scannerfixture

                import "bytes"

                var pendingTxids [][]byte

                func trackTxid(txid []byte, blockTxids [][]byte) bool {
                    if len(txid) != 32 {
                        return false
                    }
                    pendingTxids = append(pendingTxids, txid)
                    for _, blockTxid := range blockTxids {
                        if bytes.Equal(txid, blockTxid) {
                            return true
                        }
                    }
                    return false
                }
                """,
            )

            out = ws / "audit" / "go-txid-chain-truth-scan.json"
            proc = subprocess.run(
                ["make", "go-txid-chain-truth-scan", f"WS={ws}"],
                cwd=ROOT,
                capture_output=True,
                text=True,
            )
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            self.assertTrue(out.exists(), proc.stdout + proc.stderr)
            payload = json.loads(out.read_text(encoding="utf-8"))
            self.assertTrue(payload.get("advisory"))
            self.assertEqual(payload.get("detector"), "go_txid_chain_truth_scan_seed")
            self.assertEqual(len(payload.get("findings", [])), 1, payload)
            self.assertNotIn("severity", payload["findings"][0], payload["findings"][0])


if __name__ == "__main__":
    unittest.main()
