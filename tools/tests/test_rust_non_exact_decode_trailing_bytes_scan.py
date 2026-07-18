#!/usr/bin/env python3
"""Tests for ``tools/rust-non-exact-decode-trailing-bytes-scan.py`` (Wave H-3B).

Bug shape: ``decode_2718(`` (non-exact) accepting trailing bytes vs
``decode_2718_exact``.  Patch 6a1333dd fixed the attributes consolidation
path to use the exact variant.

Coverage
--------
1. ``test_flags_decode_2718_no_guard`` — bare ``decode_2718(`` in a fn body
   without ``is_empty()`` guard must fire with ``confidence="high"``.
2. ``test_medium_confidence_when_is_empty_guard_present`` — ``decode_2718(``
   with ``buf.is_empty()`` guard must fire with ``confidence="medium"``.
3. ``test_low_confidence_when_exact_also_present`` — fn body containing both
   ``decode_2718(`` and ``decode_2718_exact(`` must fire with ``confidence="low"``.
4. ``test_clean_decode_2718_exact_only`` — fn using only ``decode_2718_exact(``
   must NOT fire.
5. ``test_does_not_flag_test_code`` — call inside ``#[cfg(test)] mod tests``
   must not fire.
6. ``test_strict_exits_one`` — ``--strict`` exits 1 when any row emitted.
7. ``test_row_schema_fields`` — row must carry required schema fields.
8. ``test_smoke_real_base_repo`` — live smoke: must fire on
   ``crates/consensus/engine/src/attributes.rs`` (6a1333dd audit-snapshot).
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCANNER = ROOT / "tools" / "rust-non-exact-decode-trailing-bytes-scan.py"
LIVE_BASE_AZUL = Path(os.path.expanduser("~/audits/base-azul"))


def _run(workspace: Path, extra_args: list[str] | None = None) -> dict:
    cmd = [sys.executable, str(SCANNER), "--workspace", str(workspace), "--print-json"]
    if extra_args:
        cmd.extend(extra_args)
    proc = subprocess.run(cmd, capture_output=True, text=True)
    assert proc.returncode in (0, 1), proc.stdout + proc.stderr
    return json.loads(proc.stdout)


def _write_synthetic(
    workspace: Path,
    *,
    body: str,
    crate_relpath: str = "external/base/crates/consensus/engine/src",
    file_relpath: str = "attributes.rs",
) -> Path:
    crate_root = workspace / crate_relpath
    crate_root.mkdir(parents=True, exist_ok=True)
    target = crate_root / file_relpath
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(body)
    return target


class RustNonExactDecodeTrailingBytesScanTests(unittest.TestCase):
    def test_flags_decode_2718_no_guard(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            body = textwrap.dedent(
                """
                pub fn check_transactions(attr_tx_bytes: &[u8]) -> bool {
                    let Ok(attr_tx) = BaseTxEnvelope::decode_2718(&mut &attr_tx_bytes[..]) else {
                        return false;
                    };
                    true
                }
                """
            ).lstrip()
            _write_synthetic(ws, body=body)
            payload = _run(ws)
            hits = [r for r in payload["rows"] if r["pattern_id"] == "decode_2718_without_exact"]
            self.assertGreaterEqual(len(hits), 1, payload)
            self.assertEqual(hits[0]["confidence"], "high")

    def test_medium_confidence_when_is_empty_guard_present(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            body = textwrap.dedent(
                """
                pub fn decoded_transactions(raw: &[u8]) -> Result<(), ()> {
                    let mut buf = raw;
                    let tx = BaseTxEnvelope::decode_2718(&mut buf).map_err(|_| ())?;
                    if !buf.is_empty() {
                        return Err(());
                    }
                    Ok(())
                }
                """
            ).lstrip()
            _write_synthetic(ws, body=body)
            payload = _run(ws)
            hits = [r for r in payload["rows"] if r["pattern_id"] == "decode_2718_without_exact"]
            self.assertGreaterEqual(len(hits), 1, payload)
            self.assertEqual(hits[0]["confidence"], "medium")
            self.assertTrue(hits[0]["has_is_empty_guard"])

    def test_low_confidence_when_exact_also_present(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            body = textwrap.dedent(
                """
                pub fn both_paths(raw: &[u8]) -> Result<(), ()> {
                    let tx = BaseTxEnvelope::decode_2718(&mut &raw[..]).map_err(|_| ())?;
                    let tx2 = BaseTxEnvelope::decode_2718_exact(raw).map_err(|_| ())?;
                    Ok(())
                }
                """
            ).lstrip()
            _write_synthetic(ws, body=body)
            payload = _run(ws)
            hits = [r for r in payload["rows"] if r["pattern_id"] == "decode_2718_without_exact"]
            self.assertGreaterEqual(len(hits), 1, payload)
            self.assertEqual(hits[0]["confidence"], "low")
            self.assertTrue(hits[0]["has_exact_in_same_fn"])

    def test_clean_decode_2718_exact_only(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            body = textwrap.dedent(
                """
                pub fn decoded_fixed(raw: &[u8]) -> Result<(), ()> {
                    let tx = BaseTxEnvelope::decode_2718_exact(raw).map_err(|_| ())?;
                    Ok(())
                }
                """
            ).lstrip()
            _write_synthetic(ws, body=body)
            payload = _run(ws)
            self.assertEqual(payload["rows"], [], payload)

    def test_does_not_flag_test_code(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            body = textwrap.dedent(
                """
                pub fn nothing() {}

                #[cfg(test)]
                mod tests {
                    fn decode_in_test(raw: &[u8]) {
                        let _ = BaseTxEnvelope::decode_2718(&mut &raw[..]).unwrap();
                    }
                }
                """
            ).lstrip()
            _write_synthetic(ws, body=body)
            payload = _run(ws)
            self.assertEqual(payload["rows"], [], payload)

    def test_strict_exits_one(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            body = textwrap.dedent(
                """
                pub fn parse(raw: &[u8]) -> Result<(), ()> {
                    let _ = Tx::decode_2718(&mut &raw[..]).map_err(|_| ())?;
                    Ok(())
                }
                """
            ).lstrip()
            _write_synthetic(ws, body=body)
            cmd = [
                sys.executable, str(SCANNER),
                "--workspace", str(ws),
                "--print-json", "--strict",
            ]
            proc = subprocess.run(cmd, capture_output=True, text=True)
            self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)

    def test_row_schema_fields(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            body = textwrap.dedent(
                """
                pub fn f(raw: &[u8]) {
                    let _ = Tx::decode_2718(&mut &raw[..]);
                }
                """
            ).lstrip()
            _write_synthetic(ws, body=body)
            payload = _run(ws)
            self.assertGreaterEqual(len(payload["rows"]), 1)
            row = payload["rows"][0]
            required = {"file", "line", "pattern_id", "containing_fn", "input_source",
                        "has_is_empty_guard", "has_exact_in_same_fn", "snippet",
                        "confidence", "candidate_status"}
            for field in required:
                self.assertIn(field, row, f"Missing field: {field}")
            self.assertEqual(row["candidate_status"], "kill_or_reframe")

    @unittest.skipUnless(
        (LIVE_BASE_AZUL / "external" / "base-rc28-clean" / "crates" / "consensus"
         / "engine" / "src" / "attributes.rs").is_file(),
        f"requires live base-azul checkout at {LIVE_BASE_AZUL}",
    )
    def test_smoke_real_base_repo(self) -> None:
        """Must fire on consensus/engine/src/attributes.rs (6a1333dd bug location)."""
        payload = _run(LIVE_BASE_AZUL)
        attr_hits = [
            r for r in payload["rows"]
            if "consensus" in r["file"] and "engine" in r["file"] and "attributes" in r["file"]
        ]
        self.assertGreaterEqual(len(attr_hits), 1, payload["rows"])


if __name__ == "__main__":
    unittest.main()
