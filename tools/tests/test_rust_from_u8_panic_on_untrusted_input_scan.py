#!/usr/bin/env python3
"""Tests for ``tools/rust-from-u8-panic-on-untrusted-input-scan.py`` (Wave H-3B).

Bug shape: From<u8> impl with wildcard panic!/unreachable! arm, fed by
network input.  Patch 4839aea3 changed BatchType::from(u8) to TryFrom<u8>
returning an error instead of panicking.

Coverage
--------
1. ``test_flags_from_u8_panic_wildcard`` — ``impl From<u8> for MyEnum`` with
   ``_ => panic!(...)`` must fire ``from_u8_panic_wildcard``.
2. ``test_flags_from_u8_unreachable_wildcard`` — ``_ => unreachable!(...)``
   must fire ``from_u8_unreachable_wildcard``.
3. ``test_clean_tryfrom_does_not_flag`` — ``impl TryFrom<u8> for MyEnum``
   (the fixed form) must NOT fire.
4. ``test_clean_exhaustive_match_does_not_flag`` — ``impl From<u8>`` with
   all arms explicit (no wildcard) must NOT fire.
5. ``test_does_not_flag_test_code`` — panic inside ``#[cfg(test)] mod tests``
   must not be flagged.
6. ``test_strict_exits_one_on_any_row`` — ``--strict`` exits 1 when any row
   is emitted.
7. ``test_row_schema_fields`` — emitted row must carry the required schema
   fields: file, line, pattern_id, containing_fn, enum_name, confidence,
   candidate_status.
8. ``test_smoke_real_base_repo`` — live smoke: must fire on
   ``crates/consensus/protocol/src/batch/type.rs`` (audit-snapshot bug location).
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
SCANNER = ROOT / "tools" / "rust-from-u8-panic-on-untrusted-input-scan.py"
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
    crate_relpath: str = "external/base/crates/consensus/protocol/src/batch",
    file_relpath: str = "type.rs",
) -> Path:
    crate_root = workspace / crate_relpath
    crate_root.mkdir(parents=True, exist_ok=True)
    target = crate_root / file_relpath
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(body)
    return target


class RustFromU8PanicOnUntrustedInputScanTests(unittest.TestCase):
    def test_flags_from_u8_panic_wildcard(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            body = textwrap.dedent(
                """
                pub enum BatchType {
                    Single,
                    Span,
                }
                impl From<u8> for BatchType {
                    fn from(val: u8) -> Self {
                        match val {
                            0x00 => Self::Single,
                            0x01 => Self::Span,
                            _ => panic!("Invalid batch type: {val}"),
                        }
                    }
                }
                """
            ).lstrip()
            _write_synthetic(ws, body=body)
            payload = _run(ws)
            hits = [r for r in payload["rows"] if r["pattern_id"] == "from_u8_panic_wildcard"]
            self.assertEqual(len(hits), 1, payload)
            self.assertEqual(hits[0]["enum_name"], "BatchType")

    def test_flags_from_u8_unreachable_wildcard(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            body = textwrap.dedent(
                """
                pub enum MsgType { A, B }
                impl From<u8> for MsgType {
                    fn from(val: u8) -> Self {
                        match val {
                            0 => Self::A,
                            1 => Self::B,
                            _ => unreachable!("bad type"),
                        }
                    }
                }
                """
            ).lstrip()
            _write_synthetic(ws, body=body)
            payload = _run(ws)
            hits = [r for r in payload["rows"] if r["pattern_id"] == "from_u8_unreachable_wildcard"]
            self.assertEqual(len(hits), 1, payload)
            self.assertEqual(hits[0]["enum_name"], "MsgType")

    def test_clean_tryfrom_does_not_flag(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            body = textwrap.dedent(
                """
                pub enum BatchType { Single, Span }
                pub struct DecodeErr;
                impl TryFrom<u8> for BatchType {
                    type Error = DecodeErr;
                    fn try_from(val: u8) -> Result<Self, Self::Error> {
                        match val {
                            0x00 => Ok(Self::Single),
                            0x01 => Ok(Self::Span),
                            _ => Err(DecodeErr),
                        }
                    }
                }
                """
            ).lstrip()
            _write_synthetic(ws, body=body)
            payload = _run(ws)
            # TryFrom is the fixed form — must not fire.
            self.assertEqual(payload["rows"], [], payload)

    def test_clean_exhaustive_match_does_not_flag(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            body = textwrap.dedent(
                """
                pub enum Bit { Zero, One }
                impl From<u8> for Bit {
                    fn from(val: u8) -> Self {
                        match val {
                            0 => Self::Zero,
                            _ => Self::One,
                        }
                    }
                }
                """
            ).lstrip()
            _write_synthetic(ws, body=body)
            payload = _run(ws)
            # No panic/unreachable — clean.
            self.assertEqual(payload["rows"], [], payload)

    def test_does_not_flag_test_code(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            body = textwrap.dedent(
                """
                pub fn nothing() {}

                #[cfg(test)]
                mod tests {
                    pub enum T { A }
                    impl From<u8> for T {
                        fn from(val: u8) -> Self {
                            match val {
                                0 => Self::A,
                                _ => panic!("test only"),
                            }
                        }
                    }
                }
                """
            ).lstrip()
            _write_synthetic(ws, body=body)
            payload = _run(ws)
            self.assertEqual(payload["rows"], [], payload)

    def test_strict_exits_one_on_any_row(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            body = textwrap.dedent(
                """
                pub enum BatchType { Single }
                impl From<u8> for BatchType {
                    fn from(val: u8) -> Self {
                        match val {
                            0 => Self::Single,
                            _ => panic!("bad"),
                        }
                    }
                }
                """
            ).lstrip()
            _write_synthetic(ws, body=body)
            cmd = [
                sys.executable, str(SCANNER),
                "--workspace", str(ws),
                "--print-json",
                "--strict",
            ]
            proc = subprocess.run(cmd, capture_output=True, text=True)
            self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)

    def test_row_schema_fields(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            body = textwrap.dedent(
                """
                pub enum T { A }
                impl From<u8> for T {
                    fn from(val: u8) -> Self {
                        match val {
                            0 => Self::A,
                            _ => panic!("bad"),
                        }
                    }
                }
                """
            ).lstrip()
            _write_synthetic(ws, body=body)
            payload = _run(ws)
            self.assertGreaterEqual(len(payload["rows"]), 1)
            row = payload["rows"][0]
            required = {"file", "line", "pattern_id", "containing_fn", "enum_name",
                        "confidence", "candidate_status", "input_source", "snippet"}
            for field in required:
                self.assertIn(field, row, f"Missing field: {field}")
            self.assertEqual(row["candidate_status"], "kill_or_reframe")

    @unittest.skipUnless(
        (LIVE_BASE_AZUL / "external" / "base-rc28-clean" / "crates" / "consensus"
         / "protocol" / "src" / "batch" / "type.rs").is_file(),
        f"requires live base-azul checkout at {LIVE_BASE_AZUL}",
    )
    def test_smoke_real_base_repo(self) -> None:
        """Must fire on batch/type.rs — the 4839aea3 audit-snapshot bug location."""
        payload = _run(LIVE_BASE_AZUL)
        batch_hits = [
            r for r in payload["rows"]
            if "batch" in r["file"] and "type" in r["file"]
        ]
        self.assertGreaterEqual(len(batch_hits), 1, payload["rows"])
        self.assertEqual(batch_hits[0]["enum_name"], "BatchType")
        self.assertEqual(batch_hits[0]["pattern_id"], "from_u8_panic_wildcard")


if __name__ == "__main__":
    unittest.main()
