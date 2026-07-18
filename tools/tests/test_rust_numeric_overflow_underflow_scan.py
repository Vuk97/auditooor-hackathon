#!/usr/bin/env python3
"""Tests for ``tools/rust-numeric-overflow-underflow-scan.py`` (Wave H-3F).

Bug shapes:
  - frame_queue.rs:68: ``while i < self.queue.len() - 1`` — usize underflow when
    queue is empty (0 - 1 wraps to usize::MAX in release mode → OOB index).
  - frame_queue.rs:75: ``prev_frame.number + 1 != next_frame.number`` — Frame.number
    is u16; + 1 panics in debug or wraps in release when number == u16::MAX.

Coverage
--------
1. ``test_flags_usize_len_sub_without_guard`` — ``while i < queue.len() - 1`` must
   fire ``usize_sub_without_empty_guard``.
2. ``test_flags_u16_field_add_overflow`` — ``frame.number + 1`` where ``number: u16``
   must fire ``u8_u16_add_overflow_risk``.
3. ``test_clean_when_is_empty_guard_present`` — same sub pattern but preceded by
   ``if queue.is_empty() { return; }`` must NOT fire (or fires with guard=True).
4. ``test_clean_saturating_sub_does_not_fire`` — ``queue.len().saturating_sub(1)``
   must NOT fire.
5. ``test_clean_saturating_add_does_not_fire_for_u16`` — ``frame.number.saturating_add(1)``
   must NOT fire.
6. ``test_flags_checked_add_unwrap`` — ``x.checked_add(1).unwrap()`` must fire
   ``checked_add_unwrap``.
7. ``test_does_not_flag_test_code`` — patterns inside ``#[cfg(test)] mod tests``
   must not be flagged.
8. ``test_strict_exits_one_on_any_row`` — ``--strict`` exits 1 when rows present.
9. ``test_row_schema_fields`` — row must carry required schema fields.
10. ``test_smoke_real_base_repo`` — live smoke: fires at frame_queue.rs:68 AND :75.
    Skipped when snapshot absent.
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
SCANNER = ROOT / "tools" / "rust-numeric-overflow-underflow-scan.py"
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
    crate_relpath: str = "external/base/crates/consensus/derive/src/stages",
    file_relpath: str = "frame_queue.rs",
) -> Path:
    crate_root = workspace / crate_relpath
    crate_root.mkdir(parents=True, exist_ok=True)
    target = crate_root / file_relpath
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(body)
    return target


def _write_protocol(workspace: Path, *, body: str) -> Path:
    """Write a protocol crate file that declares Frame.number: u16."""
    crate_root = workspace / "external/base/crates/consensus/protocol/src"
    crate_root.mkdir(parents=True, exist_ok=True)
    target = crate_root / "frame.rs"
    target.write_text(body)
    return target


class NumericOverflowUnderflowScanTests(unittest.TestCase):
    def test_flags_usize_len_sub_without_guard(self) -> None:
        """while i < queue.len() - 1 without empty guard must fire usize_sub_without_empty_guard."""
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            body = textwrap.dedent(
                """
                pub fn prune(&mut self) {
                    let mut i = 0;
                    while i < self.queue.len() - 1 {
                        let prev = &self.queue[i];
                        let next = &self.queue[i + 1];
                        i += 1;
                    }
                }
                """
            )
            _write_synthetic(ws, body=body)
            result = _run(ws)
            rows = result["rows"]
            sub_rows = [r for r in rows if r["pattern_id"] == "usize_sub_without_empty_guard"]
            self.assertGreater(len(sub_rows), 0, f"Expected usize_sub rows, got: {rows}")

    def test_flags_u16_field_add_overflow(self) -> None:
        """frame.number + 1 where number: u16 must fire u8_u16_add_overflow_risk."""
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            # Write frame.rs declaring number: u16
            _write_protocol(
                ws,
                body=textwrap.dedent(
                    """
                    pub struct Frame {
                        pub id: [u8; 16],
                        pub number: u16,
                        pub data: Vec<u8>,
                        pub is_last: bool,
                    }
                    """
                ),
            )
            body = textwrap.dedent(
                """
                use crate::Frame;

                pub fn prune(&mut self) {
                    let mut i = 0;
                    while i < self.queue.len() {
                        let prev_frame = &self.queue[i];
                        let next_frame = &self.queue[i + 1];
                        if prev_frame.number + 1 != next_frame.number {
                            self.queue.remove(i + 1);
                        }
                        i += 1;
                    }
                }
                """
            )
            _write_synthetic(ws, body=body)
            result = _run(ws)
            rows = result["rows"]
            u16_rows = [r for r in rows if r["pattern_id"] == "u8_u16_add_overflow_risk"]
            self.assertGreater(len(u16_rows), 0, f"Expected u8_u16_add_overflow_risk, got: {rows}")

    def test_clean_when_is_empty_guard_present(self) -> None:
        """Same len()-1 pattern but guarded by is_empty(): must be safe or low confidence."""
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            body = textwrap.dedent(
                """
                pub fn prune(&mut self) {
                    if self.queue.is_empty() {
                        return;
                    }
                    let mut i = 0;
                    while i < self.queue.len() - 1 {
                        i += 1;
                    }
                }
                """
            )
            _write_synthetic(ws, body=body)
            result = _run(ws)
            rows = result["rows"]
            # Rows with guard should have safe_guard_present=True or confidence != "high".
            unguarded_high = [
                r for r in rows
                if r["pattern_id"] == "usize_sub_without_empty_guard"
                and not r.get("safe_guard_present")
                and r.get("confidence") == "high"
            ]
            self.assertEqual(
                len(unguarded_high),
                0,
                f"is_empty() guard should suppress high-confidence rows: {unguarded_high}",
            )

    def test_clean_saturating_sub_does_not_fire(self) -> None:
        """queue.len().saturating_sub(1) must NOT fire."""
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            body = textwrap.dedent(
                """
                pub fn prune(&mut self) {
                    let bound = self.queue.len().saturating_sub(1);
                    let mut i = 0;
                    while i < bound {
                        i += 1;
                    }
                }
                """
            )
            _write_synthetic(ws, body=body)
            result = _run(ws)
            rows = result["rows"]
            sub_rows = [r for r in rows if r["pattern_id"] == "usize_sub_without_empty_guard"]
            self.assertEqual(len(sub_rows), 0, f"saturating_sub should not fire: {sub_rows}")

    def test_clean_saturating_add_does_not_fire_for_u16(self) -> None:
        """frame.number.saturating_add(1) must NOT fire u8_u16_add_overflow_risk."""
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write_protocol(
                ws,
                body=textwrap.dedent(
                    """
                    pub struct Frame {
                        pub number: u16,
                    }
                    """
                ),
            )
            body = textwrap.dedent(
                """
                pub fn safe_prune(&mut self) {
                    let prev_frame = &self.queue[0];
                    let next_expected = prev_frame.number.saturating_add(1);
                }
                """
            )
            _write_synthetic(ws, body=body)
            result = _run(ws)
            rows = result["rows"]
            u16_rows = [r for r in rows if r["pattern_id"] == "u8_u16_add_overflow_risk"]
            self.assertEqual(len(u16_rows), 0, f"saturating_add should not fire: {u16_rows}")

    def test_flags_checked_add_unwrap(self) -> None:
        """x.checked_add(1).unwrap() must fire checked_add_unwrap."""
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            body = textwrap.dedent(
                """
                pub fn advance(&mut self) {
                    let next_block = parent_number.checked_add(1).unwrap();
                }
                """
            )
            _write_synthetic(ws, body=body)
            result = _run(ws)
            rows = result["rows"]
            unwrap_rows = [r for r in rows if r["pattern_id"] == "checked_add_unwrap"]
            self.assertGreater(len(unwrap_rows), 0, f"Expected checked_add_unwrap row, got: {rows}")

    def test_does_not_flag_test_code(self) -> None:
        """Patterns inside #[cfg(test)] mod tests must not be flagged."""
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            body = textwrap.dedent(
                """
                #[cfg(test)]
                mod tests {
                    fn test_prune_empty() {
                        let mut i = 0;
                        while i < queue.len() - 1 {
                            i += 1;
                        }
                    }
                }
                """
            )
            _write_synthetic(ws, body=body)
            result = _run(ws)
            rows = result["rows"]
            self.assertEqual(len(rows), 0, f"Test code must not be flagged, got: {rows}")

    def test_strict_exits_one_on_any_row(self) -> None:
        """--strict exits 1 when any row is emitted."""
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            body = textwrap.dedent(
                """
                pub fn prune(&mut self) {
                    let mut i = 0;
                    while i < self.queue.len() - 1 {
                        i += 1;
                    }
                }
                """
            )
            _write_synthetic(ws, body=body)
            result = _run(ws)
            if not result["rows"]:
                self.skipTest("Scanner emitted no rows; strict-exit test requires ≥1 row")
            cmd = [
                sys.executable,
                str(SCANNER),
                "--workspace",
                str(ws),
                "--print-json",
                "--strict",
            ]
            proc = subprocess.run(cmd, capture_output=True, text=True)
            self.assertEqual(proc.returncode, 1, "--strict must exit 1 when rows present")

    def test_row_schema_fields(self) -> None:
        """Emitted rows must carry the required schema fields."""
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            body = textwrap.dedent(
                """
                pub fn prune(&mut self) {
                    let mut i = 0;
                    while i < self.queue.len() - 1 {
                        i += 1;
                    }
                }
                """
            )
            _write_synthetic(ws, body=body)
            result = _run(ws)
            rows = result["rows"]
            if not rows:
                self.skipTest("Scanner emitted no rows; schema test requires ≥1 row")
            required_fields = {
                "file",
                "line",
                "pattern_id",
                "function",
                "expression",
                "confidence",
                "candidate_status",
                "submission_posture",
                "safe_guard_present",
            }
            for row in rows:
                missing = required_fields - set(row.keys())
                self.assertFalse(missing, f"Row missing fields: {missing}")

    @unittest.skipUnless(
        LIVE_BASE_AZUL.is_dir(),
        "Live audit snapshot not present; skipping smoke test",
    )
    def test_smoke_real_base_repo(self) -> None:
        """Live smoke: must fire at frame_queue.rs:68 AND frame_queue.rs:75."""
        result = _run(LIVE_BASE_AZUL)
        rows = result["rows"]
        fq_rows = [r for r in rows if "frame_queue.rs" in r["file"]]
        line_68 = [r for r in fq_rows if r["line"] == 68]
        line_75 = [r for r in fq_rows if r["line"] == 75]
        self.assertGreater(
            len(line_68),
            0,
            f"Expected hit at frame_queue.rs:68; frame_queue rows: {[(r['line'], r['pattern_id']) for r in fq_rows]}",
        )
        self.assertGreater(
            len(line_75),
            0,
            f"Expected hit at frame_queue.rs:75; frame_queue rows: {[(r['line'], r['pattern_id']) for r in fq_rows]}",
        )


if __name__ == "__main__":
    unittest.main()
