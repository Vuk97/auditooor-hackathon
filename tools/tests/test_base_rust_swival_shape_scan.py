#!/usr/bin/env python3
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
TOOL = ROOT / "tools" / "base-rust-swival-shape-scan.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("base_rust_swival_shape_scan", TOOL)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules["base_rust_swival_shape_scan"] = mod
    spec.loader.exec_module(mod)
    return mod


MOD = _load_module()


def _assert_candidate_only(testcase: unittest.TestCase, row) -> None:
    testcase.assertEqual(row.candidate_kind, "detector_harness_task_candidate")
    testcase.assertEqual(row.submission_posture, "NOT_SUBMIT_READY")
    testcase.assertEqual(row.selected_impact, "")
    testcase.assertEqual(row.severity, "none")
    testcase.assertTrue(row.impact_contract_required)
    testcase.assertEqual(row.impact_contract_id, "")


def _write(ws: Path, rel: str, body: str) -> Path:
    path = ws / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(body).lstrip(), encoding="utf-8")
    return path


class BaseRustSwivalShapeScanTests(unittest.TestCase):
    def test_flags_unchecked_u64_to_usize_in_consensus_path(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write(
                ws,
                "external/base/crates/consensus/protocol/src/batch.rs",
                """
                pub fn decode_count(buf: [u8; 8]) -> usize {
                    let block_count = u64::from_le_bytes(buf) as usize;
                    block_count
                }
                """,
            )
            rows = MOD.scan_workspace(ws, ["external/base/crates"])
            hit = next(
                (r for r in rows if r.pattern_id == "swival_integer_len_truncation"),
                None,
            )
            self.assertIsNotNone(hit, rows)
            _assert_candidate_only(self, hit)

    def test_checked_conversion_is_not_flagged(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write(
                ws,
                "external/base/crates/consensus/protocol/src/batch.rs",
                """
                pub fn decode_count(buf: [u8; 8]) -> Result<usize, ()> {
                    let raw = u64::from_le_bytes(buf);
                    let block_count = usize::try_from(raw).map_err(|_| ())?;
                    Ok(block_count)
                }
                """,
            )
            rows = MOD.scan_workspace(ws, ["external/base/crates"])
            self.assertFalse(
                any(r.pattern_id == "swival_integer_len_truncation" for r in rows),
                rows,
            )

    def test_flags_length_prefix_allocation_without_cap(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write(
                ws,
                "external/base/crates/consensus/protocol/src/wire.rs",
                """
                pub fn decode<R: Reader>(mut reader: R) -> Vec<u8> {
                    let n = reader.read_u32();
                    let mut out = Vec::with_capacity(n as usize);
                    out
                }
                """,
            )
            rows = MOD.scan_workspace(ws, ["external/base/crates"])
            self.assertTrue(
                any(r.pattern_id == "swival_len_prefixed_alloc_no_cap" for r in rows),
                rows,
            )

    def test_cap_before_allocation_is_not_flagged(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write(
                ws,
                "external/base/crates/consensus/protocol/src/wire.rs",
                """
                const MAX_MESSAGE_SIZE: u32 = 1024;
                pub fn decode<R: Reader>(mut reader: R) -> Result<Vec<u8>, ()> {
                    let n = reader.read_u32();
                    if n > MAX_MESSAGE_SIZE { return Err(()); }
                    let mut out = Vec::with_capacity(n as usize);
                    Ok(out)
                }
                """,
            )
            rows = MOD.scan_workspace(ws, ["external/base/crates"])
            self.assertFalse(
                any(r.pattern_id == "swival_len_prefixed_alloc_no_cap" for r in rows),
                rows,
            )

    def test_flags_decode_without_visible_guard(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write(
                ws,
                "external/base/crates/consensus/protocol/src/message.rs",
                """
                pub fn decode_message(data: &[u8]) -> Result<Message, Error> {
                    Message::parse(data)
                }
                """,
            )
            rows = MOD.scan_workspace(ws, ["external/base/crates"])
            self.assertTrue(
                any(r.pattern_id == "swival_decode_without_visible_guard" for r in rows),
                rows,
            )

    def test_version_guard_suppresses_decode_guard_row(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write(
                ws,
                "external/base/crates/consensus/protocol/src/message.rs",
                """
                pub fn decode_message(data: &[u8], version: u8) -> Result<Message, Error> {
                    ensure!(version == 2);
                    Message::parse(data)
                }
                """,
            )
            rows = MOD.scan_workspace(ws, ["external/base/crates"])
            self.assertFalse(
                any(r.pattern_id == "swival_decode_without_visible_guard" for r in rows),
                rows,
            )

    def test_cli_writes_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write(
                ws,
                "external/base/crates/consensus/protocol/src/batch.rs",
                """
                pub fn decode_count(buf: [u8; 8]) -> usize {
                    let block_count = u64::from_le_bytes(buf) as usize;
                    block_count
                }
                """,
            )
            proc = subprocess.run(
                [sys.executable, str(TOOL), "--workspace", str(ws), "--print-json"],
                capture_output=True,
                text=True,
                timeout=30,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            payload = json.loads(proc.stdout)
            self.assertEqual(payload["row_count"], 1)
            row = payload["rows"][0]
            self.assertEqual(row["candidate_kind"], "detector_harness_task_candidate")
            self.assertEqual(row["submission_posture"], "NOT_SUBMIT_READY")
            self.assertEqual(row["selected_impact"], "")
            self.assertEqual(row["severity"], "none")
            self.assertTrue(row["impact_contract_required"])
            self.assertTrue(
                (ws / "critical_hunt/swival_shape_scan/base_rust_swival_shape_scan.json").is_file()
            )

    def test_flags_unsafe_len_pointer_primitive(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write(
                ws,
                "external/base/crates/consensus/protocol/src/unsafe_decode.rs",
                """
                pub unsafe fn decode_slice(ptr: *const u8, len: usize) -> &'static [u8] {
                    core::slice::from_raw_parts(ptr, len)
                }
                """,
            )
            rows = MOD.scan_workspace(ws, ["external/base/crates"])
            self.assertTrue(
                any(r.pattern_id == "swival_unsafe_len_pointer_primitive" for r in rows),
                rows,
            )

    def test_safe_file_set_len_is_not_unsafe_vec_set_len_shape(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write(
                ws,
                "external/base/crates/consensus/peers/src/store.rs",
                """
                pub fn sync(file: &std::fs::File) -> std::io::Result<()> {
                    file.set_len(0)?;
                    Ok(())
                }
                """,
            )
            rows = MOD.scan_workspace(ws, ["external/base/crates"])
            self.assertFalse(
                any(r.pattern_id == "swival_unsafe_len_pointer_primitive" for r in rows),
                rows,
            )

    def test_flags_relaxed_atomic_state_transition(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write(
                ws,
                "external/base/crates/consensus/service/src/state.rs",
                """
                use core::sync::atomic::{AtomicU64, Ordering};
                pub struct State { pub l1_head_number: AtomicU64 }
                impl State {
                    pub fn update_head(&self, head: u64) {
                        self.l1_head_number.store(head, Ordering::Relaxed);
                    }
                }
                """,
            )
            rows = MOD.scan_workspace(ws, ["external/base/crates"])
            self.assertTrue(
                any(r.pattern_id == "swival_relaxed_atomic_state_transition" for r in rows),
                rows,
            )

    def test_metrics_only_relaxed_atomic_is_not_flagged(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write(
                ws,
                "external/base/crates/consensus/service/src/metrics.rs",
                """
                use core::sync::atomic::{AtomicU64, Ordering};
                pub struct Metrics { pub hits: AtomicU64 }
                impl Metrics {
                    pub fn inc(&self) {
                        self.hits.fetch_add(1, Ordering::Relaxed);
                    }
                }
                """,
            )
            rows = MOD.scan_workspace(ws, ["external/base/crates"])
            self.assertFalse(
                any(r.pattern_id == "swival_relaxed_atomic_state_transition" for r in rows),
                rows,
            )

    def test_cfg_test_module_is_masked(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            _write(
                ws,
                "external/base/crates/consensus/service/src/state.rs",
                """
                #[cfg(test)]
                mod tests {
                    use core::sync::atomic::{AtomicU64, Ordering};
                    pub struct State { pub l1_head_number: AtomicU64 }
                    #[test]
                    fn test_head() {
                        let state = State { l1_head_number: AtomicU64::new(0) };
                        state.l1_head_number.store(1, Ordering::Relaxed);
                    }
                }
                """,
            )
            rows = MOD.scan_workspace(ws, ["external/base/crates"])
            self.assertEqual(rows, [])


if __name__ == "__main__":
    unittest.main()
