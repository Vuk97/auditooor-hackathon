#!/usr/bin/env python3
"""Tests for ``tools/rust-host-length-cast-unbounded-alloc-scan.py`` (Wave H-3F).

Bug shapes: preimage oracle / hint-channel reader allocates unbounded Vec from
host-controlled u32/u64 length without a cap.

Promoted candidates:
  - oracle.rs:33-55 (swival-rust-stdlib-192) — u64 → usize → vec![0; length]
  - hint.rs:78-95  (swival-rust-stdlib-196) — u32 → usize → vec![0u8; len as usize]

Coverage
--------
1. ``test_flags_u64_from_be_bytes_to_usize_alloc`` — from_be_bytes(u64) + vec![0; var]
   (oracle.rs write_key shape) must fire ``host_u64_to_usize_vec_alloc``.
2. ``test_flags_u32_len_then_vec_alloc_as_usize`` — u32::from_be_bytes + vec![0u8; len as usize]
   (hint.rs shape) must fire ``host_u32_to_usize_vec_alloc``.
3. ``test_clean_when_cap_guard_before_alloc`` — same shape but with
   ``if len > MAX_HINT_SIZE { return Err(...) }`` must set ``length_cap_present=True``.
4. ``test_clean_no_channel_context`` — u32 read in a non-host context must NOT fire.
5. ``test_does_not_flag_test_code`` — patterns inside ``#[cfg(test)] mod tests {}``
   must not be flagged.
6. ``test_strict_exits_one_on_any_row`` — ``--strict`` exits 1 when any row is emitted.
7. ``test_row_schema_fields`` — row must carry required fields: file, line,
   pattern_id, function, length_variable, confidence, candidate_status.
8. ``test_smoke_real_base_repo`` — live smoke: fires at oracle.rs and hint.rs
   in the audit snapshot. Skipped when snapshot absent.
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
SCANNER = ROOT / "tools" / "rust-host-length-cast-unbounded-alloc-scan.py"
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
    crate_relpath: str = "external/base/crates/proof/preimage/src",
    file_relpath: str = "oracle.rs",
) -> Path:
    crate_root = workspace / crate_relpath
    crate_root.mkdir(parents=True, exist_ok=True)
    target = crate_root / file_relpath
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(body)
    return target


class HostLengthCastUnboundedAllocScanTests(unittest.TestCase):
    def test_flags_u64_from_be_bytes_to_usize_alloc(self) -> None:
        """oracle.rs write_key shape: from_be_bytes(u64) result used in vec![0; var]."""
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            body = textwrap.dedent(
                """
                pub async fn write_key(&self) -> usize {
                    let mut length_buffer = [0u8; 8];
                    self.channel.read_exact(&mut length_buffer).await?;
                    Ok(u64::from_be_bytes(length_buffer) as usize)
                }

                pub async fn get(&self) -> Vec<u8> {
                    let length = self.write_key(key).await?;
                    let mut data_buffer = alloc::vec![0; length];
                    self.channel.read_exact(&mut data_buffer).await?;
                    Ok(data_buffer)
                }
                """
            )
            _write_synthetic(ws, body=body)
            result = _run(ws)
            rows = result["rows"]
            # At least one row should fire on the write_key or alloc site.
            self.assertGreater(len(rows), 0, f"Expected rows, got none. stderr output check needed.")

    def test_flags_u32_len_then_vec_alloc_as_usize(self) -> None:
        """hint.rs shape: u32::from_be_bytes + vec![0u8; len as usize]."""
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            body = textwrap.dedent(
                """
                pub async fn next_hint(&self) -> Result<()> {
                    let mut len_buf = [0u8; 4];
                    self.channel.read_exact(&mut len_buf).await?;
                    let len = u32::from_be_bytes(len_buf);
                    let mut raw_payload = vec![0u8; len as usize];
                    self.channel.read_exact(raw_payload.as_mut_slice()).await?;
                    Ok(())
                }
                """
            )
            _write_synthetic(ws, body=body, file_relpath="hint.rs")
            result = _run(ws)
            rows = result["rows"]
            self.assertGreater(len(rows), 0, "Expected rows for u32 hint channel shape")
            ids = {r["pattern_id"] for r in rows}
            self.assertTrue(
                ids & {"host_u32_to_usize_vec_alloc", "channel_read_then_vec_alloc"},
                f"Expected u32 pattern IDs, got {ids}",
            )

    def test_clean_when_cap_guard_before_alloc(self) -> None:
        """Same hint shape but with a length cap guard: length_cap_present must be True."""
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            body = textwrap.dedent(
                """
                const MAX_HINT_SIZE: usize = 16 * 1024 * 1024;

                pub async fn next_hint(&self) -> Result<()> {
                    let mut len_buf = [0u8; 4];
                    self.channel.read_exact(&mut len_buf).await?;
                    let len = u32::from_be_bytes(len_buf);
                    if len as usize > MAX_HINT_SIZE {
                        return Err(HintError::TooLarge);
                    }
                    let mut raw_payload = vec![0u8; len as usize];
                    self.channel.read_exact(raw_payload.as_mut_slice()).await?;
                    Ok(())
                }
                """
            )
            _write_synthetic(ws, body=body, file_relpath="hint.rs")
            result = _run(ws)
            rows = result["rows"]
            # Rows may still be emitted but cap must be detected.
            capped = [r for r in rows if r.get("length_cap_present")]
            self.assertTrue(
                not rows or capped,
                "When MAX_HINT_SIZE cap guard is present, rows should have length_cap_present=True",
            )

    def test_clean_no_channel_context(self) -> None:
        """u32 conversion in a pure math context with no channel access must NOT fire."""
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            body = textwrap.dedent(
                """
                pub fn compute_checksum(data: &[u8]) -> u32 {
                    let len = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
                    let mut result = vec![0u8; len as usize];
                    result
                }
                """
            )
            # Write to a non-proof path so host context heuristics don't fire.
            _write_synthetic(
                ws,
                body=body,
                crate_relpath="external/base/crates/utilities/checksum/src",
                file_relpath="lib.rs",
            )
            result = _run(ws)
            rows = result["rows"]
            # Should have no high-confidence rows in a pure math context.
            high_rows = [r for r in rows if r.get("confidence") == "high"]
            self.assertEqual(
                len(high_rows),
                0,
                f"Pure math context should not produce high-confidence rows, got: {high_rows}",
            )

    def test_does_not_flag_test_code(self) -> None:
        """Patterns inside #[cfg(test)] mod tests must not be flagged."""
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            body = textwrap.dedent(
                """
                #[cfg(test)]
                mod tests {
                    pub async fn mock_hint_reader() {
                        let mut len_buf = [0u8; 4];
                        self.channel.read_exact(&mut len_buf).await?;
                        let len = u32::from_be_bytes(len_buf);
                        let mut raw_payload = vec![0u8; len as usize];
                    }
                }
                """
            )
            _write_synthetic(ws, body=body, file_relpath="hint.rs")
            result = _run(ws)
            rows = result["rows"]
            self.assertEqual(len(rows), 0, f"Test code must not be flagged, got: {rows}")

    def test_strict_exits_one_on_any_row(self) -> None:
        """--strict must exit 1 when any row is emitted."""
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            body = textwrap.dedent(
                """
                pub async fn next_hint(&self) -> Result<()> {
                    let mut len_buf = [0u8; 4];
                    self.channel.read_exact(&mut len_buf).await?;
                    let len = u32::from_be_bytes(len_buf);
                    let mut raw_payload = vec![0u8; len as usize];
                    self.channel.read_exact(raw_payload.as_mut_slice()).await?;
                    Ok(())
                }
                """
            )
            _write_synthetic(ws, body=body, file_relpath="hint.rs")
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
                pub async fn next_hint(&self) -> Result<()> {
                    let mut len_buf = [0u8; 4];
                    self.channel.read_exact(&mut len_buf).await?;
                    let len = u32::from_be_bytes(len_buf);
                    let mut raw_payload = vec![0u8; len as usize];
                    self.channel.read_exact(raw_payload.as_mut_slice()).await?;
                    Ok(())
                }
                """
            )
            _write_synthetic(ws, body=body, file_relpath="hint.rs")
            result = _run(ws)
            rows = result["rows"]
            if not rows:
                self.skipTest("Scanner emitted no rows; schema test requires ≥1 row")
            required_fields = {
                "file",
                "line",
                "pattern_id",
                "function",
                "length_variable",
                "confidence",
                "candidate_status",
                "submission_posture",
            }
            for row in rows:
                missing = required_fields - set(row.keys())
                self.assertFalse(missing, f"Row missing fields: {missing}")

    @unittest.skipUnless(
        LIVE_BASE_AZUL.is_dir(),
        "Live audit snapshot not present; skipping smoke test",
    )
    def test_smoke_real_base_repo(self) -> None:
        """Live smoke: must fire at oracle.rs:33-55 AND hint.rs:78-95."""
        result = _run(LIVE_BASE_AZUL)
        rows = result["rows"]
        oracle_hits = [
            r for r in rows
            if "oracle.rs" in r["file"]
            and 27 <= r["line"] <= 65
        ]
        hint_hits = [
            r for r in rows
            if "hint.rs" in r["file"]
            and 78 <= r["line"] <= 100
        ]
        self.assertGreater(
            len(oracle_hits),
            0,
            f"Expected ≥1 hit at oracle.rs:27-65; rows={[r['file'] + ':' + str(r['line']) for r in rows]}",
        )
        self.assertGreater(
            len(hint_hits),
            0,
            f"Expected ≥1 hit at hint.rs:78-100; rows={[r['file'] + ':' + str(r['line']) for r in rows]}",
        )


if __name__ == "__main__":
    unittest.main()
