#!/usr/bin/env python3
"""Tests for ``tools/rust-decode-bomb-scan.py`` (PR #556 Wave 6 Worker G).

The scanner generalises the Wave 5 Worker O snappy ``decompress_vec``
finding into a corpus-wide attacker-controlled-length allocation detector.

Coverage rationale
------------------

1. ``test_flags_vec_macro_attacker_len`` — bare ``vec![0; user_len]`` where
   ``user_len`` arrives via fn parameter must fire ``vec_macro_attacker_len``.

2. ``test_flags_with_capacity_payload_declared_len`` — the Wave-5 shape:
   ``Vec::with_capacity(payload.declared_len())`` must fire
   ``vec_with_capacity_attacker_len`` with ``length_cap_present=False``.

3. ``test_clean_when_explicit_max_clamp_before_alloc`` — same handler shape
   but with ``if user_len > MAX_LEN { return Err(...) }; vec![0; user_len]``
   must record ``length_cap_present=True`` and the clamp constant name.

4. ``test_clean_when_const_capacity`` — ``Vec::with_capacity(MAX_BUFFER_SIZE)``
   must NOT fire (capacity is a known const).

5. ``test_flags_snappy_decompress_vec`` — the Wave-5 finding shape itself.

6. ``test_flags_read_then_with_capacity`` — ``let n = reader.read_u32() as
   usize; let mut buf = Vec::with_capacity(n)`` must fire
   ``read_then_with_capacity``.

7. ``test_does_not_flag_test_code`` — ``#[cfg(test)] mod tests { ... }``
   blocks are stripped before scanning.

8. ``test_strict_exits_one_on_uncapped_public_source`` — ``--strict`` must
   exit 1 when an uncapped row sits on a public attacker-input source.

9. ``test_smoke_real_base_repo`` — when the live Base Azul checkout is
   present, the scanner must flag all 5 known snappy sites. Skip when
   absent so CI on bare clones still passes.
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
SCANNER = ROOT / "tools" / "rust-decode-bomb-scan.py"
LIVE_BASE_AZUL = Path(os.path.expanduser("~/audits/base-azul"))


def _run(workspace: Path, extra_args: list[str] | None = None) -> dict:
    cmd = [
        sys.executable,
        str(SCANNER),
        "--workspace",
        str(workspace),
        "--print-json",
    ]
    if extra_args:
        cmd.extend(extra_args)
    proc = subprocess.run(cmd, capture_output=True, text=True)
    assert proc.returncode in (0, 1), proc.stdout + proc.stderr
    return json.loads(proc.stdout)


def _write_synthetic(
    workspace: Path,
    *,
    body: str,
    crate_relpath: str = "external/base/crates/consensus/gossip",
    file_relpath: str = "src/lib.rs",
) -> Path:
    crate_root = workspace / crate_relpath
    crate_root.mkdir(parents=True, exist_ok=True)
    (crate_root / "Cargo.toml").write_text(
        textwrap.dedent(
            """
            [package]
            name = "synthetic"
            version = "0.1.0"
            edition = "2021"
            """
        ).lstrip()
    )
    target = crate_root / file_relpath
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(body)
    return target


class RustDecodeBombScanTests(unittest.TestCase):
    def test_flags_vec_macro_attacker_len(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            body = textwrap.dedent(
                """
                pub fn decode_message(user_len: usize, data: &[u8]) -> Vec<u8> {
                    let mut buf = vec![0; user_len];
                    buf.copy_from_slice(&data[..user_len]);
                    buf
                }
                """
            ).lstrip()
            _write_synthetic(ws, body=body)
            payload = _run(ws)
            hits = [
                r for r in payload["rows"]
                if r["pattern_id"] == "vec_macro_attacker_len"
            ]
            self.assertEqual(len(hits), 1, payload)
            self.assertEqual(hits[0]["function"], "decode_message")
            self.assertFalse(hits[0]["length_cap_present"])

    def test_flags_with_capacity_payload_declared_len(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            body = textwrap.dedent(
                """
                pub struct Payload { pub declared_len: u64 }
                impl Payload {
                    pub fn declared_len(&self) -> usize { self.declared_len as usize }
                }
                pub fn decode(payload: &Payload) -> Vec<u8> {
                    let mut buf = Vec::with_capacity(payload.declared_len());
                    buf
                }
                """
            ).lstrip()
            _write_synthetic(ws, body=body)
            payload = _run(ws)
            hits = [
                r for r in payload["rows"]
                if r["pattern_id"] == "vec_with_capacity_attacker_len"
                and r["function"] == "decode"
            ]
            self.assertEqual(len(hits), 1, payload)
            self.assertFalse(hits[0]["length_cap_present"])

    def test_clean_when_explicit_max_clamp_before_alloc(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            body = textwrap.dedent(
                """
                const MAX_LEN: usize = 1024;
                pub fn decode_message(user_len: usize, data: &[u8]) -> Result<Vec<u8>, ()> {
                    if user_len > MAX_LEN {
                        return Err(());
                    }
                    let mut buf = vec![0; user_len];
                    Ok(buf)
                }
                """
            ).lstrip()
            _write_synthetic(ws, body=body)
            payload = _run(ws)
            hits = [
                r for r in payload["rows"]
                if r["pattern_id"] == "vec_macro_attacker_len"
            ]
            # Clean baseline: scanner may still flag for review, but the cap
            # MUST be detected and named.
            for h in hits:
                self.assertTrue(
                    h["length_cap_present"],
                    f"Expected cap detected for {h}",
                )
                self.assertEqual(h["length_cap_value_or_const_name"], "MAX_LEN")

    def test_clean_when_const_capacity(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            body = textwrap.dedent(
                """
                const MAX_BUFFER_SIZE: usize = 4096;
                pub fn alloc_buf() -> Vec<u8> {
                    let mut buf = Vec::with_capacity(MAX_BUFFER_SIZE);
                    buf
                }
                """
            ).lstrip()
            _write_synthetic(ws, body=body)
            payload = _run(ws)
            hits = [
                r for r in payload["rows"]
                if r["pattern_id"] == "vec_with_capacity_attacker_len"
            ]
            self.assertEqual(hits, [], payload)

    def test_flags_snappy_decompress_vec(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            body = textwrap.dedent(
                """
                pub fn compute_message_id(msg_data: &[u8]) -> [u8; 20] {
                    let mut decoder = snap::raw::Decoder::new();
                    let id = decoder.decompress_vec(msg_data).unwrap();
                    [0u8; 20]
                }
                """
            ).lstrip()
            _write_synthetic(ws, body=body)
            payload = _run(ws)
            hits = [
                r for r in payload["rows"]
                if r["pattern_id"] == "snappy_decompress_vec"
            ]
            self.assertEqual(len(hits), 1, payload)
            self.assertEqual(hits[0]["function"], "compute_message_id")
            self.assertEqual(hits[0]["attacker_input_source"], "gossip")
            self.assertFalse(hits[0]["length_cap_present"])
            self.assertEqual(hits[0]["candidate_kind"], "detector_harness_task_candidate")
            self.assertEqual(hits[0]["submission_posture"], "NOT_SUBMIT_READY")
            self.assertEqual(hits[0]["selected_impact"], "")
            self.assertEqual(hits[0]["severity"], "none")
            self.assertTrue(hits[0]["impact_contract_required"])
            self.assertEqual(hits[0]["impact_contract_id"], "")
            self.assertIn("mempool impact", hits[0]["not_applicable_impacts"])
            self.assertIn(">=30%", hits[0]["kill_or_reframe_rule"])

    def test_snappy_decompress_len_precheck_marks_cap_present(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            body = textwrap.dedent(
                """
                const MAX_GOSSIP_SIZE: usize = 10 * 1024 * 1024;

                pub fn compute_message_id(msg_data: &[u8]) -> [u8; 20] {
                    let decompressed_len = snap::raw::decompress_len(msg_data).unwrap();
                    if decompressed_len > MAX_GOSSIP_SIZE {
                        return [0u8; 20];
                    }
                    let mut decoder = snap::raw::Decoder::new();
                    let id = decoder.decompress_vec(msg_data).unwrap();
                    [0u8; 20]
                }
                """
            ).lstrip()
            _write_synthetic(ws, body=body)
            payload = _run(ws)
            hits = [
                r for r in payload["rows"]
                if r["pattern_id"] == "snappy_decompress_vec"
            ]
            self.assertEqual(len(hits), 1, payload)
            self.assertTrue(hits[0]["length_cap_present"])
            self.assertEqual(
                hits[0]["length_cap_value_or_const_name"],
                "MAX_GOSSIP_SIZE",
            )

    def test_flags_read_then_with_capacity(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            body = textwrap.dedent(
                """
                pub async fn read_frame(reader: &mut Reader) -> Vec<u8> {
                    let len = reader.read_u32().await.unwrap() as usize;
                    let mut buf = Vec::with_capacity(len);
                    buf
                }
                """
            ).lstrip()
            _write_synthetic(
                ws,
                body=body,
                crate_relpath="external/base/crates/proof/tee",
                file_relpath="src/transport.rs",
            )
            payload = _run(ws)
            hits = [
                r for r in payload["rows"]
                if r["pattern_id"] == "read_then_with_capacity"
            ]
            self.assertEqual(len(hits), 1, payload)
            self.assertFalse(hits[0]["length_cap_present"])

    def test_does_not_flag_test_code(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            body = textwrap.dedent(
                """
                pub fn nothing() -> () { () }

                #[cfg(test)]
                mod tests {
                    use super::*;
                    pub fn fake_decode(user_len: usize) -> Vec<u8> {
                        let mut buf = vec![0; user_len];
                        buf
                    }
                }
                """
            ).lstrip()
            _write_synthetic(ws, body=body)
            payload = _run(ws)
            self.assertEqual(
                [r for r in payload["rows"] if r["function"] == "fake_decode"],
                [],
                payload,
            )

    def test_strict_exits_one_on_uncapped_public_source(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            body = textwrap.dedent(
                """
                pub fn decode(msg_data: &[u8]) -> Vec<u8> {
                    let mut decoder = snap::raw::Decoder::new();
                    let id = decoder.decompress_vec(msg_data).unwrap();
                    id
                }
                """
            ).lstrip()
            _write_synthetic(ws, body=body)
            cmd = [
                sys.executable,
                str(SCANNER),
                "--workspace",
                str(ws),
                "--print-json",
                "--strict",
            ]
            proc = subprocess.run(cmd, capture_output=True, text=True)
            self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)

    def test_writes_files_to_workspace(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            body = textwrap.dedent(
                """
                pub fn decode(payload_len: usize) -> Vec<u8> {
                    let mut buf = Vec::with_capacity(payload_len);
                    buf
                }
                """
            ).lstrip()
            _write_synthetic(ws, body=body)
            cmd = [sys.executable, str(SCANNER), "--workspace", str(ws)]
            proc = subprocess.run(cmd, capture_output=True, text=True)
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            json_path = ws / "critical_hunt" / "decode_bomb" / "rust_decode_bomb_scan.json"
            md_path = ws / "critical_hunt" / "decode_bomb" / "rust_decode_bomb_scan.md"
            self.assertTrue(json_path.is_file())
            self.assertTrue(md_path.is_file())
            data = json.loads(json_path.read_text())
            self.assertGreaterEqual(len(data["rows"]), 1)
            for row in data["rows"]:
                self.assertEqual(row["submission_posture"], "NOT_SUBMIT_READY")
                self.assertEqual(row["selected_impact"], "")
                self.assertEqual(row["severity"], "none")
                self.assertTrue(row["impact_contract_required"])

    def test_output_never_selects_severity_without_impact_contract(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            body = textwrap.dedent(
                """
                pub fn decode(payload_len: usize, msg_data: &[u8]) -> Vec<u8> {
                    let mut decoder = snap::raw::Decoder::new();
                    let _decoded = decoder.decompress_vec(msg_data).unwrap();
                    Vec::with_capacity(payload_len)
                }
                """
            ).lstrip()
            _write_synthetic(ws, body=body)
            payload = _run(ws)
            self.assertGreaterEqual(len(payload["rows"]), 2, payload)
            for row in payload["rows"]:
                self.assertEqual(row["selected_impact"], "")
                self.assertEqual(row["severity"], "none")
                self.assertEqual(row["submission_posture"], "NOT_SUBMIT_READY")
                self.assertEqual(row["impact_contract_id"], "")
                self.assertTrue(row["impact_contract_required"])

    @unittest.skipUnless(
        (LIVE_BASE_AZUL / "external" / "base" / "crates" / "consensus" / "gossip"
         / "src" / "config.rs").is_file(),
        f"requires live base-azul checkout at {LIVE_BASE_AZUL}",
    )
    def test_smoke_real_base_repo(self) -> None:
        """Scanner must catch all 5 known snappy decompress_vec sites."""
        payload = _run(LIVE_BASE_AZUL)
        snappy = [
            r for r in payload["rows"]
            if r["pattern_id"] == "snappy_decompress_vec"
        ]
        self.assertEqual(
            len(snappy),
            5,
            f"Expected 5 snappy sites, got {len(snappy)}: {snappy}",
        )
        # Sanity: gossip/config.rs:106 and four envelope.rs sites.
        gossip_files = {r["file"] for r in snappy}
        self.assertTrue(any("gossip" in f for f in gossip_files), gossip_files)
        self.assertTrue(any("envelope.rs" in f for f in gossip_files), gossip_files)


if __name__ == "__main__":
    unittest.main()
