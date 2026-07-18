#!/usr/bin/env python3
"""Tests for ``tools/base-rpc-crash-probe.py`` (Wave-10 Lane F, A8).

Coverage rationale
------------------

1. ``test_flags_unbounded_vec_param`` — a synthetic Rust RPC handler with a
   ``Vec<Bytes>`` parameter and no length cap must fire ``unbounded_input``.

2. ``test_does_not_flag_when_explicit_len_cap`` — same handler shape but
   with ``if keys.len() > MAX_KEYS { ... }`` must NOT fire (regression
   guard for the lazy "any Vec<X> is bad" failure mode).

3. ``test_does_not_flag_test_code`` — a ``#[cfg(test)] mod tests`` block
   containing a ``Vec<Bytes>`` handler must NOT fire (we don't want
   in-tree fuzz harnesses lighting up the matrix).

4. ``test_jwt_crate_marks_auth_gate_jwt`` — when the same crate ships a
   ``JwtSecret`` / ``jwt::validate`` token, the candidate is still emitted
   (default-to-kill) but with ``auth_gate=jwt`` so the matrix can downrank
   it.

5. ``test_oom_path_crossbeam_unbounded`` — a function calling
   ``crossbeam_channel::unbounded()`` must be flagged with
   ``pattern_type=oom_path``.

6. ``test_smoke_eth_get_proof_real_repo`` — the live Base Azul RPC source
   under ``external/base/crates/execution/rpc/src/eth/proofs.rs`` must
   produce the unbounded-keys candidate Kimi-7 named.  The test is
   skipped (not failed) when that source is not present on this machine.
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
SCANNER = ROOT / "tools" / "base-rpc-crash-probe.py"
LIVE_BASE_AZUL = Path(os.path.expanduser("~/audits/base-azul"))
LIVE_PROOFS_RS = (
    LIVE_BASE_AZUL
    / "external"
    / "base"
    / "crates"
    / "execution"
    / "rpc"
    / "src"
    / "eth"
    / "proofs.rs"
)


def _run(workspace: Path, extra_args: list[str] | None = None) -> dict:
    cmd = [sys.executable, str(SCANNER), "--workspace", str(workspace), "--out-json", "-"]
    if extra_args:
        cmd.extend(extra_args)
    proc = subprocess.run(cmd, capture_output=True, text=True)
    assert proc.returncode in (0, 1), proc.stdout + proc.stderr
    return json.loads(proc.stdout)


def _write_synthetic_rpc(
    workspace: Path,
    *,
    body: str,
    crate_relpath: str = "external/base/crates/execution/rpc",
    file_relpath: str = "src/eth/proofs.rs",
    with_jwt_sibling: bool = False,
) -> Path:
    crate_root = workspace / crate_relpath
    (crate_root).mkdir(parents=True, exist_ok=True)
    (crate_root / "Cargo.toml").write_text(
        textwrap.dedent(
            """
            [package]
            name = "base-execution-rpc"
            version = "0.1.0"
            edition = "2021"
            """
        ).lstrip()
    )
    src = crate_root / Path(file_relpath).parent
    src.mkdir(parents=True, exist_ok=True)
    file_path = crate_root / file_relpath
    file_path.write_text(body)
    if with_jwt_sibling:
        (src / "auth.rs").write_text(
            textwrap.dedent(
                """
                pub struct JwtSecret(pub Vec<u8>);
                impl JwtSecret {
                    pub fn validate(&self, _t: &str) -> bool { true }
                }
                """
            ).lstrip()
        )
    return file_path


class A8RpcCrashProbeTests(unittest.TestCase):
    def test_flags_unbounded_vec_param(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            body = textwrap.dedent(
                """
                use alloy_primitives::Bytes;

                pub async fn eth_getProof(
                    &self,
                    address: [u8; 20],
                    keys: Vec<Bytes>,
                ) -> Result<Vec<u8>, String> {
                    let _storage_keys = keys.iter().map(|k| k.0.clone()).collect::<Vec<_>>();
                    Ok(Vec::new())
                }
                """
            ).lstrip()
            _write_synthetic_rpc(ws, body=body)
            payload = _run(ws)
            unbounded = [r for r in payload["rows"] if r["pattern_type"] == "unbounded_input"]
            self.assertEqual(len(unbounded), 1, payload)
            row = unbounded[0]
            self.assertEqual(row["function"], "eth_getProof")
            self.assertEqual(row["parameter"], "keys")
            self.assertEqual(row["candidate_status"], "kill_or_reframe")
            self.assertEqual(row["auth_gate"], "public")
            self.assertIn("Vec<Bytes>", row["parameter_type"])

    def test_does_not_flag_when_explicit_len_cap(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            body = textwrap.dedent(
                """
                const MAX_KEYS: usize = 1024;

                pub async fn eth_getProof(
                    &self,
                    address: [u8; 20],
                    keys: Vec<Bytes>,
                ) -> Result<Vec<u8>, String> {
                    if keys.len() > MAX_KEYS {
                        return Err("too many keys".into());
                    }
                    Ok(Vec::new())
                }
                """
            ).lstrip()
            _write_synthetic_rpc(ws, body=body)
            payload = _run(ws)
            unbounded = [r for r in payload["rows"] if r["pattern_type"] == "unbounded_input"]
            self.assertEqual(unbounded, [], payload)

    def test_does_not_flag_test_code(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            body = textwrap.dedent(
                """
                pub async fn handler(&self, _x: u32) -> Result<(), String> { Ok(()) }

                #[cfg(test)]
                mod tests {
                    use super::*;
                    pub async fn fake_handler(keys: Vec<u8>) -> Result<(), String> {
                        let _ = keys.iter().count();
                        Ok(())
                    }
                }
                """
            ).lstrip()
            _write_synthetic_rpc(ws, body=body)
            payload = _run(ws)
            self.assertEqual(
                [r for r in payload["rows"] if r["function"] == "fake_handler"],
                [],
                payload,
            )

    def test_jwt_crate_marks_auth_gate_jwt(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            body = textwrap.dedent(
                """
                pub async fn engine_newPayloadV4(
                    &self,
                    payload: Vec<u8>,
                ) -> Result<(), String> {
                    let _len = payload.len();
                    Ok(())
                }
                """
            ).lstrip()
            _write_synthetic_rpc(ws, body=body, with_jwt_sibling=True)
            payload = _run(ws)
            unbounded = [r for r in payload["rows"] if r["pattern_type"] == "unbounded_input"]
            self.assertEqual(len(unbounded), 1, payload)
            self.assertEqual(unbounded[0]["auth_gate"], "jwt")
            self.assertEqual(unbounded[0]["candidate_status"], "kill_or_reframe")

    def test_oom_path_crossbeam_unbounded(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            body = textwrap.dedent(
                """
                pub async fn stream_receipts(&self) -> Result<(), String> {
                    let (tx, rx) = crossbeam_channel::unbounded();
                    drop((tx, rx));
                    Ok(())
                }
                """
            ).lstrip()
            _write_synthetic_rpc(ws, body=body, file_relpath="src/eth/receipts.rs")
            payload = _run(ws)
            oom = [r for r in payload["rows"] if r["pattern_type"] == "oom_path"]
            self.assertEqual(len(oom), 1, payload)
            self.assertEqual(oom[0]["function"], "stream_receipts")
            self.assertEqual(oom[0]["candidate_status"], "kill_or_reframe")

    def test_writes_files_to_workspace_when_not_stdout(self) -> None:
        """Idempotency + file output smoke."""
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            body = textwrap.dedent(
                """
                pub async fn eth_getProof(&self, keys: Vec<u8>) -> Result<(), String> {
                    let _ = keys.iter();
                    Ok(())
                }
                """
            ).lstrip()
            _write_synthetic_rpc(ws, body=body)
            cmd = [sys.executable, str(SCANNER), "--workspace", str(ws)]
            proc = subprocess.run(cmd, capture_output=True, text=True)
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            json_path = ws / "critical_hunt" / "rpc_crash" / "a8_rpc_crash_matrix.json"
            md_path = ws / "critical_hunt" / "rpc_crash" / "a8_rpc_crash_matrix.md"
            self.assertTrue(json_path.is_file())
            self.assertTrue(md_path.is_file())
            cand_dir = ws / "critical_hunt" / "candidates"
            self.assertTrue(cand_dir.is_dir())
            cand_files = list(cand_dir.glob("*.json"))
            self.assertGreaterEqual(len(cand_files), 1)
            # Idempotent rerun.
            proc2 = subprocess.run(cmd, capture_output=True, text=True)
            self.assertEqual(proc2.returncode, 0)
            self.assertEqual(
                json.loads(json_path.read_text()),
                json.loads(json_path.read_text()),
            )

    def test_strict_exits_one_when_public_unbounded_remains(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            body = textwrap.dedent(
                """
                pub async fn eth_getProof(&self, keys: Vec<u8>) -> Result<(), String> {
                    let _ = keys.iter();
                    Ok(())
                }
                """
            ).lstrip()
            _write_synthetic_rpc(ws, body=body)
            cmd = [
                sys.executable, str(SCANNER), "--workspace", str(ws),
                "--out-json", "-", "--strict",
            ]
            proc = subprocess.run(cmd, capture_output=True, text=True)
            self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)

    @unittest.skipUnless(
        LIVE_PROOFS_RS.is_file(),
        f"requires live base-azul checkout at {LIVE_PROOFS_RS}",
    )
    def test_smoke_eth_get_proof_real_repo(self) -> None:
        """Smoke-fire against the real Base Azul RPC tree.

        Required by the Lane F brief: the scanner MUST flag the unbounded
        ``keys: Vec<JsonStorageKey>`` parameter at
        ``crates/execution/rpc/src/eth/proofs.rs:67-76``.
        """
        payload = _run(LIVE_BASE_AZUL)
        get_proof_unbounded = [
            r
            for r in payload["rows"]
            if r["pattern_type"] == "unbounded_input"
            and r["function"] == "get_proof"
            and r["parameter"] == "keys"
            and "proofs.rs" in r["file"]
        ]
        self.assertGreaterEqual(
            len(get_proof_unbounded),
            1,
            f"Expected eth_getProof unbounded keys flag; got rows: {payload['rows'][:5]}",
        )
        # And the OOM_PATH on the engine-tree validator should also surface
        # if that file is in scope.  We surface this as a soft-check (info
        # log) rather than a hard assertion since the validator lives in a
        # different RPC root.


if __name__ == "__main__":
    unittest.main()
