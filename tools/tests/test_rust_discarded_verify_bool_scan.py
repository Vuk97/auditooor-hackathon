#!/usr/bin/env python3
"""Tests for ``tools/rust-discarded-verify-bool-scan.py`` (Wave H-3B).

Bug shape: a function returning ``Result<bool, E>`` is used with ``?`` but
the ``bool`` inside ``Ok(bool)`` is discarded — ``Ok(false)`` is treated as
success.  Patch a974aa35 fixed ``KzgProof::verify_kzg_proof(...)?`` to bind
and check the boolean result.

Coverage
--------
1. ``test_flags_verify_kzg_proof_discarded`` — bare
   ``something.verify_kzg_proof(...).map_err(...)? ;`` must fire
   ``discarded_verify_bool``.
2. ``test_flags_verify_standalone_q`` — ``verify_proof(...)? ;`` at statement
   level must fire.
3. ``test_clean_bound_result_checked`` — ``let valid = ...; if !valid { return Err(...) }``
   must NOT fire (result is bound and checked).
4. ``test_clean_let_binding`` — ``let _result = call(...)?;`` must NOT fire.
5. ``test_does_not_flag_test_code`` — statement-level ? in ``#[cfg(test)]``
   must not fire.
6. ``test_strict_exits_one`` — ``--strict`` exits 1 when any row emitted.
7. ``test_row_schema_fields`` — row must carry required schema fields.
8. ``test_smoke_real_base_repo`` — live smoke: must fire on
   ``crates/succinct/utils/client/src/precompiles/custom.rs``
   (a974aa35 audit-snapshot bug location).
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
SCANNER = ROOT / "tools" / "rust-discarded-verify-bool-scan.py"
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
    crate_relpath: str = "external/base/crates/proof/succinct/utils/client/src/precompiles",
    file_relpath: str = "custom.rs",
) -> Path:
    crate_root = workspace / crate_relpath
    crate_root.mkdir(parents=True, exist_ok=True)
    target = crate_root / file_relpath
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(body)
    return target


class RustDiscardedVerifyBoolScanTests(unittest.TestCase):
    def test_flags_verify_kzg_proof_discarded(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            body = textwrap.dedent(
                """
                pub fn verify_kzg_proof(&self, z: &[u8; 32], y: &[u8; 32]) -> Result<(), PrecompileError> {
                    KzgProof::verify_kzg_proof(&commitment, &z, &y, &proof, &self.kzg_settings)
                        .map_err(|_| PrecompileError::BlobVerifyKzgProofFailed)?;
                    Ok(())
                }
                """
            ).lstrip()
            _write_synthetic(ws, body=body)
            payload = _run(ws)
            hits = [r for r in payload["rows"] if r["pattern_id"] == "discarded_verify_bool"]
            self.assertGreaterEqual(len(hits), 1, payload)
            self.assertEqual(hits[0]["confidence"], "high")

    def test_flags_verify_standalone_q(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            body = textwrap.dedent(
                """
                pub fn run(ctx: &Ctx) -> Result<(), Error> {
                    verify_proof(&ctx.proof)?;
                    Ok(())
                }
                """
            ).lstrip()
            _write_synthetic(ws, body=body)
            payload = _run(ws)
            hits = [r for r in payload["rows"] if r["pattern_id"] == "discarded_verify_bool"]
            self.assertGreaterEqual(len(hits), 1, payload)

    def test_clean_bound_result_checked(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            body = textwrap.dedent(
                """
                pub fn verify_kzg(&self, z: &[u8; 32], y: &[u8; 32]) -> Result<(), Error> {
                    let valid = KzgProof::verify_kzg_proof(&commitment, &z, &y, &proof, &self.settings)
                        .map_err(|_| Error::Failed)?;
                    if !valid {
                        return Err(Error::Failed);
                    }
                    Ok(())
                }
                """
            ).lstrip()
            _write_synthetic(ws, body=body)
            payload = _run(ws)
            # The let binding means result is not discarded at statement level.
            hits = [r for r in payload["rows"] if r["pattern_id"] == "discarded_verify_bool"]
            self.assertEqual(hits, [], payload)

    def test_clean_let_binding(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            body = textwrap.dedent(
                """
                pub fn check(ctx: &Ctx) -> Result<bool, Error> {
                    let result = verify_proof(&ctx.proof)?;
                    Ok(result)
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
                pub fn prod() {}

                #[cfg(test)]
                mod tests {
                    fn check_kzg() -> Result<(), Error> {
                        verify_kzg_proof(&c, &z, &y, &p)?;
                        Ok(())
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
                pub fn run(ctx: &Ctx) -> Result<(), Error> {
                    verify_kzg_proof(&ctx.c, &ctx.z, &ctx.y, &ctx.p)?;
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
                pub fn f(ctx: &Ctx) -> Result<(), Error> {
                    verify_proof(&ctx.p)?;
                    Ok(())
                }
                """
            ).lstrip()
            _write_synthetic(ws, body=body)
            payload = _run(ws)
            self.assertGreaterEqual(len(payload["rows"]), 1)
            row = payload["rows"][0]
            required = {"file", "line", "pattern_id", "containing_fn", "input_source",
                        "snippet", "confidence", "candidate_status"}
            for field in required:
                self.assertIn(field, row, f"Missing field: {field}")
            self.assertEqual(row["candidate_status"], "kill_or_reframe")

    @unittest.skipUnless(
        (LIVE_BASE_AZUL / "external" / "base-rc28-clean" / "crates" / "succinct"
         / "utils" / "client" / "src" / "precompiles" / "custom.rs").is_file(),
        f"requires live base-azul checkout at {LIVE_BASE_AZUL}",
    )
    def test_smoke_real_base_repo(self) -> None:
        """Must fire on succinct/.../precompiles/custom.rs (a974aa35 bug location)."""
        payload = _run(LIVE_BASE_AZUL)
        custom_hits = [
            r for r in payload["rows"]
            if "custom.rs" in r["file"] and "succinct" in r["file"]
            and "precompile" in r["file"]
        ]
        self.assertGreaterEqual(len(custom_hits), 1, payload["rows"])
        self.assertIn("kzg", custom_hits[0]["snippet"].lower())


if __name__ == "__main__":
    unittest.main()
