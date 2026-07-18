#!/usr/bin/env python3
"""Tests for ``tools/rust-hardfork-precompile-address-mismatch-scan.py`` (Wave H-3B).

Bug shape: hardfork-versioned precompile address mismatch — ``P256VERIFY``
(pre-Osaka address) used in a hardfork-specific zkVM setup path where
``P256VERIFY_OSAKA`` is expected.  Patch 56381928 fixed the registry to use
the Azul/Osaka variant.

Coverage
--------
1. ``test_flags_p256verify_bare_in_hardfork_context`` — file with ``OpSpecId``
   context + bare ``P256VERIFY`` (not ``P256VERIFY_OSAKA``) must fire
   ``hardfork_precompile_non_osaka_in_zkvm``.
2. ``test_clean_p256verify_osaka_only`` — file using only ``P256VERIFY_OSAKA``
   must NOT fire.
3. ``test_no_flag_without_hardfork_context`` — file with bare ``P256VERIFY``
   but no hardfork context (no ``OpSpecId``/``BASE_V1``/``OSAKA``) must NOT
   fire.
4. ``test_in_setup_fn_raises_confidence`` — ``P256VERIFY`` inside a
   ``get_precompiles`` fn in a hardfork file must fire with
   ``confidence="high"`` and ``in_setup_fn=True``.
5. ``test_does_not_flag_test_code`` — usage inside ``#[cfg(test)]`` must not
   fire.
6. ``test_strict_exits_one`` — ``--strict`` exits 1 when any row emitted.
7. ``test_row_schema_fields`` — row must carry required schema fields.
8. ``test_smoke_real_base_repo`` — live smoke: must fire on
   ``crates/succinct/utils/client/src/precompiles/mod.rs``
   (56381928 audit-snapshot bug location, ``get_precompiles`` fn).
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
SCANNER = ROOT / "tools" / "rust-hardfork-precompile-address-mismatch-scan.py"
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
    crate_relpath: str = "external/base/crates/succinct/utils/client/src/precompiles",
    file_relpath: str = "mod.rs",
) -> Path:
    crate_root = workspace / crate_relpath
    crate_root.mkdir(parents=True, exist_ok=True)
    target = crate_root / file_relpath
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(body)
    return target


class RustHardforkPrecompileAddressMismatchScanTests(unittest.TestCase):
    def test_flags_p256verify_bare_in_hardfork_context(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            body = textwrap.dedent(
                """
                use base_common_evm::OpSpecId;

                fn get_precompiles() -> Vec<Precompile> {
                    vec![
                        secp256r1::P256VERIFY,
                    ]
                }
                """
            ).lstrip()
            _write_synthetic(ws, body=body)
            payload = _run(ws)
            hits = [r for r in payload["rows"]
                    if r["pattern_id"] == "hardfork_precompile_non_osaka_in_zkvm"]
            self.assertGreaterEqual(len(hits), 1, payload)

    def test_clean_p256verify_osaka_only(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            body = textwrap.dedent(
                """
                use base_common_evm::OpSpecId;

                fn base_v1() -> Vec<Precompile> {
                    vec![
                        secp256r1::P256VERIFY_OSAKA,
                    ]
                }
                """
            ).lstrip()
            _write_synthetic(ws, body=body)
            payload = _run(ws)
            # P256VERIFY_OSAKA only — must not fire.
            self.assertEqual(payload["rows"], [], payload)

    def test_no_flag_without_hardfork_context(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            body = textwrap.dedent(
                """
                fn add_precompile(precompiles: &mut Vec<Precompile>) {
                    precompiles.push(secp256r1::P256VERIFY);
                }
                """
            ).lstrip()
            _write_synthetic(ws, body=body)
            payload = _run(ws)
            # No hardfork context present — scanner skips this file.
            self.assertEqual(payload["rows"], [], payload)

    def test_in_setup_fn_raises_confidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            body = textwrap.dedent(
                """
                use base_common_evm::OpSpecId;

                fn get_precompiles() -> Vec<Precompile> {
                    vec![secp256r1::P256VERIFY]
                }
                """
            ).lstrip()
            _write_synthetic(ws, body=body)
            payload = _run(ws)
            hits = [r for r in payload["rows"]
                    if r["pattern_id"] == "hardfork_precompile_non_osaka_in_zkvm"]
            self.assertGreaterEqual(len(hits), 1, payload)
            self.assertEqual(hits[0]["confidence"], "high")
            self.assertTrue(hits[0]["in_setup_fn"])

    def test_does_not_flag_test_code(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            body = textwrap.dedent(
                """
                use base_common_evm::OpSpecId;

                pub fn nothing() {}

                #[cfg(test)]
                mod tests {
                    fn test_p256() {
                        let p = secp256r1::P256VERIFY;
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
                use base_common_evm::OpSpecId;

                fn get_precompiles() -> Vec<Precompile> {
                    vec![secp256r1::P256VERIFY]
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
                use base_common_evm::OpSpecId;

                fn get_precompiles() -> Vec<Precompile> {
                    vec![secp256r1::P256VERIFY]
                }
                """
            ).lstrip()
            _write_synthetic(ws, body=body)
            payload = _run(ws)
            self.assertGreaterEqual(len(payload["rows"]), 1)
            row = payload["rows"][0]
            required = {"file", "line", "pattern_id", "containing_fn", "input_source",
                        "has_hardfork_context", "in_setup_fn", "snippet",
                        "confidence", "candidate_status"}
            for field in required:
                self.assertIn(field, row, f"Missing field: {field}")
            self.assertEqual(row["candidate_status"], "kill_or_reframe")

    @unittest.skipUnless(
        (LIVE_BASE_AZUL / "external" / "base-rc28-clean" / "crates" / "succinct"
         / "utils" / "client" / "src" / "precompiles" / "mod.rs").is_file(),
        f"requires live base-azul checkout at {LIVE_BASE_AZUL}",
    )
    def test_smoke_real_base_repo(self) -> None:
        """Must fire on succinct/.../precompiles/mod.rs (56381928 bug location)."""
        payload = _run(LIVE_BASE_AZUL)
        mod_hits = [
            r for r in payload["rows"]
            if "mod.rs" in r["file"] and "succinct" in r["file"] and "precompile" in r["file"]
        ]
        self.assertGreaterEqual(len(mod_hits), 1, payload["rows"])
        self.assertIn("P256VERIFY", mod_hits[0]["snippet"])
        self.assertEqual(mod_hits[0]["confidence"], "high")


if __name__ == "__main__":
    unittest.main()
