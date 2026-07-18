#!/usr/bin/env python3
"""Lock test for P-16 trusted_forwarder_rpc_without_auth_primitive.

Source: Base-Azul engagement-3 FN-B3 (base/base@v0.8.0-rc.24:
crates/execution/txpool/src/builder/rpc.rs:72). A Rust RPC handler accepts a
caller-supplied ``sender: Address`` and constructs
``Recovered::new_unchecked(...)`` while the containing crate ships no JWT,
mTLS, or IP-allowlist primitive. The public RPC endpoint is therefore
forgeable.

Hard-negative #1: a crate-sibling file under the same ``Cargo.toml`` that
imports ``jsonwebtoken`` / uses ``JwtSecret`` disables the finding (the crate
ships an auth primitive).

Hard-negative #2: a function that reads ``sender`` but never calls
``Recovered::new_unchecked`` must not fire — otherwise the scanner degrades
to "any fn with a sender argument is an auth bug".
"""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCANNER = ROOT / "tools" / "trusted-forwarder-rpc-scanner.py"


def _run(target: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(SCANNER), str(target), "--json"],
        capture_output=True,
        text=True,
    )


def _write_crate(root: Path, *, with_auth: bool, rpc_body: str) -> Path:
    (root / "Cargo.toml").write_text(
        textwrap.dedent(
            """
            [package]
            name = "txpool"
            version = "0.1.0"
            edition = "2021"

            [dependencies]
            """
        ).lstrip()
        + ("jsonwebtoken = \"9\"\n" if with_auth else "")
    )
    src = root / "crates" / "execution" / "txpool" / "src" / "builder"
    src.mkdir(parents=True, exist_ok=True)
    (src / "rpc.rs").write_text(rpc_body)
    if with_auth:
        # A sibling file that proves the crate ships JwtSecret usage.
        (src / "auth.rs").write_text(
            textwrap.dedent(
                """
                use jsonwebtoken::{decode, Validation};

                pub struct JwtSecret(pub Vec<u8>);

                impl JwtSecret {
                    pub fn validate(&self, token: &str) -> bool {
                        // jwt::validate stub
                        !token.is_empty()
                    }
                }
                """
            ).lstrip()
        )
    return root


class P16TrustedForwarderRpcTests(unittest.TestCase):
    def test_flags_rpc_handler_in_crate_without_auth_primitive(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            rpc_body = textwrap.dedent(
                """
                use alloy_primitives::Address;

                pub struct Recovered<T>(T, Address);
                impl<T> Recovered<T> {
                    pub fn new_unchecked(inner: T, sender: Address) -> Self { Self(inner, sender) }
                }

                pub async fn base_insertValidatedTransaction(
                    tx: Vec<u8>,
                    sender: Address,
                ) -> Result<(), String> {
                    // Trusted forwarder: caller asserts its own sender.
                    let _rec = Recovered::new_unchecked(tx, sender);
                    Ok(())
                }
                """
            ).lstrip()
            _write_crate(root, with_auth=False, rpc_body=rpc_body)

            rpc_path = root / "crates" / "execution" / "txpool" / "src" / "builder" / "rpc.rs"
            proc = _run(rpc_path)
            self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
            out = json.loads(proc.stdout)
            self.assertEqual(len(out["findings"]), 1, out)
            finding = out["findings"][0]
            self.assertEqual(
                finding["pattern"], "trusted_forwarder_rpc_without_auth_primitive"
            )
            self.assertEqual(finding["function"], "base_insertValidatedTransaction")
            self.assertEqual(finding["auth_tokens_found"], [])

    def test_does_not_flag_when_crate_ships_jwt_auth(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            rpc_body = textwrap.dedent(
                """
                use alloy_primitives::Address;
                use crate::builder::auth::JwtSecret;

                pub struct Recovered<T>(T, Address);
                impl<T> Recovered<T> {
                    pub fn new_unchecked(inner: T, sender: Address) -> Self { Self(inner, sender) }
                }

                pub async fn base_insertValidatedTransaction(
                    tx: Vec<u8>,
                    sender: Address,
                    jwt: &JwtSecret,
                    token: &str,
                ) -> Result<(), String> {
                    if !jwt.validate(token) { return Err("bad jwt".into()); }
                    let _rec = Recovered::new_unchecked(tx, sender);
                    Ok(())
                }
                """
            ).lstrip()
            _write_crate(root, with_auth=True, rpc_body=rpc_body)

            rpc_path = root / "crates" / "execution" / "txpool" / "src" / "builder" / "rpc.rs"
            proc = _run(rpc_path)
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            out = json.loads(proc.stdout)
            self.assertEqual(out["findings"], [], out)

    def test_rustls_dep_alone_does_not_suppress(self) -> None:
        """Codex review #3 regression: a bare ``rustls`` dependency in
        Cargo.toml — with no client-cert verifier wiring and no JWT
        middleware in the handler file or its router-mount path — is NOT
        proof of mTLS client auth and MUST NOT suppress the finding.
        """
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "Cargo.toml").write_text(
                textwrap.dedent(
                    """
                    [package]
                    name = "txpool"
                    version = "0.1.0"
                    edition = "2021"

                    [dependencies]
                    rustls = "0.23"
                    """
                ).lstrip()
            )
            src = root / "crates" / "execution" / "txpool" / "src" / "builder"
            src.mkdir(parents=True, exist_ok=True)
            (src / "rpc.rs").write_text(
                textwrap.dedent(
                    """
                    use alloy_primitives::Address;

                    pub struct Recovered<T>(T, Address);
                    impl<T> Recovered<T> {
                        pub fn new_unchecked(inner: T, sender: Address) -> Self { Self(inner, sender) }
                    }

                    pub async fn base_insertValidatedTransaction(
                        tx: Vec<u8>,
                        sender: Address,
                    ) -> Result<(), String> {
                        // Trusted forwarder: caller asserts its own sender.
                        let _rec = Recovered::new_unchecked(tx, sender);
                        Ok(())
                    }
                    """
                ).lstrip()
            )

            rpc_path = src / "rpc.rs"
            proc = _run(rpc_path)
            self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
            out = json.loads(proc.stdout)
            self.assertEqual(len(out["findings"]), 1, out)
            finding = out["findings"][0]
            self.assertEqual(finding["function"], "base_insertValidatedTransaction")
            self.assertEqual(finding["auth_tokens_found"], [])

    def test_hard_negative_function_never_constructs_unchecked(self) -> None:
        """Hard-negative: a function that takes `sender: Address` but never
        touches Recovered::new_unchecked must not fire — otherwise the scanner
        degrades to 'any fn with a sender arg is a bug'."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            rpc_body = textwrap.dedent(
                """
                use alloy_primitives::Address;

                pub async fn log_sender(sender: Address) -> Result<(), String> {
                    println!("sender = {:?}", sender);
                    Ok(())
                }
                """
            ).lstrip()
            _write_crate(root, with_auth=False, rpc_body=rpc_body)

            rpc_path = root / "crates" / "execution" / "txpool" / "src" / "builder" / "rpc.rs"
            proc = _run(rpc_path)
            self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
            out = json.loads(proc.stdout)
            self.assertEqual(out["findings"], [], out)


if __name__ == "__main__":
    unittest.main()
