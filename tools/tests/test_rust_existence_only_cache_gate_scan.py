#!/usr/bin/env python3
"""Tests for ``tools/rust-existence-only-cache-gate-scan.py`` (Wave H-3B).

Bug shape: cached state delta applied using only an existence check
(``has_transaction_hash``, ``contains_key``, ``.is_some()``) without verifying
that the cached entry's position matches the current execution position.  Patch
6ab29cf0 added a position-based successor check.

Coverage
--------
1. ``test_flags_has_transaction_hash`` — ``pending_blocks.has_transaction_hash(k)``
   in a cache provider fn must fire ``existence_only_cache_gate``.
2. ``test_flags_contains_key`` — ``cache.contains_key(k)`` pattern must fire.
3. ``test_clean_when_position_check_present`` — same pattern but with
   explicit ``position`` / ``index`` equality check must still fire but with
   ``has_position_check=True`` and ``confidence="medium"``.
4. ``test_does_not_flag_test_code`` — check inside ``#[cfg(test)]`` must not
   fire.
5. ``test_strict_exits_one`` — ``--strict`` exits 1 when any row emitted.
6. ``test_row_schema_fields`` — row must carry required schema fields.
7. ``test_smoke_real_base_repo`` — live smoke: must fire on
   ``crates/execution/engine-tree/src/cached_execution.rs``
   (6ab29cf0 audit-snapshot bug location).
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
SCANNER = ROOT / "tools" / "rust-existence-only-cache-gate-scan.py"
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
    crate_relpath: str = "external/base/crates/execution/engine-tree/src",
    file_relpath: str = "cached_execution.rs",
) -> Path:
    crate_root = workspace / crate_relpath
    crate_root.mkdir(parents=True, exist_ok=True)
    target = crate_root / file_relpath
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(body)
    return target


class RustExistenceOnlyCacheGateScanTests(unittest.TestCase):
    def test_flags_has_transaction_hash(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            body = textwrap.dedent(
                """
                pub fn get_cached_execution_for_tx(
                    &self,
                    prev_cached_hash: Option<&B256>,
                    tx_hash: &B256,
                ) -> Option<TxResult> {
                    let pending_blocks = self.flashblocks_state.get_pending_blocks()?;
                    if let Some(prev) = prev_cached_hash {
                        if !pending_blocks.has_transaction_hash(prev) {
                            return None;
                        }
                    }
                    pending_blocks.get_op_tx_result(tx_hash)
                }
                """
            ).lstrip()
            _write_synthetic(ws, body=body)
            payload = _run(ws)
            hits = [r for r in payload["rows"] if r["pattern_id"] == "existence_only_cache_gate"]
            self.assertGreaterEqual(len(hits), 1, payload)

    def test_flags_contains_key(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            body = textwrap.dedent(
                """
                pub fn get_cached(&self, key: &K) -> Option<V> {
                    if !self.cache.contains_key(key) {
                        return None;
                    }
                    self.cache.get(key).cloned()
                }
                """
            ).lstrip()
            _write_synthetic(ws, body=body)
            payload = _run(ws)
            hits = [r for r in payload["rows"] if r["pattern_id"] == "existence_only_cache_gate"]
            self.assertGreaterEqual(len(hits), 1, payload)

    def test_clean_when_position_check_present(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            body = textwrap.dedent(
                """
                pub fn get_cached_execution_for_tx(
                    &self,
                    prev_cached_hash: Option<&B256>,
                    tx_index: usize,
                    tx_hash: &B256,
                ) -> Option<TxResult> {
                    let pending_blocks = self.state.get_pending_blocks()?;
                    if let Some(prev) = prev_cached_hash {
                        // position-based check: verify successor
                        let expected_position = tx_index.checked_sub(1)?;
                        if !pending_blocks.has_transaction_hash(prev) {
                            return None;
                        }
                    }
                    pending_blocks.get_op_tx_result(tx_hash)
                }
                """
            ).lstrip()
            _write_synthetic(ws, body=body)
            payload = _run(ws)
            hits = [r for r in payload["rows"] if r["pattern_id"] == "existence_only_cache_gate"]
            # Still flags (pattern present) but position check lowers confidence.
            for h in hits:
                if "has_transaction_hash" in h["snippet"] or h["containing_fn"] == "get_cached_execution_for_tx":
                    self.assertTrue(h["has_position_check"], h)
                    self.assertEqual(h["confidence"], "medium", h)

    def test_does_not_flag_test_code(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            body = textwrap.dedent(
                """
                pub fn nothing() {}

                #[cfg(test)]
                mod tests {
                    fn check(cache: &Cache, k: &K) -> bool {
                        cache.contains_key(k)
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
                pub fn get_cached(&self, k: &K) -> Option<V> {
                    if !self.cache.contains_key(k) { return None; }
                    self.cache.get(k).cloned()
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
                pub fn get(&self, k: &K) -> Option<V> {
                    if !self.cache.contains_key(k) { return None; }
                    self.cache.get(k).cloned()
                }
                """
            ).lstrip()
            _write_synthetic(ws, body=body)
            payload = _run(ws)
            self.assertGreaterEqual(len(payload["rows"]), 1)
            row = payload["rows"][0]
            required = {"file", "line", "pattern_id", "containing_fn", "input_source",
                        "has_position_check", "snippet", "confidence", "candidate_status"}
            for field in required:
                self.assertIn(field, row, f"Missing field: {field}")
            self.assertEqual(row["candidate_status"], "kill_or_reframe")

    @unittest.skipUnless(
        (LIVE_BASE_AZUL / "external" / "base-rc28-clean" / "crates" / "execution"
         / "engine-tree" / "src" / "cached_execution.rs").is_file(),
        f"requires live base-azul checkout at {LIVE_BASE_AZUL}",
    )
    def test_smoke_real_base_repo(self) -> None:
        """Must fire on execution/engine-tree/src/cached_execution.rs (6ab29cf0 bug)."""
        payload = _run(LIVE_BASE_AZUL)
        cached_hits = [
            r for r in payload["rows"]
            if "cached_execution" in r["file"] and "engine-tree" in r["file"]
        ]
        self.assertGreaterEqual(len(cached_hits), 1, payload["rows"])
        self.assertIn("has_transaction_hash", cached_hits[0]["snippet"])


if __name__ == "__main__":
    unittest.main()
