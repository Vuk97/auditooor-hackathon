#!/usr/bin/env python3
"""Tests for ``tools/rust-cache-miss-policy-scanner.py`` (PR #546 K7-3).

Covers:
  * Vulnerable fixture: synthetic Rust file with err-arm-swallow +
    unwrap_or_default in payload-validation context -> flagged.
  * Clean fixture: explicit `return Err(...)` -> NOT flagged.
  * Test fixture exclusion: file under `tests/` dir -> NOT scanned.
  * Init-context unwrap_or_default suppressed.
  * `state_by_block_hash` only fires when the surrounding fn is a
    validator AND the block contains an early-Ok arm.
  * Real-corpus smoke: scan engine.rs lines 124-152 -> must flag the
    FN7 silent-pass at line 130 + unwrap_or_default at line 140.
  * Schema compatibility with base-critical-candidate-matrix.
  * Default-to-kill: every emitted row starts at `kill_or_reframe`.
  * Idempotent JSON output.

Stdlib-only. Tests use tempfile sandboxes.
"""
from __future__ import annotations

import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path


HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
SCANNER_PATH = ROOT / "tools" / "rust-cache-miss-policy-scanner.py"

spec = importlib.util.spec_from_file_location("rust_cache_miss_scanner", SCANNER_PATH)
assert spec is not None and spec.loader is not None
scanner = importlib.util.module_from_spec(spec)
sys.modules["rust_cache_miss_scanner"] = scanner
spec.loader.exec_module(scanner)  # type: ignore[union-attr]


VULNERABLE_RS = """\
//! synthetic validator with cache-miss policy bugs.

use anyhow::Result;

pub struct Validator;

impl Validator {
    pub fn validate_payload(&self, payload: &Payload) -> Result<()> {
        let storage = match self.lookup(payload.id) {
            Ok(s) => s,
            Err(_) => return Ok(()),
        };
        let updates = storage.updates.unwrap_or_default();
        match self.fetch(payload.parent) {
            Ok(_) => Ok(()),
            Err(_) => Ok(()),
        }
    }

    pub fn verify_root(&self, hash: H256) -> Result<()> {
        let Ok(state) = self.state_by_block_hash(hash) else {
            // FIXME: validate the parent later
            return Ok(());
        };
        Ok(())
    }

    pub fn check_optional(&self, opt: Option<u64>) -> Result<()> {
        let Some(v) = opt else {
            return Ok(());
        };
        Ok(())
    }
}
"""


CLEAN_RS = """\
use anyhow::Result;

pub struct Validator;

impl Validator {
    pub fn validate_payload(&self, payload: &Payload) -> Result<()> {
        let storage = match self.lookup(payload.id) {
            Ok(s) => s,
            Err(e) => return Err(e.into()),
        };
        if storage.updates.is_none() {
            return Err(anyhow::anyhow!("missing updates"));
        }
        let _updates = storage.updates.expect("validated above");
        Ok(())
    }
}
"""


INIT_RS = """\
use anyhow::Result;

pub struct Builder { val: u64 }

impl Builder {
    pub fn new() -> Self {
        let cfg = std::env::var("X").unwrap_or_default();
        let _ = cfg;
        Self { val: 0 }
    }

    pub fn build(self) -> Self {
        let _x = self.cfg.unwrap_or_default();
        self
    }
}
"""


TEST_RS = """\
//! tests live here.

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn t_validate() {
        let storage = match lookup() {
            Ok(s) => s,
            Err(_) => return Ok(()),
        };
        let _ = storage.updates.unwrap_or_default();
    }
}
"""


def _write(dir_: Path, name: str, body: str) -> Path:
    p = dir_ / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(body)
    return p


class VulnerableFixtureTests(unittest.TestCase):
    def test_vulnerable_fixture_flags_errswallow_and_unwrap(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            f = _write(tmp, "src/validator.rs", VULNERABLE_RS)
            rows = scanner.scan_file(f)
            kinds = {r.pattern_type for r in rows}
            self.assertIn("err_arm_swallow", kinds)
            self.assertIn("unwrap_or_default", kinds)
            self.assertIn("let_ok_early_ok", kinds)
            self.assertIn("let_some_early_ok", kinds)
            # Every row defaults to kill_or_reframe.
            for r in rows:
                self.assertEqual(r.candidate_status, "kill_or_reframe")
            # All rows include a "default-to-kill" note.
            for r in rows:
                self.assertTrue(any("default-to-kill" in n for n in r.notes), r.notes)

    def test_vulnerable_fixture_high_risk_when_validator_named(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            f = _write(tmp, "src/validator.rs", VULNERABLE_RS)
            rows = scanner.scan_file(f)
            high = [r for r in rows if r.risk_class == "high"]
            self.assertGreaterEqual(len(high), 2, [r.pattern_type for r in rows])
            # function_context populated for at least one validator-shaped fn.
            self.assertTrue(any("validate" in r.function_context or "verify" in r.function_context or "check" in r.function_context for r in rows))


class CleanFixtureTests(unittest.TestCase):
    def test_clean_fixture_does_not_flag_explicit_err(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            f = _write(tmp, "src/validator.rs", CLEAN_RS)
            rows = scanner.scan_file(f)
            self.assertEqual(rows, [], [r.pattern_type for r in rows])

    def test_init_context_unwrap_or_default_suppressed(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            f = _write(tmp, "src/builder.rs", INIT_RS)
            rows = scanner.scan_file(f)
            # `new` and `build` are init prefixes — unwrap_or_default suppressed.
            kinds = [r.pattern_type for r in rows]
            self.assertNotIn("unwrap_or_default", kinds, kinds)


class TestFixtureExclusionTests(unittest.TestCase):
    def test_file_under_tests_dir_not_scanned(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            f = _write(tmp, "crates/foo/tests/integration.rs", VULNERABLE_RS)
            rows = scanner.scan_file(f)
            self.assertEqual(rows, [])

    def test_file_named_tests_rs_not_scanned(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            f = _write(tmp, "src/foo_tests.rs", VULNERABLE_RS)
            rows = scanner.scan_file(f)
            self.assertEqual(rows, [])

    def test_cfg_test_module_not_scanned(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            f = _write(tmp, "src/foo.rs", TEST_RS)
            rows = scanner.scan_file(f)
            # The functions are inside #[cfg(test)] mod tests — must be empty.
            self.assertEqual(rows, [])


class StateByBlockHashGatingTests(unittest.TestCase):
    def test_non_validator_state_by_block_hash_not_flagged(self) -> None:
        body = """\
pub fn fetch_state(p: &P, h: H256) -> Result<S> {
    p.state_by_block_hash(h)
}
"""
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            f = _write(tmp, "src/fetch.rs", body)
            rows = scanner.scan_file(f)
            kinds = [r.pattern_type for r in rows]
            self.assertNotIn("state_by_block_hash_silent_pass", kinds)

    def test_validator_with_no_early_ok_not_flagged(self) -> None:
        body = """\
pub fn validate(&self, h: H256) -> Result<()> {
    let s = self.provider.state_by_block_hash(h)?;
    self.run_checks(s)
}
"""
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            f = _write(tmp, "src/v.rs", body)
            rows = scanner.scan_file(f)
            kinds = [r.pattern_type for r in rows]
            self.assertNotIn("state_by_block_hash_silent_pass", kinds)


class RealCorpusFN7SmokeTests(unittest.TestCase):
    """The FN7 silent-pass at engine.rs:124-152 must be flagged."""

    REAL_PATH = Path(
        "/Users/wolf/audits/base-azul/external/base/crates/execution/node/src/engine.rs"
    )

    def test_fn7_silent_pass_flagged(self) -> None:
        if not self.REAL_PATH.is_file():
            self.skipTest(f"real corpus not available at {self.REAL_PATH}")
        rows = scanner.scan_file(self.REAL_PATH)
        # Must have a hit inside lines 124-152 with the FN7 shape.
        fn7_rows = [
            r for r in rows
            if 124 <= r.line <= 152
            and "validate_block_post_execution_with_hashed_state" in r.function_context
        ]
        self.assertTrue(fn7_rows, f"FN7 silent-pass NOT flagged. all rows: {[(r.line, r.pattern_type) for r in rows]}")
        kinds = {r.pattern_type for r in fn7_rows}
        # The early-Ok shape at line 130 must be present.
        self.assertTrue(
            "let_ok_early_ok" in kinds or "state_by_block_hash_silent_pass" in kinds,
            f"FN7 early-Ok pattern not flagged. fn7_kinds={kinds}",
        )


class SchemaCompatibilityTests(unittest.TestCase):
    REQUIRED_FIELDS = (
        "candidate_id",
        "scope_asset",
        "impact_mapping",
        "candidate_status",
        "production_path",
        "required_proof",
        "artifact_refs",
    )

    def test_rows_have_all_matrix_required_fields(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            f = _write(tmp, "src/v.rs", VULNERABLE_RS)
            rows = scanner.scan_file(f)
            self.assertTrue(rows)
            for row in rows:
                d = row.__dict__
                for field in self.REQUIRED_FIELDS:
                    self.assertIn(field, d, f"missing {field}")

    def test_render_json_schema_version(self) -> None:
        rendered = scanner.render_json([], Path("/tmp/ws"))
        self.assertEqual(rendered["schema"], scanner.SCHEMA_VERSION)
        self.assertEqual(rendered["row_count"], 0)


class IdempotenceTests(unittest.TestCase):
    def test_two_runs_produce_identical_json(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            _write(tmp, "external/base/crates/foo/src/v.rs", VULNERABLE_RS)
            out1 = tmp / "out1"
            out2 = tmp / "out2"
            rc1 = scanner.main(["--workspace", str(tmp), "--out-dir", str(out1)])
            rc2 = scanner.main(["--workspace", str(tmp), "--out-dir", str(out2)])
            self.assertEqual(rc1, 0)
            self.assertEqual(rc2, 0)
            j1 = (out1 / "rust_cache_miss_candidates.json").read_text()
            j2 = (out2 / "rust_cache_miss_candidates.json").read_text()
            self.assertEqual(j1, j2)


class CLITests(unittest.TestCase):
    def test_help_exits_zero(self) -> None:
        parser = scanner.build_arg_parser()
        with self.assertRaises(SystemExit) as ctx:
            parser.parse_args(["--help"])
        self.assertEqual(ctx.exception.code, 0)

    def test_strict_mode_returns_one_when_high_risk(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            _write(tmp, "external/base/crates/foo/src/v.rs", VULNERABLE_RS)
            rc = scanner.main(["--workspace", str(tmp), "--out-dir", str(tmp / "out"), "--strict"])
            self.assertEqual(rc, 1)

    def test_strict_mode_returns_zero_on_clean_workspace(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            _write(tmp, "external/base/crates/foo/src/v.rs", CLEAN_RS)
            rc = scanner.main(["--workspace", str(tmp), "--out-dir", str(tmp / "out"), "--strict"])
            self.assertEqual(rc, 0)


if __name__ == "__main__":
    unittest.main()
