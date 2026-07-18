"""Tests for tools/rust-detector-runner.py (L13 Frost-pattern bootstrap)."""
from __future__ import annotations

import importlib.util
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path


HERE = Path(__file__).resolve().parent
TOOLS_DIR = HERE.parent
REPO_ROOT = TOOLS_DIR.parent
RUNNER_PATH = TOOLS_DIR / "rust-detector-runner.py"
RUST_FIXTURES = REPO_ROOT / "detectors" / "fixtures" / "rust"


def _load_runner():
    """rust-detector-runner.py has a hyphen so it isn't a normal module."""
    spec = importlib.util.spec_from_file_location(
        "rust_detector_runner", RUNNER_PATH
    )
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    sys.modules["rust_detector_runner"] = mod
    spec.loader.exec_module(mod)
    return mod


class RustDetectorRunnerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = _load_runner()

    # ------------------------------------------------------------------
    # Pattern 1 — rust.frost.dkg.self_identifier_in_round_packages
    # ------------------------------------------------------------------
    def test_dkg_self_identifier_positive(self):
        with tempfile.TemporaryDirectory() as ws:
            shutil.copy(
                RUST_FIXTURES / "positive"
                / "dkg_self_identifier_in_round_packages.rs",
                Path(ws) / "fixture.rs",
            )
            summary = self.mod.scan_workspace(Path(ws))
            pid = "rust.frost.dkg.self_identifier_in_round_packages"
            self.assertGreaterEqual(
                summary["patterns"][pid]["hit_count"], 1,
                f"expected >=1 hit in positive fixture, got: "
                f"{summary['patterns'][pid]}",
            )
            functions = [
                h["extra"]["function"]
                for h in summary["patterns"][pid]["hits"]
            ]
            self.assertIn("part2", functions)

    def test_dkg_self_identifier_negative(self):
        with tempfile.TemporaryDirectory() as ws:
            shutil.copy(
                RUST_FIXTURES / "negative"
                / "dkg_self_identifier_in_round_packages.rs",
                Path(ws) / "fixture.rs",
            )
            summary = self.mod.scan_workspace(Path(ws))
            pid = "rust.frost.dkg.self_identifier_in_round_packages"
            self.assertEqual(
                summary["patterns"][pid]["hit_count"], 0,
                f"expected 0 hits in negative (guarded) fixture, got: "
                f"{summary['patterns'][pid]}",
            )

    # ------------------------------------------------------------------
    # Pattern 2 — rust.frost.aggregate.under_threshold_signature_shares
    # ------------------------------------------------------------------
    def test_aggregate_under_threshold_positive(self):
        with tempfile.TemporaryDirectory() as ws:
            shutil.copy(
                RUST_FIXTURES / "positive"
                / "aggregate_under_threshold_signature_shares.rs",
                Path(ws) / "fixture.rs",
            )
            summary = self.mod.scan_workspace(Path(ws))
            pid = "rust.frost.aggregate.under_threshold_signature_shares"
            self.assertGreaterEqual(
                summary["patterns"][pid]["hit_count"], 1,
                f"expected >=1 hit in positive fixture, got: "
                f"{summary['patterns'][pid]}",
            )
            functions = [
                h["extra"]["function"]
                for h in summary["patterns"][pid]["hits"]
            ]
            self.assertIn("aggregate", functions)

    def test_aggregate_under_threshold_negative(self):
        with tempfile.TemporaryDirectory() as ws:
            shutil.copy(
                RUST_FIXTURES / "negative"
                / "aggregate_under_threshold_signature_shares.rs",
                Path(ws) / "fixture.rs",
            )
            summary = self.mod.scan_workspace(Path(ws))
            pid = "rust.frost.aggregate.under_threshold_signature_shares"
            self.assertEqual(
                summary["patterns"][pid]["hit_count"], 0,
                f"expected 0 hits in negative (guarded) fixture, got: "
                f"{summary['patterns'][pid]}",
            )

    # ------------------------------------------------------------------
    # Runner dispatch / structural shape
    # ------------------------------------------------------------------
    def test_list_emits_both_patterns(self):
        # Capture stdout via a buffer to verify --list output.
        from io import StringIO
        import contextlib
        buf = StringIO()
        with contextlib.redirect_stdout(buf):
            rc = self.mod.main(["--list"])
        self.assertEqual(rc, 0)
        out = buf.getvalue().strip().splitlines()
        # wave-1 patterns must still be present.
        self.assertIn(
            "rust.frost.dkg.self_identifier_in_round_packages", out
        )
        self.assertIn(
            "rust.frost.aggregate.under_threshold_signature_shares", out
        )
        # wave-2 patterns added by PR #658 Tier-C #2.
        self.assertIn(
            "rust.frost.wave2.nonce_reuse_risk_unscoped_secret", out
        )
        self.assertIn(
            "rust.frost.wave2.threshold_check_against_active_set_only", out
        )
        self.assertIn(
            "rust.frost.wave2.keypackage_serialization_unauthenticated", out
        )
        # class-B RU1 pattern.
        self.assertIn(
            "rust.panic.untrusted_ingress_unguarded_panic", out
        )
        self.assertEqual(
            len(out), 6,
            "--list should print exactly the 6 wired patterns "
            "(2 wave-1 + 3 wave-2 + 1 class-B)",
        )

    def test_summary_schema_shape(self):
        """Summary JSON must carry the auditooor.rust_detector_runner.v1
        slug and the expected top-level keys."""
        with tempfile.TemporaryDirectory() as ws:
            # No .rs files — runner should still emit a valid summary.
            summary = self.mod.scan_workspace(Path(ws))
        self.assertEqual(summary["scanner_schema"], "auditooor.rust_detector_runner.v1")
        self.assertEqual(summary["scanner"], "rust-detector-runner.py")
        self.assertEqual(summary["rust_files_scanned"], 0)
        self.assertEqual(summary["totals"]["hits"], 0)
        # Both patterns must appear in the patterns dict even on an empty scan.
        self.assertIn(
            "rust.frost.dkg.self_identifier_in_round_packages",
            summary["patterns"],
        )
        self.assertIn(
            "rust.frost.aggregate.under_threshold_signature_shares",
            summary["patterns"],
        )

    def test_main_writes_outputs_and_returns_zero(self):
        with tempfile.TemporaryDirectory() as ws:
            shutil.copy(
                RUST_FIXTURES / "positive"
                / "dkg_self_identifier_in_round_packages.rs",
                Path(ws) / "fixture.rs",
            )
            rc = self.mod.main(["--workspace", ws])
            self.assertEqual(rc, 0)
            main_out = Path(ws) / ".auditooor" / "rust_findings.json"
            alias_out = Path(ws) / ".auditooor" / "SCAN_RUST_SUMMARY.json"
            self.assertTrue(main_out.exists())
            self.assertTrue(alias_out.exists())
            data = json.loads(main_out.read_text())
            self.assertEqual(data["scanner_schema"], "auditooor.rust_detector_runner.v1")
            pid = "rust.frost.dkg.self_identifier_in_round_packages"
            self.assertGreaterEqual(data["patterns"][pid]["hit_count"], 1)

    # ------------------------------------------------------------------
    # V3 workflow-gap fix: scanners/rust/SCAN_RUST_SUMMARY.{json,md}
    # must be written by the standalone runner so intake-baseline's
    # _has_rust_scan_artifact gate is satisfied after ``make scan-rust``.
    # ------------------------------------------------------------------

    def test_standalone_writes_scanners_rust_summary_json(self):
        """Runner must write scanners/rust/SCAN_RUST_SUMMARY.json (intake gate path)."""
        with tempfile.TemporaryDirectory() as ws:
            rc = self.mod.main(["--workspace", ws])
            self.assertEqual(rc, 0)
            summary_json = Path(ws) / "scanners" / "rust" / "SCAN_RUST_SUMMARY.json"
            self.assertTrue(
                summary_json.exists(),
                f"scanners/rust/SCAN_RUST_SUMMARY.json missing — intake-baseline gate will fail",
            )
            data = json.loads(summary_json.read_text())
            # Must carry the schema slug so downstream parsers can identify it.
            self.assertEqual(data["scanner_schema"], "auditooor.rust_detector_runner.v1")

    def test_standalone_writes_scanners_rust_summary_md(self):
        """Runner must write scanners/rust/SCAN_RUST_SUMMARY.md (intake gate primary path)."""
        with tempfile.TemporaryDirectory() as ws:
            rc = self.mod.main(["--workspace", ws])
            self.assertEqual(rc, 0)
            summary_md = Path(ws) / "scanners" / "rust" / "SCAN_RUST_SUMMARY.md"
            self.assertTrue(
                summary_md.exists(),
                f"scanners/rust/SCAN_RUST_SUMMARY.md missing — intake-baseline gate will fail",
            )
            content = summary_md.read_text()
            # Must start with the expected heading.
            self.assertIn("# Rust Scan Summary", content)
            # Must mention Rust files scanned (even if 0).
            self.assertIn("Rust files scanned", content)

    def test_summary_md_fields_for_intake_gate(self):
        """Markdown summary must have required fields that intake-baseline reads."""
        with tempfile.TemporaryDirectory() as ws:
            # Add one positive fixture so hit count is non-zero.
            shutil.copy(
                RUST_FIXTURES / "positive"
                / "dkg_self_identifier_in_round_packages.rs",
                Path(ws) / "fixture.rs",
            )
            rc = self.mod.main(["--workspace", ws])
            self.assertEqual(rc, 0)
            summary_md = Path(ws) / "scanners" / "rust" / "SCAN_RUST_SUMMARY.md"
            content = summary_md.read_text()
            # Pattern table must list at least one pattern.
            self.assertIn("rust.frost.dkg.self_identifier_in_round_packages", content)
            self.assertIn("rust.frost.aggregate.under_threshold_signature_shares", content)

    def test_zero_hit_scan_exits_zero(self):
        """A clean workspace with no .rs files must exit rc=0 (0 hits is valid, not an error)."""
        with tempfile.TemporaryDirectory() as ws:
            # No .rs files — 0 hits expected.
            rc = self.mod.main(["--workspace", ws])
            self.assertEqual(
                rc, 0,
                "0-hit scan must exit 0; rc=2 on empty workspace is the reported field bug",
            )
            # Both gate artifacts must still be written.
            self.assertTrue((Path(ws) / "scanners" / "rust" / "SCAN_RUST_SUMMARY.json").exists())
            self.assertTrue((Path(ws) / "scanners" / "rust" / "SCAN_RUST_SUMMARY.md").exists())
            # .auditooor/rust_findings.json must also exist.
            self.assertTrue((Path(ws) / ".auditooor" / "rust_findings.json").exists())

    def test_missing_workspace_exits_nonzero(self):
        """Pointing at a non-existent workspace must exit non-zero (rc=2)."""
        rc = self.mod.main(["--workspace", "/nonexistent/path/that/does/not/exist"])
        self.assertNotEqual(rc, 0, "Missing workspace should exit non-zero")

    def test_no_args_exits_nonzero(self):
        """Running without --workspace must exit non-zero (genuine error, not 0-hit case)."""
        # Suppress the stderr error message in test output.
        import io
        import contextlib
        buf = io.StringIO()
        with contextlib.redirect_stderr(buf):
            rc = self.mod.main([])
        self.assertNotEqual(rc, 0, "Missing --workspace should exit non-zero")

    def test_both_artifact_dirs_written_together(self):
        """.auditooor/ and scanners/rust/ artifacts are both written in one runner call."""
        with tempfile.TemporaryDirectory() as ws:
            rc = self.mod.main(["--workspace", ws])
            self.assertEqual(rc, 0)
            ws_path = Path(ws)
            # .auditooor artifacts
            self.assertTrue((ws_path / ".auditooor" / "rust_findings.json").exists())
            self.assertTrue((ws_path / ".auditooor" / "SCAN_RUST_SUMMARY.json").exists())
            # scanners/rust artifacts (intake-baseline gate)
            self.assertTrue((ws_path / "scanners" / "rust" / "SCAN_RUST_SUMMARY.json").exists())
            self.assertTrue((ws_path / "scanners" / "rust" / "SCAN_RUST_SUMMARY.md").exists())
            # JSON content identity: both .json files must be identical.
            j1 = json.loads((ws_path / ".auditooor" / "SCAN_RUST_SUMMARY.json").read_text())
            j2 = json.loads((ws_path / "scanners" / "rust" / "SCAN_RUST_SUMMARY.json").read_text())
            self.assertEqual(j1, j2, "Both SCAN_RUST_SUMMARY.json files must have identical content")


class RustPanicFpSuppressionTests(unittest.TestCase):
    """Regression tests for the two residual RU1/R11 (rust panic-reach) FP
    classes the adversarial flagged (2026-07-10):

      (1) a `pub mod test_utils` / `impl .. for Mock<X>` scaffolding block is
          test context - a mock method (even one named like a prod fn, e.g.
          `read`) takes fixture inputs, not attacker ingress, so it must NOT
          fire; but a real prod `fn read` OUTSIDE a mock container STILL fires.

      (2) an ecrecover / signature-verify path whose recovery-id index/unwrap
          operand is bounded by a self-clamp (`% N` / `& MASK` / `.min(..)`) is
          NOT attacker-panic-reachable, so it must NOT fire; but the SAME path
          WITHOUT a self-clamp STILL fires.
    """

    @classmethod
    def setUpClass(cls):
        cls.mod = _load_runner()

    def _hits(self, src: str, path: str):
        """(#ru1, #ru2) hits for ``src`` treated as living at ``path``."""
        funcs = self.mod._extract_functions(src, Path(path))
        ru1 = self.mod._detect_untrusted_ingress_panic(funcs)
        ru2 = self.mod._detect_panic_reach_primitives(funcs)
        return len(ru1), len(ru2)

    # --- FP class 1: test_utils / mock context ------------------------------
    _MOCK_METHOD = (
        "    fn read(&mut self, buf: &mut [u8]) -> usize {\n"
        "        let first = buf[0];\n"
        "        Some(first).unwrap();\n"
        "        buf.len()\n"
        "    }\n"
    )

    def test_mock_in_test_utils_file_excluded(self):
        """A MockCompressor method in `.../src/test_utils.rs` must not fire
        (the file IS the `mod test_utils` body - the adversarial's case)."""
        src = ("impl Compressor for MockCompressor {\n"
               + self._MOCK_METHOD + "}\n")
        ru1, ru2 = self._hits(src, "crates/batcher/comp/src/test_utils.rs")
        self.assertEqual((ru1, ru2), (0, 0),
                         "MockCompressor in test_utils.rs must be suppressed")

    def test_mock_in_inline_test_utils_mod_excluded(self):
        """A mock method inside an inline `pub mod test_utils { .. }` in a prod
        file (lib.rs) must not fire."""
        src = ("pub mod test_utils {\n"
               "  impl Compressor for MockCompressor {\n"
               + self._MOCK_METHOD + "  }\n}\n")
        ru1, ru2 = self._hits(src, "crates/batcher/comp/src/lib.rs")
        self.assertEqual((ru1, ru2), (0, 0),
                         "mock inside `mod test_utils` must be suppressed")

    def test_mock_impl_block_excluded(self):
        """An `impl .. for MockCompressor` block (no wrapping mod, prod file)
        must not fire - the Self type name signals mock scaffolding."""
        src = ("impl Compressor for MockCompressor {\n"
               + self._MOCK_METHOD + "}\n")
        ru1, ru2 = self._hits(src, "src/lib.rs")
        self.assertEqual((ru1, ru2), (0, 0),
                         "impl for MockCompressor must be suppressed")

    def test_inline_mock_mod_excluded(self):
        """An inline `mod mock { .. }` module is test scaffolding."""
        src = "mod mock {\n    fn read(buf: &[u8]) -> u8 { buf[0] }\n}\n"
        ru1, ru2 = self._hits(src, "src/foo.rs")
        self.assertEqual((ru1, ru2), (0, 0),
                         "`mod mock` must be suppressed")

    def test_prod_read_in_non_mock_impl_still_fires(self):
        """PRECISION: a real prod `fn read` in a NON-mock impl (RealCodec) STILL
        fires - the suppression is container-based, never fn-name based."""
        src = ("impl Decoder for RealCodec {\n"
               "    fn read(&self, buf: &[u8]) -> u8 {\n"
               "        buf[0]\n"
               "    }\n}\n")
        ru1, _ = self._hits(src, "src/codec.rs")
        self.assertGreaterEqual(
            ru1, 1, "prod `fn read` in RealCodec must still fire (not a mock)")

    def test_prod_mock_named_generic_type_not_suppressed(self):
        """PRECISION: an `impl Trait for RealType` whose Self type is NOT `Mock*`
        must NOT be suppressed even if `Mock` appears elsewhere (generic arg)."""
        src = ("impl Handler<MockEvent> for RealServer {\n"
               "    fn on_message(&self, data: &[u8]) -> u8 {\n"
               "        data[0]\n"
               "    }\n}\n")
        ru1, _ = self._hits(src, "src/server.rs")
        self.assertGreaterEqual(
            ru1, 1,
            "impl for RealServer (Mock only a generic arg) must still fire")

    # --- FP class 2: ecrecover self-clamp -----------------------------------
    def test_ecrecover_self_clamp_modulo_suppressed(self):
        """A recovery-id derived from ingress bytes and self-clamped by `% 4`
        before a table-index / RecoveryId::from_u8().unwrap() must not fire."""
        src = (
            "pub fn ecrecover(sig: &[u8]) -> Address {\n"
            "    if sig.len() != 65 { return Address::zero(); }\n"
            "    let v = sig[64];\n"
            "    let rec_id = v % 4;\n"
            "    let recovery_id = RecoveryId::from_u8(rec_id).unwrap();\n"
            "    let pk = RECOVERY_TABLE[rec_id];\n"
            "    recover_pubkey(sig, recovery_id, pk)\n"
            "}\n"
        )
        ru1, ru2 = self._hits(src, "src/ecrecover.rs")
        self.assertEqual((ru1, ru2), (0, 0),
                         "self-clamped ecrecover recovery-id must be suppressed")

    def test_ecrecover_self_clamp_inline_mask_suppressed(self):
        """An inline `& 0x03` bitmask on the index operand is a self-clamp."""
        src = (
            "pub fn ecrecover(sig: &[u8], recid: u8) -> Address {\n"
            "    if sig.len() != 65 { return Address::zero(); }\n"
            "    let pk = RECOVERY_TABLE[recid & 0x03];\n"
            "    recover_pubkey(sig, recid, pk)\n"
            "}\n"
        )
        ru1, ru2 = self._hits(src, "src/ecrecover.rs")
        self.assertEqual((ru1, ru2), (0, 0),
                         "inline `& 0x03` mask in ecrecover must be suppressed")

    def test_ecrecover_without_clamp_still_fires(self):
        """PRECISION: the SAME ecrecover path with NO self-clamp on the
        recovery-id index STILL fires (the guard is a clamp, not the context)."""
        src = (
            "pub fn ecrecover(sig: &[u8]) -> Address {\n"
            "    if sig.len() != 65 { return Address::zero(); }\n"
            "    let v = sig[64];\n"
            "    let rec_id = v as usize;\n"
            "    let pk = RECOVERY_TABLE[rec_id];\n"
            "    recover_pubkey(sig, rec_id, pk)\n"
            "}\n"
        )
        _, ru2 = self._hits(src, "src/ecrecover.rs")
        self.assertGreaterEqual(
            ru2, 1, "unclamped recovery-id index in ecrecover must still fire")

    def test_modulo_outside_sigverify_still_fires(self):
        """PRECISION: a `% N` in a NON sig-verify fn is NOT credited as a bounds
        guard (a zero modulus can still panic) - the ingress sink STILL fires."""
        src = (
            "pub fn pick(input: &[u8], n: usize) -> u8 {\n"
            "    let idx = n % 8;\n"
            "    TABLE[idx] + input[0]\n"
            "}\n"
        )
        ru1, ru2 = self._hits(src, "src/pick.rs")
        self.assertGreaterEqual(
            ru1 + ru2, 1,
            "modulo outside a sig-verify path must not suppress the ingress sink")

    # --- genuine prod ingress unwrap STILL fires ----------------------------
    def test_genuine_prod_ingress_unwrap_still_fires(self):
        """A genuine prod decode fn whose ingress bytes reach an unguarded
        index + `.unwrap()` STILL fires under both detectors."""
        src = (
            "pub fn decode_header(input: &[u8]) -> Header {\n"
            "    let n = input[0] as usize;\n"
            "    let tag = input.get(1).unwrap();\n"
            "    Header { n, tag: *tag }\n"
            "}\n"
        )
        ru1, ru2 = self._hits(src, "src/decoder.rs")
        self.assertGreaterEqual(ru1, 1, "prod ingress index/unwrap must fire (RU1)")
        self.assertGreaterEqual(ru2, 1, "prod ingress index/unwrap must fire (R11)")

    # --- _is_test_path / _is_test_context unit assertions -------------------
    def test_is_test_path_basenames_and_dirs(self):
        p = self.mod._is_test_path
        # test-scaffolding helper files.
        self.assertTrue(p(Path("crates/x/src/test_utils.rs")))
        self.assertTrue(p(Path("src/test_helpers.rs")))
        self.assertTrue(p(Path("src/mocks.rs")))
        self.assertTrue(p(Path("src/mock.rs")))
        # test dirs.
        self.assertTrue(p(Path("crates/x/tests/it.rs")))
        self.assertTrue(p(Path("src/test_utils/helpers.rs")))
        # genuine prod files must NOT be test paths.
        self.assertFalse(p(Path("src/decoder.rs")))
        self.assertFalse(p(Path("src/reader.rs")))
        self.assertFalse(p(Path("crates/x/src/mock_data_provider.rs")))


class RustStrictCanonicalVerificationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mod = _load_runner()

    def _write_inventory(self, ws: Path, row: dict) -> None:
        aud = ws / ".auditooor"
        aud.mkdir(exist_ok=True)
        (aud / "inscope_units.jsonl").write_text(
            json.dumps(row) + "\n", encoding="utf-8"
        )

    def test_strict_requires_canonical_inventory(self):
        with tempfile.TemporaryDirectory() as ws:
            summary = self.mod.scan_workspace(Path(ws), strict=True)
            self.assertEqual(summary["strict_verification"]["verdict"], "fail")
            self.assertTrue(any("missing canonical" in e for e in summary["strict_verification"]["errors"]))

    def test_strict_no_hit_accounts_for_every_inventory_unit(self):
        with tempfile.TemporaryDirectory() as ws:
            root = Path(ws)
            source = root / "clean.rs"
            source.write_text("fn clean() {}\n", encoding="utf-8")
            self._write_inventory(root, {"file": "clean.rs", "unit_id": "rust-clean-1", "lang": "rust"})
            summary = self.mod.scan_workspace(root, strict=True)
            verification = summary["strict_verification"]
            self.assertEqual(verification["verdict"], "pass")
            self.assertEqual(verification["inventory"]["unit_count"], 1)
            self.assertEqual(verification["scanned_unit_count"], 1)
            self.assertEqual(verification["emitted_hit_count"], 0)

    def test_strict_hit_requires_exact_typed_local_disposition(self):
        with tempfile.TemporaryDirectory() as ws:
            root = Path(ws)
            fixture = RUST_FIXTURES / "positive" / "dkg_self_identifier_in_round_packages.rs"
            shutil.copy(fixture, root / "fixture.rs")
            self._write_inventory(root, {"file": "fixture.rs", "unit_id": "rust-fixture-1", "lang": "rust"})
            summary = self.mod.scan_workspace(root, strict=True)
            verification = summary["strict_verification"]
            self.assertEqual(verification["verdict"], "fail")
            hit = summary["patterns"]["rust.frost.dkg.self_identifier_in_round_packages"]["hits"][0]
            self.assertTrue(hit["stable_id"].startswith("rust-hit-"))
            self.assertEqual(verification["unresolved_hits"][0]["reason"], "no exact typed disposition")

            (root / ".auditooor" / self.mod.STRICT_DISPOSITION_FILENAME).write_text(
                json.dumps({
                    "schema": self.mod.STRICT_DISPOSITION_SCHEMA,
                    "hit_id": hit["stable_id"],
                    "pattern_id": hit["pattern_id"],
                    "unit_id": "rust-fixture-1",
                    "disposition_type": "refuted",
                    "source_evidence": [{"file": "fixture.rs", "line": 1}],
                }) + "\n",
                encoding="utf-8",
            )
            closed = self.mod.scan_workspace(root, strict=True)
            self.assertEqual(closed["strict_verification"]["verdict"], "pass")

    def test_strict_rejects_parser_error_even_with_no_hits(self):
        with tempfile.TemporaryDirectory() as ws:
            root = Path(ws)
            (root / "broken.rs").write_text(
                "fn broken() {\n", encoding="utf-8"
            )
            self._write_inventory(root, {"file": "broken.rs", "unit_id": "rust-broken-1", "lang": "rust"})
            summary = self.mod.scan_workspace(root, strict=True)
            self.assertEqual(summary["strict_verification"]["verdict"], "fail")
            self.assertTrue(any("parser error" in e for e in summary["strict_verification"]["errors"]))

    def test_strict_rejects_degraded_inventory_unit(self):
        with tempfile.TemporaryDirectory() as ws:
            root = Path(ws)
            (root / "degraded.rs").write_text("fn clean() {}\n", encoding="utf-8")
            self._write_inventory(root, {
                "file": "degraded.rs", "unit_id": "rust-degraded-1", "lang": "rust",
                "degraded": True,
            })
            summary = self.mod.scan_workspace(root, strict=True)
            self.assertEqual(summary["strict_verification"]["verdict"], "fail")
            self.assertTrue(any("degraded" in e for e in summary["strict_verification"]["errors"]))


if __name__ == "__main__":
    unittest.main()
