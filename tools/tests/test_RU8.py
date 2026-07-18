#!/usr/bin/env python3
"""Tests for ``tools/rust-eager-alloc-nomax-screen.py`` (RU8).

RU8 is a GENERAL enforcement-completeness screen, not a bug shape: for every
eager-allocation primitive whose size is a decode/wire-boundary length, it asks
"does a MAX-cap enforcement point dominate the reservation?" and emits an
advisory (verdict=needs-fuzz) row ONLY when no dominating cap exists.

Coverage
--------
1. test_planted_positive_fires              - unbounded decode-length Vec::with_capacity fires.
2. test_guarded_negative_silent             - same shape + `if n > MAX { return }` stays silent.
3. test_clamp_rebind_negative_silent        - `let n = n.min(cap)` clamp before alloc stays silent.
4. test_materialized_len_excluded           - `Vec::with_capacity(v.len())` (materialized) never fires.
5. test_const_len_excluded                  - `vec![0; BYTES_LEN]` (compile-time const) never fires.
6. test_test_code_excluded                  - patterns in `#[cfg(test)] mod` are ignored.
7. test_vec_macro_and_reserve_primitives    - the primitive family (vec![_; n], .reserve(n)) all fire.
8. test_advisory_first_default_exit_zero    - default run NEVER fail-closes (exit 0 with rows).
9. test_strict_opt_in_exit_one              - `--strict` exits 1 when a row is present.
10. test_row_schema_advisory_fields         - row carries verdict=needs-fuzz, auto_credit=False, advisory=True.
11. test_non_vacuous_neutralize_source      - neutralizing the boundary-source predicate silences the positive.
12. test_non_vacuous_neutralize_cap         - neutralizing the cap predicate (always-capped) silences the positive.
13. test_real_fleet_mutation_verify         - NEAR reed_solomon guarded=silent, guard-removed temp copy=fires.
"""
from __future__ import annotations

import importlib.util
import json
import os
import re
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCANNER = ROOT / "tools" / "rust-eager-alloc-nomax-screen.py"
NEAR_REED_SOLOMON = Path(
    os.path.expanduser("~/audits/near/src/core/primitives/src/reed_solomon.rs")
)


def _load_module():
    """Load the hyphenated tool module in-process for predicate-level tests."""
    spec = importlib.util.spec_from_file_location("ru8_mod", SCANNER)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["ru8_mod"] = mod  # register BEFORE exec (py3.14 dataclass resolution)
    spec.loader.exec_module(mod)
    return mod


def _run_cli(workspace: Path, extra: list[str] | None = None) -> tuple[dict, int]:
    cmd = [sys.executable, str(SCANNER), "--workspace", str(workspace), "--print-json"]
    if extra:
        cmd.extend(extra)
    proc = subprocess.run(cmd, capture_output=True, text=True)
    assert proc.returncode in (0, 1), proc.stdout + proc.stderr
    return json.loads(proc.stdout), proc.returncode


def _write(ws: Path, body: str, relpath: str = "src/decoder.rs") -> Path:
    p = ws / relpath
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(textwrap.dedent(body), encoding="utf-8")
    return p


# Planted POSITIVE: a decoder that reads a length prefix and eagerly reserves,
# with NO cap. This is the general shape RU8 must fire on.
POSITIVE_BODY = """
    pub fn decode_frame(reader: &mut impl std::io::Read) -> std::io::Result<Vec<u8>> {
        let mut len_buf = [0u8; 4];
        reader.read_exact(&mut len_buf)?;
        let n = u32::from_be_bytes(len_buf);
        let mut out: Vec<u8> = Vec::with_capacity(n as usize);
        reader.read_exact(&mut out)?;
        Ok(out)
    }
"""

# Guarded NEGATIVE: identical, but with a dominating MAX cap.
GUARDED_BODY = """
    const MAX_FRAME: u32 = 16 * 1024 * 1024;
    pub fn decode_frame(reader: &mut impl std::io::Read) -> std::io::Result<Vec<u8>> {
        let mut len_buf = [0u8; 4];
        reader.read_exact(&mut len_buf)?;
        let n = u32::from_be_bytes(len_buf);
        if n > MAX_FRAME {
            return Err(std::io::Error::other("frame too large"));
        }
        let mut out: Vec<u8> = Vec::with_capacity(n as usize);
        reader.read_exact(&mut out)?;
        Ok(out)
    }
"""


class TestRU8(unittest.TestCase):
    def test_planted_positive_fires(self):
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            _write(ws, POSITIVE_BODY)
            payload, _ = _run_cli(ws)
            self.assertGreaterEqual(payload["row_count"], 1)
            self.assertTrue(
                any(r["primitive"] == "vec_with_capacity" for r in payload["rows"])
            )

    def test_guarded_negative_silent(self):
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            _write(ws, GUARDED_BODY)
            payload, _ = _run_cli(ws)
            self.assertEqual(payload["row_count"], 0, payload["rows"])

    def test_clamp_rebind_negative_silent(self):
        body = """
        pub fn decode_frame(n: usize, avail: usize, src: &[u8]) -> Vec<u8> {
            let _ = src;
            let n = n.min(avail);
            let mut out: Vec<u8> = Vec::with_capacity(n);
            out
        }
        """
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            _write(ws, body)
            payload, _ = _run_cli(ws)
            self.assertEqual(payload["row_count"], 0, payload["rows"])

    def test_materialized_len_excluded(self):
        body = """
        pub fn deserialize_items(src: &[u8], items: &Vec<u8>) -> Vec<u8> {
            let _ = src;
            let mut out = Vec::with_capacity(items.len());
            out.extend_from_slice(items);
            out
        }
        """
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            _write(ws, body)
            payload, _ = _run_cli(ws)
            self.assertEqual(payload["row_count"], 0, payload["rows"])

    def test_const_len_excluded(self):
        body = """
        const BYTES_LEN: usize = 32;
        pub fn decode(src: &[u8]) -> Vec<u8> {
            let _ = src;
            vec![0u8; BYTES_LEN]
        }
        """
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            _write(ws, body)
            payload, _ = _run_cli(ws)
            self.assertEqual(payload["row_count"], 0, payload["rows"])

    def test_test_code_excluded(self):
        body = POSITIVE_BODY + """
        #[cfg(test)]
        mod tests {
            pub fn decode_frame_evil(n: u32) -> Vec<u8> {
                Vec::with_capacity(n as usize)
            }
        }
        """
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            _write(ws, body)
            payload, _ = _run_cli(ws)
            # Only the non-test positive fires; the cfg(test) one is stripped.
            self.assertTrue(all("evil" not in r["function"] for r in payload["rows"]))

    def test_vec_macro_and_reserve_primitives(self):
        body = """
        pub fn decode_a(size: usize, src: &[u8]) -> Vec<u8> {
            let _ = src;
            vec![0u8; size]
        }
        pub fn decode_b(count: usize, buf: &[u8]) {
            let _ = buf;
            let mut v: Vec<u8> = Vec::new();
            v.reserve(count);
        }
        """
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            _write(ws, body)
            payload, _ = _run_cli(ws)
            prims = {r["primitive"] for r in payload["rows"]}
            self.assertIn("vec_macro_fill", prims)
            self.assertIn("reserve", prims)

    def test_advisory_first_default_exit_zero(self):
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            _write(ws, POSITIVE_BODY)
            _payload, rc = _run_cli(ws)  # no --strict
            self.assertEqual(rc, 0)  # advisory-first: never fail-closes by default

    def test_strict_opt_in_exit_one(self):
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            _write(ws, POSITIVE_BODY)
            _payload, rc = _run_cli(ws, ["--strict"])
            self.assertEqual(rc, 1)

    def test_row_schema_advisory_fields(self):
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            _write(ws, POSITIVE_BODY)
            payload, _ = _run_cli(ws)
            self.assertEqual(payload["verdict_all"], "needs-fuzz")
            self.assertTrue(payload["advisory_first"])
            row = payload["rows"][0]
            for field in ("file", "line", "primitive", "function", "length_expr",
                          "length_token", "boundary_source", "invariant",
                          "verdict", "auto_credit", "advisory"):
                self.assertIn(field, row)
            self.assertEqual(row["verdict"], "needs-fuzz")
            self.assertFalse(row["auto_credit"])
            self.assertTrue(row["advisory"])

    # -- Fleet FP regressions (fixed) -------------------------------------

    def test_bytes_field_name_not_decode_ctx(self):
        # Fleet FP (base-azul execution.rs): a `with_capacity(capacity)` ctor
        # whose body only *mentions* the letters "bytes" inside an unrelated
        # field name (`cumulative_da_bytes_used`) must NOT be treated as a
        # decode context, so `capacity` is not a wire boundary -> silent.
        body = """
        impl ExecutionInfo {
            pub fn with_capacity(capacity: usize) -> Self {
                Self {
                    executed_transactions: Vec::with_capacity(capacity),
                    receipts: Vec::with_capacity(capacity),
                    cumulative_da_bytes_used: 0,
                    cumulative_uncompressed_bytes: 0,
                }
            }
        }
        """
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            _write(ws, body)
            payload, _ = _run_cli(ws)
            self.assertEqual(payload["row_count"], 0, payload["rows"])

    def test_bare_bytes_word_still_decode_ctx(self):
        # Guard against over-correction: a REAL whole-word `bytes` local in a
        # decode still makes the context a decode context (positive fires).
        mod = _load_module()
        self.assertTrue(mod.is_decode_context("read_frame", "let bytes = src;"))
        self.assertTrue(mod.is_decode_context("read_frame", "fn f(buf: &mut Vec<u8>)"))
        self.assertTrue(mod.is_decode_context("read_frame", "fn f(src: &[u8])"))
        # ...but the letters inside a field name do NOT (the FP shape).
        self.assertFalse(
            mod.is_decode_context("with_capacity", "cumulative_da_bytes_used: 0,")
        )

    def test_with_capacity_ctor_caller_supplied_silent(self):
        # Even if the body trips a real decode signal, a `*_with_capacity`
        # constructor's `capacity` param is caller-supplied, not wire-derived.
        body = """
        impl Buffer {
            pub fn with_capacity(capacity: usize) -> Self {
                let _tmp: &[u8] = &[];
                Self { data: Vec::with_capacity(capacity) }
            }
        }
        """
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            _write(ws, body)
            payload, _ = _run_cli(ws)
            self.assertEqual(payload["row_count"], 0, payload["rows"])

    def test_cross_fn_field_cap_silent(self):
        # Fleet FP (base-azul batch/transactions.rs + payload.rs): the decoded
        # field `self.tx_count` is range-checked in a DIFFERENT impl method than
        # the one that reserves; the cross-fn cap must silence the alloc.
        body = """
        impl SpanBatch {
            pub fn decode_bits(&mut self, r: &mut &[u8]) -> Result<(), Error> {
                if self.tx_count > Self::MAX_ELEMENTS {
                    return Err(Error::TooLarge);
                }
                let _ = SpanBatchBits::decode(r, self.tx_count as usize)?;
                Ok(())
            }
            pub fn decode_sigs(&mut self, r: &mut &[u8]) -> Result<(), Error> {
                let mut sigs = Vec::with_capacity(self.tx_count as usize);
                sigs.clear();
                Ok(())
            }
        }
        """
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            _write(ws, body)
            payload, _ = _run_cli(ws)
            self.assertEqual(payload["row_count"], 0, payload["rows"])

    def test_cross_fn_field_uncapped_still_fires(self):
        # Non-vacuity of the cross-fn cap: WITHOUT the `self.tx_count > MAX` guard
        # anywhere in the file, the decode_field reservation must still fire.
        body = """
        impl SpanBatch {
            pub fn decode_count(&mut self, r: &mut &[u8]) -> Result<(), Error> {
                let (count, _rest) = read_varint(r)?;
                self.tx_count = count;
                Ok(())
            }
            pub fn decode_sigs(&mut self, r: &mut &[u8]) -> Result<(), Error> {
                let mut sigs = Vec::with_capacity(self.tx_count as usize);
                sigs.clear();
                Ok(())
            }
        }
        """
        with tempfile.TemporaryDirectory() as d:
            ws = Path(d)
            _write(ws, body)
            payload, _ = _run_cli(ws)
            self.assertGreaterEqual(payload["row_count"], 1)
            self.assertTrue(
                any(r["boundary_source"] == "decode_field" for r in payload["rows"])
            )

    def test_has_cross_fn_field_cap_unit(self):
        mod = _load_module()
        capped = "if self.tx_count > Self::MAX_ELEMENTS { return Err(e); }"
        self.assertTrue(mod.has_cross_fn_field_cap("self.tx_count", capped))
        self.assertTrue(
            mod.has_cross_fn_field_cap("self.tx_count", "if self.tx_count >= 1024 { err }")
        )
        # A non-cap comparison (against 0 / another field) does NOT bound it.
        self.assertFalse(
            mod.has_cross_fn_field_cap("self.tx_count", "if self.tx_count > other { }")
        )
        self.assertFalse(mod.has_cross_fn_field_cap("self.tx_count", "self.tx_count as usize"))

    def test_new_test_path_tokens_excluded(self):
        # Fleet FP (near): test-support / dev-tooling crates are not audited
        # runtime and must be excluded by path.
        for rel in (
            "src/runtime/near-test-contracts/contract-for-fuzzing-rs/src/lib.rs",
            "src/runtime/runtime-params-estimator/src/action_costs.rs",
            "src/tools/state-viewer/src/congestion_control.rs",
        ):
            with tempfile.TemporaryDirectory() as d:
                ws = Path(d)
                _write(ws, POSITIVE_BODY, relpath=rel)
                payload, _ = _run_cli(ws)
                self.assertEqual(payload["row_count"], 0, f"{rel}: {payload['rows']}")

    # -- Non-vacuity: neutralizing either half of the core predicate must
    #    make the planted positive disappear. ------------------------------

    def test_non_vacuous_neutralize_source(self):
        mod = _load_module()
        rel = "src/decoder.rs"
        text = textwrap.dedent(POSITIVE_BODY)
        self.assertGreaterEqual(len(mod.scan_text(text, rel)), 1)  # baseline fires
        orig = mod.classify_boundary_source
        try:
            # Neutralize predicate half 1: nothing is a decode-boundary length.
            mod.classify_boundary_source = lambda *a, **k: (None, "")
            self.assertEqual(mod.scan_text(text, rel), [])  # positive silenced
        finally:
            mod.classify_boundary_source = orig
        self.assertGreaterEqual(len(mod.scan_text(text, rel)), 1)  # restored

    def test_non_vacuous_neutralize_cap(self):
        mod = _load_module()
        rel = "src/decoder.rs"
        text = textwrap.dedent(POSITIVE_BODY)
        self.assertGreaterEqual(len(mod.scan_text(text, rel)), 1)  # baseline fires
        orig = mod.has_dominating_cap
        try:
            # Neutralize predicate half 2: pretend every site is already capped.
            mod.has_dominating_cap = lambda *a, **k: (True, "neutralized")
            self.assertEqual(mod.scan_text(text, rel), [])  # positive silenced
        finally:
            mod.has_dominating_cap = orig
        self.assertGreaterEqual(len(mod.scan_text(text, rel)), 1)  # restored

    @unittest.skipUnless(
        NEAR_REED_SOLOMON.is_file(), "NEAR fleet snapshot absent"
    )
    def test_real_fleet_mutation_verify(self):
        mod = _load_module()
        original = NEAR_REED_SOLOMON.read_text(encoding="utf-8")

        # Guarded original: SILENT (the `if encoded_length > MAX_ENCODED_LENGTH`
        # guard dominates the Vec::with_capacity(encoded_length)).
        rows_guarded = mod.scan_text(original, "reed_solomon.rs")
        self.assertEqual(rows_guarded, [], f"expected silent on guarded source, got {rows_guarded}")

        # Mutant (temp copy, guard weakened): must FIRE. Never mutate the ws file.
        mutant = re.sub(
            r"if encoded_length > MAX_ENCODED_LENGTH \{\s*"
            r"return Err\(Error::other\(\"encoded length is too large\"\)\);\s*\}",
            "// guard removed by mutation-verify",
            original,
        )
        self.assertNotEqual(mutant, original, "mutation regex failed to apply")
        rows_mutant = mod.scan_text(mutant, "reed_solomon.rs")
        self.assertGreaterEqual(len(rows_mutant), 1, "expected fire when guard removed")
        self.assertTrue(
            any(r.length_token == "encoded_length" for r in rows_mutant)
        )


if __name__ == "__main__":
    unittest.main()
