#!/usr/bin/env python3
"""E1 decode-differential (round-trip malleability) axis - non-vacuous tests.

Pins the E1 mode added to tools/gen-state-root-parity.sh
(--emit-decode-differential): for any Rust type exposing BOTH a hand-written
decode (fn read/deserialize/decode/from_bytes) AND encode
(fn write/serialize/encode/to_bytes) on one impl, whose decode does NOT re-check
a canonical form, it emits ONE round-trip hypothesis:
    serialize(read(b)) == b   (canonical oracle)
Every row is verdict='needs-fuzz' (NO-AUTO-CREDIT); advisory, OFF by default.

Mutation-verify anchor: monero-oxide transaction.rs:511 Transaction::read (no
canonical guard). CLEAN (guard injected) must NOT fire; MUTANT (real, no guard)
MUST fire.

Matrix (pure-Rust fixtures, no external toolchain):
  - mutant.rs         (read+write, no guard)      -> 1 needs-fuzz row.
  - clean.rs          (read+write, canon guard)   -> 0 rows (suppressed).
  - fp_single_dir.rs  (decode-only)               -> 0 rows (FP guard).
  - fp_derive.rs      (derive-only symmetric)     -> 0 rows (FP guard).

Off-by-default: no --emit-decode-differential and no env -> the E1 jsonl is
never written.

Non-vacuity (test_mutate_canonical_predicate): neutralise the CANON_RE guard
regex in a temp copy of the script; the CLEAN case must then collapse 0 -> 1,
proving the canonical-guard predicate is load-bearing.
"""
from __future__ import annotations

import json
import os
import pathlib
import re
import shutil
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "tools" / "gen-state-root-parity.sh"
FX = ROOT / "tools" / "tests" / "fixtures" / "E1"


def _run(script: pathlib.Path, fixture: str | None, emit: bool = True,
         env_on: bool = False):
    """Copy fixture into a fresh tmp ws (outside tools/tests so it is not
    pruned), run the E1 detector, return emitted rows + whether jsonl exists."""
    with tempfile.TemporaryDirectory() as td:
        ws = pathlib.Path(td)
        if fixture:
            shutil.copy(FX / fixture, ws / fixture)
        out = ws / "e1.jsonl"
        cmd = ["bash", str(script), "--workspace", str(ws),
               "--decode-scan-root", str(ws), "--out", str(out)]
        if emit:
            cmd.append("--emit-decode-differential")
        env = dict(os.environ)
        if env_on:
            env["GEN_DECODE_DIFFERENTIAL"] = "1"
        else:
            env.pop("GEN_DECODE_DIFFERENTIAL", None)
        subprocess.run(cmd, check=True, capture_output=True, env=env)
        if not out.exists():
            return [], False
        rows = [json.loads(ln) for ln in out.read_text().splitlines() if ln.strip()]
        return rows, True


class E1Matrix(unittest.TestCase):

    def test_mutant_fires_one_needs_fuzz(self):
        rows, wrote = _run(SCRIPT, "mutant.rs")
        self.assertTrue(wrote)
        self.assertEqual(len(rows), 1, "unguarded round-trip pair must fire once")
        r = rows[0]
        self.assertEqual(r["id"], "E1")
        self.assertEqual(r["type"], "Widget")
        self.assertEqual(r["decode_fn"], "read")
        self.assertEqual(r["encode_fn"], "serialize")
        self.assertEqual(r["verdict"], "needs-fuzz")
        self.assertFalse(r["auto_credit"])
        self.assertIsNone(r["covered_by"])
        self.assertEqual(r["attack_class"], "serialization-malleability")
        self.assertIn("execution-state-root-parity", r["dedup_axis"])

    def test_clean_canonical_guard_suppressed(self):
        rows, _ = _run(SCRIPT, "clean.rs")
        self.assertEqual(rows, [], "a canonical round-trip guard must suppress")

    def test_fp_single_direction_suppressed(self):
        rows, _ = _run(SCRIPT, "fp_single_dir.rs")
        self.assertEqual(rows, [], "decode-only (no encode) must not fire")

    def test_fp_derive_only_suppressed(self):
        rows, _ = _run(SCRIPT, "fp_derive.rs")
        self.assertEqual(rows, [], "derive-only symmetric codec must not fire")

    def test_off_by_default_no_jsonl(self):
        # No --emit-decode-differential, no env -> E1 branch must not run.
        rows, wrote = _run(SCRIPT, "mutant.rs", emit=False, env_on=False)
        self.assertFalse(wrote, "off-by-default must not write the E1 jsonl")

    def test_env_enables_axis(self):
        rows, wrote = _run(SCRIPT, "mutant.rs", emit=False, env_on=True)
        self.assertTrue(wrote, "GEN_DECODE_DIFFERENTIAL=1 must enable the axis")
        self.assertEqual(len(rows), 1)

    def test_mutate_canonical_predicate(self):
        """Non-vacuity: break the CANON_RE guard regex -> CLEAN must now fire.
        Proves the canonical-guard predicate is load-bearing (not vacuous)."""
        src = SCRIPT.read_text()
        self.assertIn("CANON_RE  = re.compile(", src)
        broken = re.sub(
            r"CANON_RE  = re\.compile\(r'[^']*'",
            "CANON_RE  = re.compile(r'__never_match_canon__'",
            src, count=1)
        self.assertNotEqual(broken, src, "predicate line must have been mutated")
        with tempfile.TemporaryDirectory() as td:
            mut_script = pathlib.Path(td) / "mut.sh"
            mut_script.write_text(broken)
            rows, _ = _run(mut_script, "clean.rs")
        self.assertEqual(len(rows), 1,
                         "with the canonical guard predicate broken, the CLEAN "
                         "case must collapse 0 -> 1")


if __name__ == "__main__":
    unittest.main()
