#!/usr/bin/env python3
"""GEN-EL3 non-canonical serialization acceptance screen - regression + non-
vacuity tests.

Pins tools/noncanonical-serialization-screen.py: a decode
(proto/amino/json.Unmarshal, borsh/serde try_from_slice, abi.decode) followed by
a canonicality-sensitive sink (hash / map-key / dedup-set / equality / merkle-
leaf / replay-nonce) keyed on the RAW input bytes with NO re-encode/canonical
check. Rows carry verdict='needs-fuzz' (advisory, NO-AUTO-CREDIT).

Matrix (pure fixtures, no external toolchain):
  - fire.go   : proto.Unmarshal->sha256(raw) store-key + dedup[string(bz)] -> 2.
  - benign.go : re-Marshal-and-hash (form a) + key-on-decoded-field (form b) -> 0.
  - fire.rs   : try_from_slice->sha256(raw) + HashSet.contains(raw) dedup    -> 2.
  - benign.rs : msg.try_to_vec() canonical re-encode                          -> 0.
  - fire.sol  : abi.decode->keccak256(data) dedup map key                     -> 1.

Off-by-default: default mode exits 0 even with fired rows (advisory-first);
--strict / env elevates.

Non-vacuity (test_mutate_canonical_guard_predicate): neutralise the tool's
canonical-check suppressor; the BENIGN Go case must then collapse 0 -> >=1,
proving the re-encode/key-on-decoded guard is load-bearing (not a vacuous
always-fire).
"""
from __future__ import annotations

import importlib.util
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "noncanonical-serialization-screen.py"
FX = ROOT / "tools" / "tests" / "fixtures" / "gen_el3"


def _load_tool():
    spec = importlib.util.spec_from_file_location("ncs_screen_el3", TOOL)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _scan(tool, fixture: str):
    p = FX / fixture
    return tool.scan_file(p, fixture)


class GenEl3MatrixTest(unittest.TestCase):
    def setUp(self):
        self.tool = _load_tool()

    def test_fire_go_two_rows(self):
        rows = _scan(self.tool, "fire.go")
        self.assertEqual(len(rows), 2, [r["sink"] for r in rows])
        sinks = sorted(r["sink"] for r in rows)
        self.assertEqual(sinks, ["dedup", "hash"])
        for r in rows:
            self.assertEqual(r["capability"], "GEN_EL3")
            self.assertEqual(r["schema"],
                             "auditooor.noncanonical_serialization_hypotheses.v1")
            self.assertEqual(r["verdict"], "needs-fuzz")
            self.assertTrue(r["advisory"])
            self.assertFalse(r["auto_credit"])
            self.assertTrue(r["keyed_on_raw_bytes"])
            self.assertTrue(r["missing_canonical_check"])
            self.assertEqual(r["lang"], "go")
            self.assertIn(".Unmarshal", r["decode_call"])

    def test_benign_go_zero(self):
        # form (a) re-Marshal-and-compare + form (b) key-on-decoded-field.
        rows = _scan(self.tool, "benign.go")
        self.assertEqual(len(rows), 0, [r["excerpt"] for r in rows])

    def test_fire_rust_two_rows(self):
        rows = _scan(self.tool, "fire.rs")
        self.assertEqual(len(rows), 2, [r["sink"] for r in rows])
        self.assertEqual(sorted(r["sink"] for r in rows), ["dedup", "hash"])
        self.assertTrue(all(r["lang"] == "rust" for r in rows))

    def test_benign_rust_zero(self):
        # msg.try_to_vec() re-encode of the DECODED value == canonical guard.
        rows = _scan(self.tool, "benign.rs")
        self.assertEqual(len(rows), 0, [r["excerpt"] for r in rows])

    def test_fire_sol_one_row(self):
        rows = _scan(self.tool, "fire.sol")
        self.assertEqual(len(rows), 1, [r["sink"] for r in rows])
        r = rows[0]
        self.assertEqual(r["lang"], "solidity")
        self.assertEqual(r["decode_call"], "abi.decode")
        self.assertEqual(r["subject"], "data")

    def test_raw_copy_not_mistaken_for_canonical_reencode(self):
        # regression: `raw.to_vec()` (a copy of the raw input) must NOT be read
        # as a canonical re-encode of the decoded value -> dedup still fires.
        rows = _scan(self.tool, "fire.rs")
        self.assertIn("dedup", [r["sink"] for r in rows])


class GenEl3AdvisoryExitTest(unittest.TestCase):
    """Advisory-first: default exit 0 even with fired rows; --strict elevates."""

    def _run_ws(self, extra_env=None, strict=False):
        with tempfile.TemporaryDirectory() as td:
            ws = pathlib.Path(td)
            src = ws / "src"
            src.mkdir()
            (src / "fire.go").write_text((FX / "fire.go").read_text())
            argv = [sys.executable, str(TOOL), "--workspace", str(ws)]
            if strict:
                argv.append("--strict")
            env = dict(os.environ)
            env.pop("AUDITOOOR_NONCANONICAL_SERIALIZATION_STRICT", None)
            if extra_env:
                env.update(extra_env)
            proc = subprocess.run(argv, capture_output=True, text=True, env=env)
            side = ws / ".auditooor" / \
                "noncanonical_serialization_hypotheses.jsonl"
            rows = []
            if side.exists():
                rows = [json.loads(l) for l in side.read_text().splitlines()
                        if l.strip()]
            return proc.returncode, rows, proc.stdout

    def test_default_advisory_exit0_with_sidecar(self):
        rc, rows, out = self._run_ws()
        self.assertEqual(rc, 0, out)
        self.assertEqual(len(rows), 2, out)

    def test_strict_flag_elevates(self):
        rc, rows, out = self._run_ws(strict=True)
        self.assertEqual(rc, 1, out)
        self.assertEqual(len(rows), 2)

    def test_strict_env_elevates(self):
        rc, _rows, out = self._run_ws(
            extra_env={"AUDITOOOR_NONCANONICAL_SERIALIZATION_STRICT": "1"})
        self.assertEqual(rc, 1, out)


class GenEl3NonVacuityTest(unittest.TestCase):
    """Neutralise the canonical-check suppressor; the benign Go case must then
    collapse 0 -> >=1, proving the guard predicate is load-bearing."""

    def test_mutate_canonical_guard_predicate(self):
        # guarded.go DOES key sha256(raw) on the raw bytes, but is saved SOLELY
        # by the re-Marshal+bytes.Equal canonical-form reject (form (a)).
        tool = _load_tool()
        baseline = _scan(tool, "guarded.go")
        self.assertEqual(len(baseline), 0, "guarded must be silent at baseline")
        # weaken: force _has_canonical_check to always report NO canonical guard.
        tool._has_canonical_check = lambda body, decoded, lang: False
        weakened = tool.scan_file(FX / "guarded.go", "guarded.go")
        self.assertGreaterEqual(
            len(weakened), 1,
            "neutralising the canonical-check suppressor must make the guarded "
            "keyed-on-raw case newly fire - the guard is load-bearing")


if __name__ == "__main__":
    unittest.main()
