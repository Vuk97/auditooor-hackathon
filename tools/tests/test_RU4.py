#!/usr/bin/env python3
"""RU4 - profile_wrap_silent advisory axis on rust-numeric-overflow-underflow-scan.

The base scanner is Cargo-blind: it treats every bare-arith site the same. RU4
adds a Cargo pre-pass that resolves the EFFECTIVE release overflow-checks for
the crate owning each hit and, when release is wrap-silent (overflow-checks
omitted/false), tags the bare-arith hit ``profile_wrap_silent = true``.

Non-vacuity: the two workspace fixtures differ ONLY by the root
``[profile.release] overflow-checks`` line. Any mutation that ignores the
resolved profile (e.g. always-tag, never-tag, or honoring the member manifest
instead of the workspace root) flips at least one assertion below.

Cases
-----
1. wrap-silent ws (release omits overflow-checks) -> the usize_sub hit is tagged.
2. panic ws (release overflow-checks = true) -> NOT tagged (FP-guard / benign).
3. axis OFF by default -> no tags even on the wrap-silent ws (advisory-first).
4. checked_add_unwrap hit is never tagged (not wrap-eligible).
5. dedup boundary: axis on/off yields an identical (file,line,pattern) row set.
6. hypotheses are verdict=needs-fuzz, auto_credit=false, covered_by base.
7. resolver unit: defaults, explicit, inherits chain, bench<-release,
   workspace-root-over-member.
"""
from __future__ import annotations

import importlib.util
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCANNER = ROOT / "tools" / "rust-numeric-overflow-underflow-scan.py"
FIX = Path(__file__).resolve().parent / "fixtures" / "RU4"
# The scanner excludes any path containing "/tests/"; the checked-in fixtures
# live under tools/tests/. Each test stages the fixture into a tmp dir first.
_TMP: list[Path] = []


def _stage(name: str) -> Path:
    dst = Path(tempfile.mkdtemp(prefix=f"ru4_{name}_")) / name
    shutil.copytree(FIX / name, dst)
    _TMP.append(dst.parent)
    return dst


def tearDownModule():  # noqa: N802 (unittest hook name)
    for p in _TMP:
        shutil.rmtree(p, ignore_errors=True)


def _load_module():
    spec = importlib.util.spec_from_file_location("ru4_scan", SCANNER)
    mod = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    sys.modules["ru4_scan"] = mod  # py3.14 dataclass needs the module registered
    spec.loader.exec_module(mod)
    return mod


def _run(ws: Path, axis: bool, extra: list[str] | None = None) -> dict:
    cmd = [sys.executable, str(SCANNER), "--workspace", str(ws), "--print-json"]
    if axis:
        cmd.append("--profile-wrap-silent")
    if extra:
        cmd.extend(extra)
    proc = subprocess.run(cmd, capture_output=True, text=True)
    assert proc.returncode in (0, 1), proc.stdout + proc.stderr
    return json.loads(proc.stdout)


def _tagged(payload: dict) -> list[dict]:
    return [r for r in payload["rows"] if r["profile_wrap_silent"]]


class ProfileWrapSilentAxis(unittest.TestCase):
    def setUp(self):
        self.wrap = _stage("wrap_silent_ws")
        self.panic = _stage("panic_ws")

    def test_wrap_silent_ws_tags_bare_arith(self):
        pl = _run(self.wrap, axis=True)
        subs = [r for r in pl["rows"] if r["pattern_id"] == "usize_sub_without_empty_guard"]
        self.assertTrue(subs, "expected the len()-1 hit to be present")
        self.assertTrue(subs[0]["profile_wrap_silent"], "wrap-silent release must tag it")
        self.assertIn("wrap_silent=True", subs[0]["profile_axis_evidence"])
        self.assertGreaterEqual(pl["profile_wrap_silent_count"], 1)

    def test_panic_ws_not_tagged(self):
        # FP-guard: overflow-checks=true release must NOT be tagged wrap-silent.
        pl = _run(self.panic, axis=True)
        subs = [r for r in pl["rows"] if r["pattern_id"] == "usize_sub_without_empty_guard"]
        self.assertTrue(subs, "expected the len()-1 hit to be present")
        self.assertFalse(subs[0]["profile_wrap_silent"], "panic release must stay untagged")
        self.assertEqual(pl["profile_wrap_silent_count"], 0)

    def test_axis_off_by_default(self):
        # Advisory-first: without the flag/env, nothing is tagged even on wrap-silent.
        pl = _run(self.wrap, axis=False)
        self.assertFalse(pl["profile_axis_enabled"])
        self.assertEqual(pl["profile_wrap_silent_count"], 0)
        self.assertTrue(all(not r["profile_wrap_silent"] for r in pl["rows"]))

    def test_checked_add_unwrap_never_tagged(self):
        pl = _run(self.wrap, axis=True)
        cau = [r for r in pl["rows"] if r["pattern_id"] == "checked_add_unwrap"]
        self.assertTrue(cau, "expected the checked_add().unwrap() hit")
        self.assertTrue(all(not r["profile_wrap_silent"] for r in cau))

    def test_dedup_rowset_identical_on_off(self):
        off = _run(self.wrap, axis=False)
        on = _run(self.wrap, axis=True)

        def ident(pl):
            return sorted((r["file"], r["line"], r["pattern_id"]) for r in pl["rows"])

        self.assertEqual(ident(off), ident(on), "axis must only tag, never add/remove rows")

    def test_hypotheses_needs_fuzz_no_auto_credit(self):
        mod = _load_module()
        rows = mod.run(self.wrap, [], profile_axis=True)
        hyps = mod.build_hypotheses(rows, self.wrap)
        self.assertTrue(hyps, "wrap-silent ws should yield >=1 hypothesis")
        for h in hyps:
            self.assertEqual(h["verdict"], "needs-fuzz")
            self.assertFalse(h["auto_credit"])
            self.assertEqual(h["covered_by"], "rust-numeric-overflow-underflow-scan")
            self.assertEqual(h["axis"], "profile_wrap_silent")

    def test_resolver_semantics(self):
        mod = _load_module()
        r = mod._resolve_overflow_checks
        # Cargo built-in defaults.
        self.assertFalse(r({}, "release"))  # release default = wrap-silent
        self.assertTrue(r({}, "dev"))       # dev default = panic
        self.assertFalse(r({}, "bench"))    # bench <- release
        self.assertTrue(r({}, "test"))      # test <- dev
        # Explicit override.
        self.assertTrue(r({"release": {"overflow-checks": True}}, "release"))
        # inherits chain: custom -> release (wrap-silent) unless overridden.
        self.assertFalse(r({"wasm": {"inherits": "release"}}, "wasm"))
        self.assertTrue(r({"wasm": {"inherits": "dev"}}, "wasm"))
        # bench inherits an explicit wrap-silent release.
        self.assertFalse(r({"release": {"opt-level": 3}}, "bench"))

    def test_workspace_root_over_member(self):
        # The member crates/foo/Cargo.toml sets overflow-checks=true, which Cargo
        # IGNORES. Resolution must use the wrap-silent workspace root.
        mod = _load_module()
        res = mod.CargoProfileResolver(enabled=True)
        member_file = self.wrap / "crates" / "foo" / "src" / "lib.rs"
        wrap_silent, evidence = res.wrap_silent_for_file(member_file)
        self.assertTrue(wrap_silent, f"root must win over member: {evidence}")


if __name__ == "__main__":
    unittest.main()
