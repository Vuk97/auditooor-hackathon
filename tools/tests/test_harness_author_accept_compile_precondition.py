#!/usr/bin/env python3
# <!-- r36-rebuttal: lane enf-laneC G1 (id25) registered in commit message -->
"""G1 (id25): harness-source-COMPILES precondition + identifier-splice hardening.

Two coupled hardenings, both regression-guarded here:

  (a) tools/harness-author-accept.py grows an ADVISORY-FIRST, default-OFF
      harness-source-COMPILES precondition (check 6). With the env unset the gate
      output is BYTE-IDENTICAL to the pre-existing five-check gate (never a
      retro-red). With AUDITOOOR_HARNESS_COMPILE_STRICT=1 (or --compile-strict) a
      non-compiling Solidity harness is REJECTED - the miss that let the NUVA
      CrossChainManager_FuzzProps.sol (corrupted into `Euint256(0)ecutorArgs`)
      through author-accept even though its medusa run errored rc=6 engine-error.
      never-false-red: a missing forge toolchain / cross-language harness / no
      foundry root is an advisory NOTE, not a FAIL.

  (b) tools/evm-engine-harness-author.py hardens the placeholder identifier splice
      so a valid identifier like `ExecutorArgs` can NEVER be corrupted into
      `Euint256(0)ecutorArgs` (full-identifier, single-pass substitution).

The compile tests that need a real `forge build` are SKIPPED (not failed) when
forge is not resolvable, so the suite is offline-safe.
"""
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

_TOOLS = Path(__file__).resolve().parent.parent


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, str(path))
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod  # py3.14: set BEFORE exec_module
    spec.loader.exec_module(mod)
    return mod


HAA = _load(_TOOLS / "harness-author-accept.py", "harness_author_accept_compile_t")
EH = _load(_TOOLS / "evm-engine-harness-author.py", "eh_splice_t")
FBR = _load(_TOOLS / "forge-build-readiness-check.py", "fbr_compile_t")


def _forge_available() -> bool:
    try:
        return bool(FBR._forge_bin())
    except Exception:  # noqa: BLE001
        return False


# A trivially-compiling Solidity harness (no external deps / remappings needed).
COMPILING_HARNESS = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract GoodHarness {
    uint256 internal x;
    function poke(uint256 v) external { x = v; }
    function invariant_x() external view returns (bool) { return x == x; }
}
"""

# A harness with a hard compile error (undeclared identifier / bad syntax) that
# `forge build` MUST reject - the shape of the NUVA corrupted-splice harness.
NONCOMPILING_HARNESS = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract BadHarness {
    // Corrupted identifier splice: `Euint256(0)ecutorArgs` is not a valid type,
    // exactly the shape that broke CrossChainManager_FuzzProps.sol:71.
    function boom() external {
        Euint256(0)ecutorArgs memory a;
        a;
    }
}
"""


def _mk_foundry_ws(harness_body: str, *, harness_name: str = "H.sol"):
    """Build a minimal self-contained foundry workspace with the harness in test/.
    Returns (ws_path, harness_path). Caller is responsible for cleanup."""
    ws = Path(tempfile.mkdtemp())
    (ws / "foundry.toml").write_text(
        "[profile.default]\nsrc = 'src'\ntest = 'test'\nout = 'out'\nlibs = ['lib']\n",
        encoding="utf-8")
    (ws / "src").mkdir()
    (ws / "test").mkdir()
    hp = ws / "test" / harness_name
    hp.write_text(harness_body, encoding="utf-8")
    return ws, hp


class SpliceHardening(unittest.TestCase):
    """(b) The placeholder splice can never corrupt a valid identifier."""

    MAP = {"x": "uint256(0)", "y": "uint256(0)", "actor": "address(this)"}

    def test_executor_args_survives_intact(self):
        # THE regression: `ExecutorArgs` must survive the transform byte-for-byte;
        # the historical corruption `Euint256(0)ecutorArgs` must never appear.
        for arg in ("ExecutorArgs", "ExecutorArgs(x + 0)", "ExecutorArgs(x)"):
            out = EH._splice_placeholders(arg, self.MAP)
            self.assertNotIn("Euint256(0)ecutorArgs", out,
                             msg=f"NUVA corruption reproduced on {arg!r} -> {out!r}")
            self.assertIn("ExecutorArgs", out,
                          msg=f"ExecutorArgs was mangled: {arg!r} -> {out!r}")
        # the standalone `x` inside the arg IS still substituted where valid
        self.assertEqual(EH._splice_placeholders("ExecutorArgs(x)", self.MAP),
                         "ExecutorArgs(uint256(0))")

    def test_target_call_stmt_end_to_end_preserves_executor_args(self):
        # Drive the full statement builder with a struct-typed param named after
        # the NUVA type. A non-synthesizable struct param -> the call is OMITTED
        # (defense in depth) and the type name is never corrupted anywhere.
        fn = EH.FuncSig(name="execute", params="ExecutorArgs args",
                        visibility="external", mutability="nonpayable",
                        is_payable=False, returns="")
        surf = EH.ContractSurface(name="CrossChainManager", kind="contract",
                                  bases=[], functions=[fn])
        stmt = EH._target_call_stmt(surf, "atomicity", x="uint256(0)",
                                    y="uint256(0)")
        self.assertNotIn("Euint256(0)ecutorArgs", stmt)

    def test_identifier_fragments_never_touched(self):
        # placeholder LETTERS embedded in longer identifiers must be inert.
        for arg, expect in (
            ("proxyType(x + 0)", "proxyType(uint256(0) + 0)"),   # x in proxy
            ("factory_thing", "factory_thing"),                   # no whole token
            ("my_x_var", "my_x_var"),                             # x between _
            ("actorFoo", "actorFoo"),                             # actor prefix
            ("fooActor", "fooActor"),                             # actor suffix
        ):
            self.assertEqual(EH._splice_placeholders(arg, self.MAP), expect)

    def test_single_pass_no_double_substitution(self):
        # If a value substituted for `x` itself contains a bare `actor` token, the
        # single left-to-right pass must NOT re-scan and corrupt it (the old
        # sequential re.sub form could). `actor` here maps to `victimActor` (a
        # whole different identifier); the value chosen for x embeds the token
        # `actor` and must survive.
        mp = {"x": "wrap(actor)", "actor": "REPLACED"}
        out = EH._splice_placeholders("f(x)", mp)
        self.assertEqual(out, "f(wrap(actor))")

    def test_output_identical_to_wordboundary_form_on_real_args(self):
        # Pure-hardening proof: for every real _solidity_arg_for_type output the new
        # splice equals the historical `\bx\b`/`\by\b`/`\bactor\b` sequential form.
        import re as _re

        def _old(a):
            a = _re.sub(r"\bx\b", self.MAP["x"], a)
            a = _re.sub(r"\by\b", self.MAP["y"], a)
            a = _re.sub(r"\bactor\b", self.MAP["actor"], a)
            return a

        for t in ("bool", "bytes32", "string", "uint256", "int256", "address",
                  "uint8", "bytes", "bool[]", "uint256[]"):
            a = EH._solidity_arg_for_type(t, 0)
            self.assertEqual(EH._splice_placeholders(a, self.MAP), _old(a),
                             msg=f"splice drift on synthesized arg for {t!r}")


class CompilePreconditionAdvisoryOff(unittest.TestCase):
    """(a) Default-OFF: env unset -> result dict is byte-identical (no compile key)."""

    def setUp(self):
        self.ws = Path(tempfile.mkdtemp())
        self.hp = self.ws / "H.sol"
        self.hp.write_text(COMPILING_HARNESS, encoding="utf-8")
        # a minimal in-scope manifest + sidecar so we can call accept() and inspect
        # the checks dict; the oracle is stubbed non-vacuous.
        self._prev = os.environ.pop("AUDITOOOR_HARNESS_COMPILE_STRICT", None)
        # The gate now defaults ON under AUDITOOOR_L37_STRICT; clear it so the
        # unset-env cases below observe the bare non-strict (advisory) default.
        self._prev_l37 = os.environ.pop("AUDITOOOR_L37_STRICT", None)

    def tearDown(self):
        if self._prev is not None:
            os.environ["AUDITOOOR_HARNESS_COMPILE_STRICT"] = self._prev
        else:
            os.environ.pop("AUDITOOOR_HARNESS_COMPILE_STRICT", None)
        if self._prev_l37 is not None:
            os.environ["AUDITOOOR_L37_STRICT"] = self._prev_l37
        else:
            os.environ.pop("AUDITOOOR_L37_STRICT", None)
        shutil.rmtree(self.ws, ignore_errors=True)

    def _stub_oracle(self):
        return {"verdict": "non-vacuous", "behavior_changing_kill_count": 1,
                "witness_reached": True, "invariants": [], "reason": "stub"}

    def test_env_unset_no_l37_no_compile_check_key(self):
        # Case 4 (non-strict-advisory): both envs unset -> byte-identical (no key).
        os.environ.pop("AUDITOOOR_HARNESS_COMPILE_STRICT", None)
        os.environ.pop("AUDITOOOR_L37_STRICT", None)
        res = HAA.accept(harness=self.hp, ws=self.ws, oracle_verdict=self._stub_oracle())
        self.assertNotIn("compile", res["checks"],
                         msg="non-strict-advisory must not emit a compile check (retro-red risk)")

    def test_default_under_l37_enabled(self):
        # Case 1 (default-under-L37): X_STRICT unset, L37_STRICT set -> ENFORCED.
        os.environ.pop("AUDITOOOR_HARNESS_COMPILE_STRICT", None)
        for l37 in ("1", "true", "yes"):
            os.environ["AUDITOOOR_L37_STRICT"] = l37
            self.assertTrue(HAA._compile_strict_enabled(),
                            msg=f"L37_STRICT={l37!r} (X unset) must enforce by default")

    def test_env_unset_non_strict_advisory(self):
        # Case 4: X unset AND L37 unset/falsey -> OFF (advisory).
        os.environ.pop("AUDITOOOR_HARNESS_COMPILE_STRICT", None)
        for l37 in ("", "0", "false", "no"):
            if l37 == "":
                os.environ.pop("AUDITOOOR_L37_STRICT", None)
            else:
                os.environ["AUDITOOOR_L37_STRICT"] = l37
            self.assertFalse(HAA._compile_strict_enabled(),
                             msg=f"X unset + L37={l37!r} must stay advisory")

    def test_explicit_opt_out_even_under_l37(self):
        # Case 2 (opt-out): explicit X_STRICT in {0,false,no,off} -> OFF even under L37.
        os.environ["AUDITOOOR_L37_STRICT"] = "1"
        for falsey in ("0", "false", "no", "off"):
            os.environ["AUDITOOOR_HARNESS_COMPILE_STRICT"] = falsey
            self.assertFalse(HAA._compile_strict_enabled(),
                             msg=f"explicit {falsey!r} must opt out even under L37")

    def test_env_truthy_enables(self):
        # Case 3 (explicit-on): any truthy explicit value enables (L37 irrelevant).
        os.environ.pop("AUDITOOOR_L37_STRICT", None)
        for truthy in ("1", "true", "yes", "on", "STRICT"):
            os.environ["AUDITOOOR_HARNESS_COMPILE_STRICT"] = truthy
            self.assertTrue(HAA._compile_strict_enabled(), msg=f"{truthy!r} should be ON")


class CompilePreconditionNeverFalseRed(unittest.TestCase):
    """(a) Strict-ON never turns a harness red on a non-build-break path."""

    def setUp(self):
        self._prev_l37 = os.environ.pop("AUDITOOOR_L37_STRICT", None)

    def tearDown(self):
        os.environ.pop("AUDITOOOR_HARNESS_COMPILE_STRICT", None)
        if self._prev_l37 is not None:
            os.environ["AUDITOOOR_L37_STRICT"] = self._prev_l37
        else:
            os.environ.pop("AUDITOOOR_L37_STRICT", None)

    def test_non_solidity_harness_is_advisory_note_not_fail(self):
        ws = Path(tempfile.mkdtemp())
        try:
            hp = ws / "harness.rs"
            hp.write_text("fn main() {}\n", encoding="utf-8")
            fails, notes = HAA._check_compiles(ws, hp)
            self.assertEqual(fails, [])
            self.assertTrue(any("non-solidity" in n for n in notes))
        finally:
            shutil.rmtree(ws, ignore_errors=True)

    def test_no_foundry_root_is_advisory_note_not_fail(self):
        ws = Path(tempfile.mkdtemp())
        try:
            hp = ws / "loose.sol"           # a bare .sol not inside any foundry tree
            hp.write_text(COMPILING_HARNESS, encoding="utf-8")
            fails, notes = HAA._check_compiles(ws, hp)
            self.assertEqual(fails, [])
            self.assertTrue(any("no-foundry-root" in n for n in notes))
        finally:
            shutil.rmtree(ws, ignore_errors=True)


@unittest.skipUnless(_forge_available(),
                     "forge not resolvable - compile-execution tests skipped (offline-safe)")
class CompilePreconditionLiveForge(unittest.TestCase):
    """(a) With a real forge: a COMPILING harness passes; a NON-compiling one fails
    under strict, and STILL passes with the env unset (advisory-first)."""

    def setUp(self):
        self._prev_l37 = os.environ.pop("AUDITOOOR_L37_STRICT", None)

    def tearDown(self):
        os.environ.pop("AUDITOOOR_HARNESS_COMPILE_STRICT", None)
        if self._prev_l37 is not None:
            os.environ["AUDITOOOR_L37_STRICT"] = self._prev_l37
        else:
            os.environ.pop("AUDITOOOR_L37_STRICT", None)

    def test_compiling_harness_passes_check(self):
        ws, hp = _mk_foundry_ws(COMPILING_HARNESS)
        try:
            fails, notes = HAA._check_compiles(ws, hp)
            self.assertEqual(fails, [], msg=f"unexpected compile fails; notes={notes}")
            self.assertTrue(any("compile-ok" in n for n in notes))
        finally:
            shutil.rmtree(ws, ignore_errors=True)

    def test_noncompiling_harness_fails_under_strict(self):
        ws, hp = _mk_foundry_ws(NONCOMPILING_HARNESS)
        try:
            fails, _ = HAA._check_compiles(ws, hp)
            self.assertTrue(fails, "a non-compiling harness must produce a FAIL")
            self.assertTrue(any("harness-source-does-not-compile" in f for f in fails))
        finally:
            shutil.rmtree(ws, ignore_errors=True)

    def test_noncompiling_harness_passes_when_env_unset(self):
        # advisory-first: with the env unset the SAME broken harness is NOT failed
        # by the compile check (it never runs). Prove via accept() with a stubbed
        # clean oracle + in-scope + sidecar so the only variable is the compile
        # check's presence.
        ws, hp = _mk_foundry_ws(NONCOMPILING_HARNESS)
        try:
            os.environ.pop("AUDITOOOR_HARNESS_COMPILE_STRICT", None)
            res = HAA.accept(
                harness=hp, ws=ws,
                oracle_verdict={"verdict": "non-vacuous",
                                "behavior_changing_kill_count": 1,
                                "witness_reached": True, "invariants": []})
            self.assertNotIn("compile", res["checks"])
            # and with strict ON the compile check now fires and FAILS
            os.environ["AUDITOOOR_HARNESS_COMPILE_STRICT"] = "1"
            res2 = HAA.accept(
                harness=hp, ws=ws,
                oracle_verdict={"verdict": "non-vacuous",
                                "behavior_changing_kill_count": 1,
                                "witness_reached": True, "invariants": []})
            self.assertIn("compile", res2["checks"])
            self.assertFalse(res2["checks"]["compile"]["pass"])
            self.assertTrue(any("harness-source-does-not-compile" in f
                                for f in res2["fails"]))
        finally:
            shutil.rmtree(ws, ignore_errors=True)


class OwningFoundryRoot(unittest.TestCase):
    """_owning_foundry_root picks the NEAREST first-party foundry.toml ancestor and
    skips vendored (lib/) trees."""

    def test_nearest_ancestor_root(self):
        ws = Path(tempfile.mkdtemp())
        try:
            (ws / "foundry.toml").write_text("[profile.default]\n", encoding="utf-8")
            hp = ws / "test" / "recon" / "H.sol"
            hp.parent.mkdir(parents=True)
            hp.write_text(COMPILING_HARNESS, encoding="utf-8")
            root = HAA._owning_foundry_root(FBR, hp)
            self.assertEqual(Path(root).resolve(), ws.resolve())
        finally:
            shutil.rmtree(ws, ignore_errors=True)

    def test_vendored_lib_root_skipped(self):
        ws = Path(tempfile.mkdtemp())
        try:
            # a foundry.toml inside a vendored lib/ must NOT be chosen; only a
            # first-party ancestor counts. Here the ONLY toml is under lib/ ->
            # None (advisory no-root).
            libtoml = ws / "lib" / "oz" / "foundry.toml"
            libtoml.parent.mkdir(parents=True)
            libtoml.write_text("[profile.default]\n", encoding="utf-8")
            hp = ws / "lib" / "oz" / "test" / "H.sol"
            hp.parent.mkdir(parents=True)
            hp.write_text(COMPILING_HARNESS, encoding="utf-8")
            root = HAA._owning_foundry_root(FBR, hp)
            self.assertIsNone(root)
        finally:
            shutil.rmtree(ws, ignore_errors=True)


if __name__ == "__main__":
    unittest.main(verbosity=2)
