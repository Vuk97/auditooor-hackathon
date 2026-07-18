#!/usr/bin/env python3
"""F3 regression suite - kill vacuous-harness false-green (spec section F3).

Covers the four F3 edits:

  E3.1/E3.2 (function-coverage-completeness.py): under STRICT the default
    (no --mutation-verify) bar refuses to stamp real-attack on a sentinel-only
    harness body; it consults the shared tools/lib/harness_vacuity detector.
    A 1-view + 5-value-moving solidity fixture where the 5 value-moving fns only
    carry an assert(true) Halmos scaffold must classify all 5 hollow under STRICT.

  E3.3 (audit-honesty-check.py): the whole-ws hollow gate uses a PER LANGUAGE
    SUB-TREE value-moving floor under STRICT (corroborated_genuine[lang] >=
    value_moving_count[lang]) rather than the legacy n>=1 aggregate OR.

  E3.4 (typed backend-absent): a move workspace with no toolchain emits a TYPED
    move-mutation-runner-absent verdict (never a silent pass).

  harness_vacuity per-language: go-testify table (real conservation assert is
    non-vacuous; require.Equal(t,1,1) + t.Fatalf("todo") is vacuous);
    constant-foldable assertions; zk soundness-vacuity.

All fixtures are synthetic, stdlib-only, no toolchain, no network. Each test is a
genuine fail-before / pass-after guard: the "vacuous" assertions would FAIL if the
gate were a no-op, and the "non-vacuous" assertions would FAIL on a sentinel body.
"""
from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

_REPO = Path(__file__).resolve().parents[2]
_VAC_LIB = _REPO / "tools" / "lib" / "harness_vacuity.py"
_FCC_TOOL = _REPO / "tools" / "function-coverage-completeness.py"
_HONESTY_TOOL = _REPO / "tools" / "audit-honesty-check.py"


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, str(path))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _wj(p: Path, obj) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(obj), encoding="utf-8")


def _run_fcc(ws: Path, *, strict: bool) -> dict:
    env = dict(os.environ)
    env.pop("AUDITOOOR_FCC_MUTATION_VERIFY", None)
    if strict:
        env["AUDITOOOR_L37_STRICT"] = "1"
    else:
        env.pop("AUDITOOOR_L37_STRICT", None)
    cp = subprocess.run(
        [sys.executable, str(_FCC_TOOL), "--workspace", str(ws), "--json"],
        capture_output=True, text=True, env=env,
    )
    assert cp.stdout.strip(), f"no JSON (rc={cp.returncode}); stderr=\n{cp.stderr[:800]}"
    return json.loads(cp.stdout)


def _run_honesty(ws: Path, *, strict: bool, extra_env: dict | None = None) -> dict:
    env = dict(os.environ)
    if strict:
        env["AUDITOOOR_L37_STRICT"] = "1"
    else:
        env.pop("AUDITOOOR_L37_STRICT", None)
    if extra_env:
        env.update(extra_env)
    cp = subprocess.run(
        [sys.executable, str(_HONESTY_TOOL), "--workspace", str(ws), "--json"],
        capture_output=True, text=True, env=env,
    )
    assert cp.stdout.strip(), f"no JSON (rc={cp.returncode}); stderr=\n{cp.stderr[:800]}"
    return json.loads(cp.stdout)


# ---------------------------------------------------------------------------
# harness_vacuity per-language detector tests
# ---------------------------------------------------------------------------

class GoTestifyVacuityTest(unittest.TestCase):
    """The go testify table (THE cosmos-SDK assertion lib)."""

    def setUp(self):
        self.vac = _load(_VAC_LIB, "hv_f3_go")

    def test_real_testify_conservation_is_non_vacuous(self):
        body = (
            "func TestSendCoins(t *testing.T) {\n"
            "    balBefore := k.GetBalance(ctx, addr)\n"
            "    k.SendCoins(ctx, addr, to, amt)\n"
            "    require.Equal(t, balAfter, balBefore.Sub(amt))\n}\n"
        )
        # FAIL-BEFORE: a pure testify relational conservation assert was wrongly
        # rejected as sentinel-only before the testify regex was added.
        self.assertFalse(self.vac.is_sentinel_only_harness(body))

    def test_testify_equal_same_literal_plus_todo_fatal_is_vacuous(self):
        body = (
            "func TestStub(t *testing.T) {\n"
            "    require.Equal(t, 1, 1)\n"
            '    t.Fatalf("todo")\n}\n'
        )
        # FAIL-BEFORE: the unconditional t.Fatalf short-circuit wrongly accepted
        # this; require.Equal(t,1,1) is a tautology.
        self.assertTrue(self.vac.is_sentinel_only_harness(body))

    def test_require_true_literal_is_vacuous(self):
        self.assertTrue(self.vac.is_sentinel_only_harness(
            "func T(t *testing.T) { require.True(t, true) }"))

    def test_require_nil_literal_is_vacuous(self):
        self.assertTrue(self.vac.is_sentinel_only_harness(
            "func T(t *testing.T) { require.Nil(t, nil) }"))

    def test_unconditional_fatal_only_is_vacuous(self):
        # A bare t.Fatalf("unimplemented") with no relational if is a stub.
        self.assertTrue(self.vac.is_sentinel_only_harness(
            'func T(t *testing.T) { t.Fatalf("unimplemented") }'))

    def test_guarded_fatal_is_non_vacuous(self):
        body = (
            "func T(t *testing.T) {\n    out := f(1)\n"
            '    if out != 2 { t.Fatalf("bad: %v", out) }\n}\n'
        )
        self.assertFalse(self.vac.is_sentinel_only_harness(body))


class ConstantFoldVacuityTest(unittest.TestCase):
    """Offline constant-foldable assertion detector."""

    def setUp(self):
        self.vac = _load(_VAC_LIB, "hv_f3_cf")

    def test_require_literal_relation_is_vacuous(self):
        self.assertTrue(self.vac.is_sentinel_only_harness(
            "function check() public { require(1 > 0); }"))

    def test_assert_literal_neq_is_vacuous(self):
        self.assertTrue(self.vac.is_sentinel_only_harness(
            "function check() public { assert(2 != 3); }"))

    def test_move_addr_literal_neq_is_vacuous(self):
        # Move assert!(@0x1 != @0x0, E) - operands are address literals.
        self.assertTrue(self.vac.is_sentinel_only_harness(
            "#[test]\nfun t() { assert!(@0x1 != @0x0, 0); }"))

    def test_len_ge_zero_is_vacuous(self):
        self.assertTrue(self.vac.is_sentinel_only_harness(
            "def test_x():\n    assert len(items) >= 0\n"))

    def test_self_eq_is_vacuous(self):
        self.assertTrue(self.vac.is_sentinel_only_harness(
            "function check() public { assert(x == x); }"))

    def test_real_relation_with_variable_is_non_vacuous(self):
        self.assertFalse(self.vac.is_sentinel_only_harness(
            "function check() public { assert(balAfter == balBefore + amt); }"))


class ZkSoundnessVacuityTest(unittest.TestCase):
    """zk soundness-vacuity: happy-path-only circuit test is vacuous."""

    def setUp(self):
        self.vac = _load(_VAC_LIB, "hv_f3_zk")

    def test_happy_path_only_circuit_is_vacuous(self):
        body = (
            "fn test_circuit() {\n"
            "    let w = good_witness();\n"
            "    circuit.prove(w);\n"
            "    assert_eq!(verify_proof(w), true);\n}\n"
        )
        # FAIL-BEFORE: a real assert_eq! on a valid witness was credited; a
        # missing constraint is invisible without a negative witness.
        self.assertTrue(self.vac.is_sentinel_only_harness(body))

    def test_negative_witness_circuit_is_non_vacuous(self):
        body = (
            "fn test_circuit_soundness() {\n"
            "    let w = forged_witness();\n"
            "    should_fail!(circuit.verify(w));\n}\n"
        )
        self.assertFalse(self.vac.is_sentinel_only_harness(body))


# ---------------------------------------------------------------------------
# E3.1/E3.2 - fcc STRICT value-moving floor (solidity fixture)
# ---------------------------------------------------------------------------

def _mk_view_plus_value_moving_ws() -> Path:
    """1 trivial view fn + 5 value-moving fns; the 5 value-moving fns each only
    carry an assert(true) Halmos scaffold (sentinel)."""
    ws = Path(tempfile.mkdtemp(prefix="f3_floor_"))
    src = ws / "src"
    src.mkdir(parents=True, exist_ok=True)
    (src / "Vault.sol").write_text(
        "pragma solidity ^0.8.20;\n"
        "contract Vault {\n"
        "    mapping(address => uint256) public balances;\n"
        "    function totalView() external view returns (uint256) { return 1; }\n"
        "    function deposit(uint256 a) external { balances[msg.sender] += a; }\n"
        "    function withdraw(uint256 a) external { balances[msg.sender] -= a; }\n"
        "    function mintTo(address to, uint256 a) external { balances[to] += a; }\n"
        "    function burnFrom(address f, uint256 a) external { balances[f] -= a; }\n"
        "    function moveAll(address to) external { balances[to] += balances[msg.sender]; }\n"
        "}\n",
        encoding="utf-8",
    )
    # A per-function Halmos scaffold for each value-moving fn whose ENTIRE body
    # is assert(true) (sentinel). The harness names the fn via check_<name>.
    htdir = ws / "poc-tests" / "per_function_invariants"
    htdir.mkdir(parents=True, exist_ok=True)
    # An explicit "Function under test: Vault.<fn> at <file>:<line>" header
    # (matched by fcc _UNDER_TEST_RE) ties each harness to the named fn, so the
    # harness genuinely TARGETS it - the sentinel body must then drive a hollow
    # classification (a real E3.2 guard, not an untouched no-op).
    # 4 fns carry a literal assert(true) (caught by the LOCAL _VACUOUS_RES too);
    # `moveAll` carries a CONSTANT-FOLDABLE assert (assert(1 < 2)) which the local
    # _VACUOUS_RES does NOT catch but the shared harness_vacuity detector DOES -
    # proving the E3.2 shared-detector import is load-bearing.
    for fn in ("deposit", "withdraw", "mintTo", "burnFrom"):
        (htdir / f"Halmos_Vault_{fn}.sol").write_text(
            "pragma solidity ^0.8.13;\n"
            f"// Function under test: Vault.{fn} at src/Vault.sol:5\n"
            f"contract Halmos_Vault_{fn} {{\n"
            f"  function check_{fn}() public {{\n"
            "    assert(true);\n  }\n}\n",
            encoding="utf-8",
        )
    (htdir / "Halmos_Vault_moveAll.sol").write_text(
        "pragma solidity ^0.8.13;\n"
        "// Function under test: Vault.moveAll at src/Vault.sol:9\n"
        "contract Halmos_Vault_moveAll {\n"
        "  function check_moveAll() public {\n"
        "    assert(1 < 2);\n  }\n}\n",
        encoding="utf-8",
    )
    return ws


class FccStrictValueMovingFloorTest(unittest.TestCase):
    def setUp(self):
        self.ws = _mk_view_plus_value_moving_ws()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.ws, ignore_errors=True)

    def test_strict_classifies_sentinel_value_moving_fns_hollow(self):
        """Under STRICT, the 5 value-moving fns whose only harness is
        assert(true) must be classified hollow (E3.1/E3.2), so the gate does NOT
        pass-fully-covered."""
        res = _run_fcc(self.ws, strict=True)
        by_name = {f["name"]: f["classification"] for f in res["functions"]}
        for fn in ("deposit", "withdraw", "mintTo", "burnFrom", "moveAll"):
            self.assertIn(fn, by_name, by_name)
            self.assertNotEqual(
                by_name[fn], "real-attack",
                f"{fn} has only an assert(true) scaffold - must NOT be real-attack "
                f"under STRICT; got {by_name[fn]}",
            )
        self.assertNotEqual(res["verdict"], "pass-fully-covered", by_name)

    def test_shared_detector_catches_const_fold_both_bars(self):
        """The `moveAll` harness body is `assert(1 < 2)` - a CONSTANT-FOLDABLE
        tautology the LOCAL _VACUOUS_RES does NOT catch (it only matches
        assert(true)/require(true)). E3.2 runs the shared harness_vacuity detector
        on every harness body BEFORE any real-attack credit in BOTH bars, so this
        const-fold sentinel is classified hollow regardless of STRICT - proving
        the shared-detector import is load-bearing (without it `moveAll` would be
        credited real-attack)."""
        for strict in (False, True):
            res = _run_fcc(self.ws, strict=strict)
            by = {f["name"]: f["classification"] for f in res["functions"]}
            self.assertEqual(
                by["moveAll"], "hollow",
                f"const-fold assert(1<2) must be hollow (shared detector); "
                f"strict={strict}; got {by}",
            )


# ---------------------------------------------------------------------------
# E3.3 - audit-honesty-check per-language floor
# ---------------------------------------------------------------------------

def _mk_solidity_floor_ws(value_moving: int, corroborated: int) -> Path:
    """Solidity ws with `value_moving` value-moving fns and `corroborated`
    genuine per_function mutation kills. Engine artifacts so real_execution=True."""
    ws = Path(tempfile.mkdtemp(prefix="f3_honesty_"))
    a = ws / ".auditooor"
    a.mkdir(parents=True, exist_ok=True)
    src = ws / "src"
    src.mkdir(parents=True, exist_ok=True)
    (src / "Vault.sol").write_text(
        "pragma solidity ^0.8.0;\ncontract Vault {\n"
        "  mapping(address=>uint256) public bal;\n"
        "  function f(uint256 a) external { bal[msg.sender] += a; }\n}\n",
        encoding="utf-8",
    )
    _wj(a / "value_moving_functions.json", {
        "function_count": value_moving,
        "functions": [
            {"file": "src/Vault.sol", "function": f"fn_{i}", "language": "sol"}
            for i in range(value_moving)
        ],
    })
    per_fn = [
        {
            "function": f"fn_{i}", "language": "solidity",
            "mutation_verified": True, "oracle_verdict": "non-vacuous",
            "killed": True,
        }
        for i in range(corroborated)
    ]
    _wj(a / "mutation_verify_coverage.json", {
        "counts": {"per_function_verified": 0, "total": corroborated},
        "per_function": per_fn,
    })
    _wj(a / "halmos" / "artifact.json", {"status": "ok", "properties_checked": 5})
    _wj(a / "g15_hunt_coverage_gate_last_result.json", {
        "coverage_pct": 1.0, "covered": 10, "total": 10,
    })
    _wj(a / "depth_certificate.json", {
        "negative_space_ran": True, "sibling_diff_ran": True,
    })
    _wj(a / "coverage_report.json", {"covered": 10, "total": 10, "pct": 1.0})
    return ws


class HonestyPerLanguageFloorTest(unittest.TestCase):
    def tearDown(self):
        import shutil
        for ws in getattr(self, "_to_clean", []):
            shutil.rmtree(ws, ignore_errors=True)

    def _track(self, ws):
        self._to_clean = getattr(self, "_to_clean", [])
        self._to_clean.append(ws)
        return ws

    def test_strict_floor_fails_when_corroborated_below_value_moving(self):
        """1 view + 5 value-moving solidity fns, only 1 corroborated genuine kill
        -> per-fn floor (1 < 5) fails under STRICT."""
        ws = self._track(_mk_solidity_floor_ws(value_moving=5, corroborated=1))
        res = _run_honesty(ws, strict=True)
        self.assertIn(
            "fail-hollow-per-function-harnesses", res["fails"],
            f"corroborated(1) < value_moving(5) per language must FAIL under "
            f"STRICT; fails={res['fails']}",
        )

    def test_strict_floor_passes_when_corroborated_meets_value_moving(self):
        ws = self._track(_mk_solidity_floor_ws(value_moving=5, corroborated=5))
        res = _run_honesty(ws, strict=True)
        self.assertNotIn(
            "fail-hollow-per-function-harnesses", res["fails"],
            f"corroborated(5) >= value_moving(5) must clear the floor; "
            f"fails={res['fails']}",
        )

    def test_default_aggregate_passes_with_one_kill(self):
        """Without STRICT the legacy aggregate n>=1 behavior is preserved: 1
        genuine kill suppresses the fail even with 5 value-moving fns (no
        regression to the default path)."""
        ws = self._track(_mk_solidity_floor_ws(value_moving=5, corroborated=1))
        res = _run_honesty(ws, strict=False)
        self.assertNotIn(
            "fail-hollow-per-function-harnesses", res["fails"],
            f"default (non-STRICT) aggregate path must accept 1 kill; "
            f"fails={res['fails']}",
        )

    def test_mixed_language_floor_not_masked_by_other_language(self):
        """Mixed sol+circom: solidity floor met (2 genuine kills for 2 sol fns)
        but circom floor unmet (0 kills for 1 circom fn) -> STRICT FAILS (the
        cross-cutting rule that a solidity half must not mask a zk half).
        circom has no built-in runner, so without a waiver it is recorded as a
        typed circom-mutation-runner-absent verdict AND the floor still fails."""
        ws = self._track(_mk_solidity_floor_ws(value_moving=2, corroborated=2))
        a = ws / ".auditooor"
        vmf = json.loads((a / "value_moving_functions.json").read_text())
        vmf["functions"].append(
            {"file": "circuits/main.circom", "function": "Main", "language": "circom"})
        vmf["function_count"] = len(vmf["functions"])
        _wj(a / "value_moving_functions.json", vmf)
        res = _run_honesty(ws, strict=True)
        self.assertIn(
            "fail-hollow-per-function-harnesses", res["fails"],
            f"circom floor (0 < 1) must not be masked by a met solidity floor; "
            f"fails={res['fails']}",
        )
        verdicts = {v["lang"]: v for v in res.get("mutation_runner_absent", [])}
        self.assertIn("circom", verdicts, res.get("mutation_runner_absent"))
        self.assertEqual(
            verdicts["circom"]["verdict"], "circom-mutation-runner-absent")
        self.assertFalse(verdicts["circom"]["waived"])


# ---------------------------------------------------------------------------
# E3.4 - typed move-mutation-runner-absent (never silent pass)
# ---------------------------------------------------------------------------

def _mk_move_runner_absent_ws() -> Path:
    """Move ws: 1 value-moving move fn, NO mutation toolchain / no corroborated
    kills. Under STRICT this must emit a TYPED move-mutation-runner-absent
    verdict (with a waiver path), never a silent pass."""
    ws = Path(tempfile.mkdtemp(prefix="f3_move_"))
    a = ws / ".auditooor"
    a.mkdir(parents=True, exist_ok=True)
    src = ws / "sources"
    src.mkdir(parents=True, exist_ok=True)
    (src / "coin.move").write_text(
        "module x::coin {\n"
        "    public entry fun transfer(from: &signer, to: address, amt: u64) {\n"
        "        coin::transfer(from, to, amt);\n    }\n}\n",
        encoding="utf-8",
    )
    _wj(a / "value_moving_functions.json", {
        "function_count": 1,
        "functions": [
            {"file": "sources/coin.move", "function": "transfer", "language": "move"}
        ],
    })
    _wj(a / "mutation_verify_coverage.json", {
        "counts": {"per_function_verified": 0, "total": 0},
        "per_function": [],
    })
    # Engine artifacts so real_execution=True (the ws is otherwise pre-empted by
    # fail-hollow-engines, which short-circuits PATH 2). _detect_lang buckets a
    # move-only ws under the solidity arm, so a halmos ok-status artifact makes
    # real_execution True and lets the per-language floor + E3.4 typed verdict run.
    _wj(a / "halmos" / "artifact.json", {"status": "ok", "properties_checked": 5})
    _wj(a / "g15_hunt_coverage_gate_last_result.json", {
        "coverage_pct": 1.0, "covered": 10, "total": 10,
    })
    _wj(a / "depth_certificate.json", {
        "negative_space_ran": True, "sibling_diff_ran": True,
    })
    _wj(a / "coverage_report.json", {"covered": 10, "total": 10, "pct": 1.0})
    return ws


class MoveRunnerAbsentTypedTest(unittest.TestCase):
    def setUp(self):
        self.ws = _mk_move_runner_absent_ws()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.ws, ignore_errors=True)

    def test_move_runner_absent_is_typed_not_silent(self):
        """STRICT: move ws with no toolchain emits a TYPED
        move-mutation-runner-absent verdict (never silent pass) and the floor
        fails (unwaived)."""
        res = _run_honesty(self.ws, strict=True)
        verdicts = {v["lang"]: v for v in res.get("mutation_runner_absent", [])}
        self.assertIn("move", verdicts, res.get("mutation_runner_absent"))
        self.assertEqual(verdicts["move"]["verdict"], "move-mutation-runner-absent")
        self.assertFalse(verdicts["move"]["waived"])
        self.assertEqual(verdicts["move"]["waiver_env"], "AUDITOOOR_MVC_RUNNER_MOVE")
        # never a silent pass: the floor still fails when unwaived.
        self.assertIn("fail-hollow-per-function-harnesses", res["fails"], res["fails"])

    def test_move_runner_waiver_clears_the_brick(self):
        """When the move waiver env is set (a language-appropriate substitute
        ran), the typed verdict is recorded as waived and the floor does NOT
        brick on the no-runner language alone."""
        res = _run_honesty(
            self.ws, strict=True,
            extra_env={"AUDITOOOR_MVC_RUNNER_MOVE": "aptos move test"},
        )
        verdicts = {v["lang"]: v for v in res.get("mutation_runner_absent", [])}
        self.assertIn("move", verdicts, res.get("mutation_runner_absent"))
        self.assertTrue(verdicts["move"]["waived"])
        self.assertNotIn(
            "fail-hollow-per-function-harnesses", res["fails"],
            f"a waived move-runner-absent must not brick the only-move ws; "
            f"fails={res['fails']}",
        )


if __name__ == "__main__":
    unittest.main()
