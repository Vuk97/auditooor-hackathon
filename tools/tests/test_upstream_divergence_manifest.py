#!/usr/bin/env python3
"""Guard: upstream-divergence-manifest fails-closed when a fork is declared
but the deviation manifest is absent, empty, or stub-only.

Three canonical scenarios the gate specification requires:
  1. Fork declared + NO manifest (absent)          => FAIL
  2. Fork declared + populated manifest             => PASS
  3. Non-fork workspace                             => n/a-pass (pass-no-fork-detected)

Additional cases exercised:
  4. fork_target.json explicit declaration (no dep grep needed)
  5. package.json dep grep triggers detection
  6. Cargo.toml dep grep triggers detection
  7. go.mod grep triggers detection
  8. SCOPE.md prose grep triggers detection
  9. Manifest present but empty deviations list     => FAIL
 10. Manifest present but missing upstream field    => FAIL
 11. Manifest present but entries lack required fields => FAIL
 12. No in-scope source                             => pass-no-source (n/a)
"""
from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

_TOOLS = Path(__file__).resolve().parent.parent

_spec = importlib.util.spec_from_file_location(
    "udm", str(_TOOLS / "upstream-divergence-manifest.py"))
udm = importlib.util.module_from_spec(_spec)
sys.modules["udm"] = udm
_spec.loader.exec_module(udm)


# ---------------------------------------------------------------------------
# Test workspace factory helpers
# ---------------------------------------------------------------------------

def _ws() -> Path:
    return Path(tempfile.mkdtemp())


def _write_sol(ws: Path, rel: str = "src/Vault.sol") -> None:
    """Drop a minimal Solidity file so the workspace has in-scope source."""
    p = ws / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(
        "// SPDX-License-Identifier: MIT\n"
        "contract Vault { function deposit() external {} }\n",
        encoding="utf-8",
    )


def _write_manifest(ws: Path, *, upstream: str = "liquity",
                    deviations: list | None = None) -> Path:
    """Write a valid upstream_divergence.json manifest."""
    if deviations is None:
        deviations = [
            {"file": "src/Vault.sol", "kind": "modified",
             "summary": "added re-entrancy guard not present in upstream"},
        ]
    d = ws / ".auditooor"
    d.mkdir(parents=True, exist_ok=True)
    p = d / "upstream_divergence.json"
    p.write_text(json.dumps({
        "schema": "auditooor.upstream_divergence_manifest.v1",
        "upstream": upstream,
        "deviations": deviations,
    }), encoding="utf-8")
    return p


def _write_fork_target_json(ws: Path, upstream: str = "liquity") -> None:
    """Drop an explicit fork_target.json in the workspace root."""
    (ws / "fork_target.json").write_text(
        json.dumps({"upstream": upstream, "fork_of": upstream}),
        encoding="utf-8",
    )


def _write_package_json(ws: Path, dep: str = "liquity-lib") -> None:
    (ws / "package.json").write_text(
        json.dumps({
            "name": "my-protocol",
            "dependencies": {dep: "^1.0.0"},
        }),
        encoding="utf-8",
    )


def _write_cargo_toml(ws: Path, dep: str = "solady") -> None:
    (ws / "Cargo.toml").write_text(
        f'[dependencies]\n{dep} = "0.1"\n',
        encoding="utf-8",
    )


def _write_go_mod(ws: Path, pkg: str = "github.com/compound-finance/compound-protocol") -> None:
    (ws / "go.mod").write_text(
        f"module mymodule\n\nrequire (\n\t{pkg} v1.0.0\n)\n",
        encoding="utf-8",
    )


def _write_scope_md(ws: Path, text: str = "This protocol is a fork of Aave V3.") -> None:
    (ws / "SCOPE.md").write_text(text, encoding="utf-8")


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestUpstreamDivergenceManifest(unittest.TestCase):

    # -----------------------------------------------------------------------
    # Scenario 1: Fork declared + NO manifest => FAIL
    # -----------------------------------------------------------------------
    def test_fork_declared_no_manifest_FAILS(self):
        """The primary load-bearing case: fork detected, manifest absent => FAIL."""
        ws = _ws()
        _write_sol(ws)
        _write_fork_target_json(ws, "liquity")
        # Intentionally do NOT write a manifest.

        res = udm.evaluate(ws)
        self.assertEqual(
            res["verdict"],
            "fail-upstream-fork-divergence-manifest-missing",
            msg=f"Expected FAIL but got: {res['verdict']} | {res['reason']}",
        )
        self.assertTrue(res["fork_detected"])
        self.assertIn("liquity", res.get("upstream", "").lower())

    # -----------------------------------------------------------------------
    # Scenario 2: Fork declared + populated manifest => PASS
    # -----------------------------------------------------------------------
    def test_fork_declared_populated_manifest_PASSES(self):
        """Complementary case: fork detected + populated manifest => PASS."""
        ws = _ws()
        _write_sol(ws)
        _write_fork_target_json(ws, "liquity")
        _write_manifest(ws, upstream="liquity")

        res = udm.evaluate(ws)
        self.assertEqual(
            res["verdict"],
            "pass-fork-divergence-populated",
            msg=f"Expected PASS but got: {res['verdict']} | {res['reason']}",
        )
        self.assertTrue(res["fork_detected"])

    # -----------------------------------------------------------------------
    # No-fork attestation escape: detect tags a first-party canonical-source
    # target as a "fork", operator attests fork:false + reason => PASS.
    # -----------------------------------------------------------------------
    def test_no_fork_attestation_with_reason_PASSES(self):
        ws = _ws()
        _write_sol(ws)
        _write_fork_target_json(ws, "morpho")  # detect fires
        d = ws / ".auditooor"
        d.mkdir(parents=True, exist_ok=True)
        (d / "upstream_divergence.json").write_text(json.dumps({
            "schema": "auditooor.upstream_divergence_manifest.v1",
            "upstream": "morpho (first-party / canonical)",
            "fork": False,
            "reason": "morpho-org's own canonical repos, not a fork of any upstream",
            "deviations": [],
        }), encoding="utf-8")
        res = udm.evaluate(ws)
        self.assertEqual(res["verdict"], "pass-no-fork-attested",
                         msg=f"Got: {res['verdict']} | {res['reason']}")
        # attested target is NOT a real fork
        self.assertFalse(res["fork_detected"])

    def test_no_fork_attestation_missing_reason_FAILS(self):
        """fork:false without a reason must NOT pass (false-green-safe)."""
        ws = _ws()
        _write_sol(ws)
        _write_fork_target_json(ws, "morpho")
        d = ws / ".auditooor"
        d.mkdir(parents=True, exist_ok=True)
        (d / "upstream_divergence.json").write_text(json.dumps({
            "schema": "auditooor.upstream_divergence_manifest.v1",
            "upstream": "morpho",
            "fork": False,
            "deviations": [],
        }), encoding="utf-8")
        res = udm.evaluate(ws)
        self.assertEqual(res["verdict"],
                         "fail-upstream-fork-divergence-manifest-missing",
                         msg=f"Got: {res['verdict']} | {res['reason']}")

    def test_no_fork_attestation_does_not_passthrough_real_fork(self):
        """fork:true (real fork) with empty deviations still FAILS - the
        attestation escape must not green a genuine fork target."""
        ws = _ws()
        _write_sol(ws)
        _write_fork_target_json(ws, "liquity")
        d = ws / ".auditooor"
        d.mkdir(parents=True, exist_ok=True)
        (d / "upstream_divergence.json").write_text(json.dumps({
            "schema": "auditooor.upstream_divergence_manifest.v1",
            "upstream": "liquity",
            "fork": True,
            "reason": "this is a real fork",
            "deviations": [],
        }), encoding="utf-8")
        res = udm.evaluate(ws)
        self.assertEqual(res["verdict"],
                         "fail-upstream-fork-divergence-manifest-missing",
                         msg=f"Got: {res['verdict']} | {res['reason']}")

    # -----------------------------------------------------------------------
    # Scenario 3: Non-fork workspace => n/a-pass
    # -----------------------------------------------------------------------
    def test_non_fork_workspace_NApass(self):
        """No upstream fork markers => pass-no-fork-detected (n/a)."""
        ws = _ws()
        _write_sol(ws)
        # Plain package.json with no known upstream deps.
        (ws / "package.json").write_text(
            json.dumps({"name": "myapp", "dependencies": {"lodash": "^4.0.0"}}),
            encoding="utf-8",
        )

        res = udm.evaluate(ws)
        self.assertEqual(res["verdict"], "pass-no-fork-detected",
                         msg=f"Got: {res['verdict']} | {res['reason']}")
        self.assertFalse(res["fork_detected"])

    # -----------------------------------------------------------------------
    # Detection surface: fork_target.json in .auditooor/
    # -----------------------------------------------------------------------
    def test_auditooor_fork_target_json_detected(self):
        ws = _ws()
        _write_sol(ws)
        d = ws / ".auditooor"
        d.mkdir(parents=True, exist_ok=True)
        (d / "fork_target.json").write_text(
            json.dumps({"upstream": "compound"}), encoding="utf-8"
        )
        # No manifest -> FAIL
        res = udm.evaluate(ws)
        self.assertEqual(res["verdict"], "fail-upstream-fork-divergence-manifest-missing")
        self.assertTrue(res["fork_detected"])

    # -----------------------------------------------------------------------
    # Detection surface: package.json
    # -----------------------------------------------------------------------
    def test_package_json_dep_triggers_detection(self):
        ws = _ws()
        _write_sol(ws)
        _write_package_json(ws, dep="liquity-contracts")
        # No manifest -> FAIL
        res = udm.evaluate(ws)
        self.assertEqual(res["verdict"], "fail-upstream-fork-divergence-manifest-missing",
                         msg=f"Got: {res['verdict']}")
        self.assertTrue(res["fork_detected"])
        self.assertIn("package.json", res.get("detection_source", ""))

    # -----------------------------------------------------------------------
    # Detection surface: Cargo.toml
    # -----------------------------------------------------------------------
    def test_cargo_toml_dep_triggers_detection(self):
        ws = _ws()
        _write_sol(ws)
        _write_cargo_toml(ws, dep="solady")
        res = udm.evaluate(ws)
        self.assertEqual(res["verdict"], "fail-upstream-fork-divergence-manifest-missing")
        self.assertIn("Cargo.toml", res.get("detection_source", ""))

    # -----------------------------------------------------------------------
    # Detection surface: go.mod
    # -----------------------------------------------------------------------
    def test_gomod_dep_triggers_detection(self):
        ws = _ws()
        _write_sol(ws)
        _write_go_mod(ws, pkg="github.com/compound-finance/compound-protocol")
        res = udm.evaluate(ws)
        self.assertEqual(res["verdict"], "fail-upstream-fork-divergence-manifest-missing")
        self.assertIn("go.mod", res.get("detection_source", ""))

    # -----------------------------------------------------------------------
    # Detection surface: SCOPE.md prose
    # -----------------------------------------------------------------------
    def test_scope_md_prose_triggers_detection(self):
        ws = _ws()
        _write_sol(ws)
        _write_scope_md(ws, "This codebase is a fork of Uniswap V3.")
        res = udm.evaluate(ws)
        self.assertEqual(res["verdict"], "fail-upstream-fork-divergence-manifest-missing")
        self.assertIn("SCOPE.md", res.get("detection_source", ""))

    # -----------------------------------------------------------------------
    # FALSE-POSITIVE GUARD: a bare upstream name in prose with NO fork context
    # and NO in-scope source (vendored OOS lib / prior-audit firm) must NOT be
    # treated as a fork. Regression for the optimism FP where SCOPE.md listed
    # "OpenZeppelin" as a prior-audit firm ("OpenZeppelin, Sherlock, Cantina ...
    # collected into prior_audits/") and OZ lived only under lib/ - the gate
    # demanded a bogus upstream_divergence.json for a non-fork.
    # -----------------------------------------------------------------------
    def test_scope_md_bare_name_no_fork_context_NOT_detected(self):
        ws = _ws()
        _write_sol(ws)  # src/Vault.sol - no upstream name in path
        _write_scope_md(
            ws,
            "Prior audit reports (OpenZeppelin, Sherlock, Cantina) collected\n"
            "into prior_audits/. PoC must run on a LOCAL fork of mainnet.\n",
        )
        res = udm.evaluate(ws)
        self.assertEqual(
            res["verdict"], "pass-no-fork-detected",
            msg=f"bare-name prose mis-detected as fork: {res}")
        self.assertFalse(res.get("fork_detected"))

    def test_scope_md_name_with_fork_context_IS_detected(self):
        # "forked from OpenZeppelin" on one line -> genuine fork (proximity).
        ws = _ws()
        _write_sol(ws)
        _write_scope_md(ws, "Token core is forked from OpenZeppelin ERC20.")
        res = udm.evaluate(ws)
        self.assertEqual(
            res["verdict"], "fail-upstream-fork-divergence-manifest-missing",
            msg=f"genuine prose fork not detected: {res}")
        self.assertTrue(res.get("fork_detected"))

    def test_in_scope_source_corroborates_even_without_fork_word(self):
        # No fork verb, but the upstream's source ships IN-SCOPE (src/, not lib/)
        # -> corroborated fork (e.g. a vendored-but-in-scope fork copy).
        ws = _ws()
        _write_sol(ws, rel="src/openzeppelin/ERC20.sol")
        _write_scope_md(ws, "Uses OpenZeppelin ERC20 as the token base.")
        res = udm.evaluate(ws)
        self.assertTrue(
            res.get("fork_detected"),
            msg=f"in-scope upstream source did not corroborate: {res}")

    def test_vendored_oos_lib_only_NOT_detected(self):
        # Same name, but the only source bearing it is under lib/ (OOS vendored).
        ws = _ws()
        _write_sol(ws)  # src/Vault.sol
        # Vendored copy under lib/ - must be ignored by corroboration.
        _write_sol(ws, rel="lib/openzeppelin-contracts/contracts/ERC20.sol")
        _write_scope_md(ws, "Depends on OpenZeppelin ERC20 (vendored under lib/).")
        res = udm.evaluate(ws)
        self.assertEqual(
            res["verdict"], "pass-no-fork-detected",
            msg=f"vendored OOS lib mis-detected as fork: {res}")

    # -----------------------------------------------------------------------
    # Manifest present but empty deviations list => FAIL
    # -----------------------------------------------------------------------
    def test_manifest_empty_deviations_FAILS(self):
        ws = _ws()
        _write_sol(ws)
        _write_fork_target_json(ws, "aave")
        _write_manifest(ws, upstream="aave", deviations=[])  # empty list

        res = udm.evaluate(ws)
        self.assertEqual(res["verdict"], "fail-upstream-fork-divergence-manifest-missing",
                         msg=f"Got: {res['verdict']} | {res['reason']}")
        self.assertIn("empty", res["reason"].lower())

    # -----------------------------------------------------------------------
    # Manifest present but missing upstream field => FAIL
    # -----------------------------------------------------------------------
    def test_manifest_missing_upstream_FAILS(self):
        ws = _ws()
        _write_sol(ws)
        _write_fork_target_json(ws, "morpho")
        # Write manifest with no "upstream" field.
        d = ws / ".auditooor"
        d.mkdir(parents=True, exist_ok=True)
        (d / "upstream_divergence.json").write_text(json.dumps({
            "schema": "auditooor.upstream_divergence_manifest.v1",
            "deviations": [
                {"file": "src/Pool.sol", "kind": "modified",
                 "summary": "changed fee math"},
            ],
        }), encoding="utf-8")

        res = udm.evaluate(ws)
        self.assertEqual(res["verdict"], "fail-upstream-fork-divergence-manifest-missing")
        self.assertIn("upstream", res["reason"].lower())

    # -----------------------------------------------------------------------
    # Manifest entries lack required fields => FAIL
    # -----------------------------------------------------------------------
    def test_manifest_stub_entries_FAILS(self):
        ws = _ws()
        _write_sol(ws)
        _write_fork_target_json(ws, "solady")
        # Entries missing "summary".
        _write_manifest(ws, upstream="solady", deviations=[
            {"file": "src/Vault.sol", "kind": "modified", "summary": ""},
        ])

        res = udm.evaluate(ws)
        self.assertEqual(res["verdict"], "fail-upstream-fork-divergence-manifest-missing",
                         msg=f"Got: {res['verdict']} | {res['reason']}")

    # -----------------------------------------------------------------------
    # No in-scope source => pass-no-source
    # -----------------------------------------------------------------------
    def test_no_source_NApass(self):
        ws = _ws()
        # No .sol / .rs / .go / .vy files -> no in-scope source.
        _write_fork_target_json(ws, "uniswap")  # fork marker present

        res = udm.evaluate(ws)
        self.assertEqual(res["verdict"], "pass-no-source",
                         msg=f"Got: {res['verdict']} | {res['reason']}")

    # -----------------------------------------------------------------------
    # Multiple valid deviation entries - all count
    # -----------------------------------------------------------------------
    def test_multiple_deviations_PASSES(self):
        ws = _ws()
        _write_sol(ws)
        _write_fork_target_json(ws, "compound")
        _write_manifest(ws, upstream="compound", deviations=[
            {"file": "src/Comptroller.sol", "kind": "modified",
             "summary": "added pause guardian role"},
            {"file": "src/CToken.sol", "kind": "added",
             "summary": "added collateral-factor override"},
        ])

        res = udm.evaluate(ws)
        self.assertEqual(res["verdict"], "pass-fork-divergence-populated")
        self.assertIn("2 deviation", res["reason"])

    # -----------------------------------------------------------------------
    # fork_target.json with no upstream field still declares fork
    # -----------------------------------------------------------------------
    def test_fork_target_json_no_upstream_field_is_still_fork(self):
        ws = _ws()
        _write_sol(ws)
        (ws / "fork_target.json").write_text(
            json.dumps({"notes": "this is a fork"}), encoding="utf-8"
        )
        # No manifest -> FAIL
        res = udm.evaluate(ws)
        self.assertEqual(res["verdict"], "fail-upstream-fork-divergence-manifest-missing")
        self.assertTrue(res["fork_detected"])

    # -----------------------------------------------------------------------
    # signal key is present in result
    # -----------------------------------------------------------------------
    def test_signal_key_present_in_result(self):
        ws = _ws()
        _write_sol(ws)
        res = udm.evaluate(ws)
        self.assertIn("signal", res)
        self.assertEqual(res["signal"], "fork-divergence-content")

    # -----------------------------------------------------------------------
    # Verdict is content-checked, not presence-checked (stub JSON object only)
    # -----------------------------------------------------------------------
    def test_stub_json_object_FAILS(self):
        """A file with {} (valid JSON, no required fields) must FAIL."""
        ws = _ws()
        _write_sol(ws)
        _write_fork_target_json(ws, "balancer")
        d = ws / ".auditooor"
        d.mkdir(parents=True, exist_ok=True)
        (d / "upstream_divergence.json").write_text("{}", encoding="utf-8")

        res = udm.evaluate(ws)
        self.assertEqual(res["verdict"], "fail-upstream-fork-divergence-manifest-missing",
                         msg="Stub empty object must fail content check")

    # -----------------------------------------------------------------------
    # Aave detection via SCOPE.md with populated manifest => PASS
    # -----------------------------------------------------------------------
    def test_scope_md_detection_with_manifest_PASSES(self):
        ws = _ws()
        _write_sol(ws)
        _write_scope_md(ws, "Protocol is based on a fork of Aave V3 with modifications.")
        _write_manifest(ws, upstream="aave", deviations=[
            {"file": "src/LendingPool.sol", "kind": "modified",
             "summary": "removed flash loan fee"},
        ])

        res = udm.evaluate(ws)
        self.assertEqual(res["verdict"], "pass-fork-divergence-populated",
                         msg=f"Got: {res['verdict']} | {res['reason']}")
        self.assertEqual(res.get("detection_source"), "SCOPE.md")


if __name__ == "__main__":
    unittest.main(verbosity=2)
