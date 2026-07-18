#!/usr/bin/env python3
"""Tests for P26: narrow-waist credit-evidence loader + advisory credit-plane lint.

Covers:
  MUST-CATCH  : a genuine mutation-verified mvc sidecar on disk but the manifest
                says 0/N genuine -> lint FLAGS it (the serving-join false-red).
  MUST-CATCH  : a ws-owned hunt sidecar in the derived dir but not bridged into the
                ws bridge dir -> lint FLAGS it.
  MUST-NOT-CATCH: a cluster sidecar (credited-by-design on the narrower per-fn
                manifest scope) -> lint SUPPRESSES via the EXPECTED-SCOPE ALLOWLIST.
  MUST-NOT-CATCH: a credited mvc sidecar (manifest has the genuine row) -> not flagged.
  ALLOWLIST-INTEGRITY: a NON-allowlisted per-fn narrowing still flags (the allowlist
                is not over-broad).
  REGRESSION (flag-unset == baseline): the lint emits WARN + rc 0 by DEFAULT
                (env unset), and rc 1 ONLY under an explicit STRICT env/flag -
                mirroring lane_result_validator's AUDITOOOR_*_STRICT envelope.
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

_REPO = Path(__file__).resolve().parent.parent.parent
_LINT = _REPO / "tools" / "credit-plane-lint.py"
_LOADER = _REPO / "tools" / "lib" / "credit_evidence.py"


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, str(path))
    mod = importlib.util.module_from_spec(spec)
    sys.modules.setdefault(name, mod)  # needed for @dataclass on 3.12+/3.14
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
    return mod


lint_mod = _load(_LINT, "credit_plane_lint_under_test")
loader_mod = _load(_LOADER, "credit_evidence_under_test")


# --- fixture builders -------------------------------------------------------

def _genuine_perfn_sidecar(function: str, srcbase: str) -> dict:
    """An auto-producer-schema genuine per-fn mvc sidecar (verdict=non-vacuous,
    a behaviour-changing kill counter + a killed mutant_results row)."""
    return {
        "schema": "auditooor.mvc_sidecar.v1",
        "function": function,
        "source_file": f"src/{srcbase}.sol",
        "verdict": "non-vacuous",
        "behavior_changing_kill_count": 1,
        "killed_count": 1,
        "mutant_results": [
            {"killed": True, "kill_kind": "behavior-changing",
             "output_tail": "invariant_solvency() FAILED: assertion violated"},
        ],
    }


def _cluster_sidecar(function: str) -> dict:
    """A cluster/cross-function sidecar (mutation_verify[] campaign, KILLED row).
    Genuine per sidecar_is_genuine, but out-of-scope for the per-FN manifest."""
    return {
        "schema": "auditooor.mvc_sidecar.cluster.v1",
        "function": function,
        "mutation_verified": True,
        "mutants_killed": 1,
        "mutation_verify": [
            {"verdict": "killed", "output_tail": "property_ falsified"},
        ],
    }


def _write_ws(tmp: Path, *, sidecars: dict[str, dict], manifest_genuine_fns: list[str],
              manifest_present: bool = True) -> Path:
    ws = tmp / "ws_fixture"
    scdir = ws / ".auditooor" / "mvc_sidecar"
    scdir.mkdir(parents=True, exist_ok=True)
    for fname, rec in sidecars.items():
        (scdir / fname).write_text(json.dumps(rec), encoding="utf-8")
    if manifest_present:
        verdicts = [{"function": fn, "verdict": "non-vacuous"} for fn in manifest_genuine_fns]
        # include some non-genuine rows so the manifest is realistic
        verdicts.append({"function": "someOtherFn", "verdict": "vacuous"})
        (ws / ".auditooor" / "genuine_coverage_manifest.json").write_text(
            json.dumps({"verdicts": verdicts, "counts": {}}), encoding="utf-8"
        )
    return ws


class TestCreditPlaneLint(unittest.TestCase):

    def test_must_catch_genuine_mvc_uncredited(self):
        """MUST-CATCH: real mutation-verified harness on disk, manifest says 0/N
        genuine -> the genuine-coverage-sidecar-merge scenario -> FLAGGED."""
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            ws = _write_ws(
                tmp,
                sidecars={"mvc-vault-deposit.json": _genuine_perfn_sidecar("deposit", "vault")},
                manifest_genuine_fns=[],  # manifest credits NOTHING -> 0/N genuine
            )
            res = lint_mod.lint(ws, strict=False)
            self.assertEqual(res["verdict"], "warn-uncredited-evidence")
            self.assertEqual(res["flagged_count"], 1)
            f = res["flagged"][0]
            self.assertEqual(f["family"], "mvc")
            self.assertEqual(f["reason"], "mvc-per-fn-uncredited")
            self.assertEqual(f["function"], "deposit")

    def test_must_not_catch_credited_mvc(self):
        """MUST-NOT-CATCH: manifest DOES credit the fn -> not flagged."""
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            ws = _write_ws(
                tmp,
                sidecars={"mvc-vault-deposit.json": _genuine_perfn_sidecar("deposit", "vault")},
                manifest_genuine_fns=["deposit"],  # credited
            )
            res = lint_mod.lint(ws, strict=False)
            self.assertEqual(res["verdict"], "pass-all-credited")
            self.assertEqual(res["flagged_count"], 0)

    def test_must_not_catch_cluster_sidecar_allowlisted(self):
        """MUST-NOT-CATCH: a cluster sidecar is credited-by-design on a narrower set
        (out of scope for the per-FN manifest) -> SUPPRESSED by the allowlist, not
        flagged. Validates the EXPECTED-SCOPE ALLOWLIST."""
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            # cluster filename does NOT match the per-fn mvc-<src>-<fn> shape.
            ws = _write_ws(
                tmp,
                sidecars={"mvc-cluster-solvency.json": _cluster_sidecar("clusterInvariant")},
                manifest_genuine_fns=[],  # not in per-fn manifest (correct - it's a cluster)
            )
            res = lint_mod.lint(ws, strict=False)
            # It IS genuine on-disk and uncredited, but allowlisted -> suppressed.
            self.assertEqual(res["verdict"], "pass-all-credited")
            self.assertEqual(res["flagged_count"], 0)
            self.assertEqual(res["suppressed_count"], 1)
            self.assertEqual(
                res["suppressed_by_allowlist"][0]["reason"],
                "mvc-cluster-not-per-fn-manifest",
            )

    def test_allowlist_not_overbroad_perfn_still_flags(self):
        """ALLOWLIST-INTEGRITY: a well-formed per-fn sidecar (mvc-<src>-<fn>) that is
        uncredited is NOT swallowed by the cluster allowlist - it still FLAGS. Proves
        the allowlist keys on a precise reason-code, not a broad glob."""
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            ws = _write_ws(
                tmp,
                sidecars={
                    "mvc-vault-deposit.json": _genuine_perfn_sidecar("deposit", "vault"),
                    "mvc-cluster-solvency.json": _cluster_sidecar("clusterInvariant"),
                },
                manifest_genuine_fns=[],
            )
            res = lint_mod.lint(ws, strict=False)
            # per-fn deposit flags; cluster suppressed.
            self.assertEqual(res["flagged_count"], 1)
            self.assertEqual(res["suppressed_count"], 1)
            self.assertEqual(res["flagged"][0]["function"], "deposit")

    def test_must_catch_hunt_derived_not_bridged(self):
        """MUST-CATCH: a ws-owned hunt sidecar in the derived dir but no bridged copy
        in the ws bridge dir -> FLAGGED (hunt serving-join)."""
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            ws = tmp / "ws_fixture"
            (ws / ".auditooor" / "hunt_findings_sidecars").mkdir(parents=True, exist_ok=True)
            # derived dir with a ws-owned sidecar, NOT bridged
            derived = tmp / "derived"
            hdir = derived / "mimo_harness_wsfixture_workflow"
            hdir.mkdir(parents=True, exist_ok=True)
            (hdir / "task123.json").write_text(
                json.dumps({"workspace_path": str(ws.resolve()),
                            "result": "{}"}),
                encoding="utf-8",
            )
            res = lint_mod.lint(ws, strict=False, derived_root=derived)
            self.assertEqual(res["flagged_count"], 1)
            self.assertEqual(res["flagged"][0]["family"], "hunt")
            self.assertEqual(res["flagged"][0]["reason"], "hunt-derived-not-bridged")

    def test_must_not_catch_hunt_bridged(self):
        """MUST-NOT-CATCH: the derived sidecar IS bridged -> not flagged."""
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            ws = tmp / "ws_fixture"
            bridge = ws / ".auditooor" / "hunt_findings_sidecars"
            bridge.mkdir(parents=True, exist_ok=True)
            derived = tmp / "derived"
            hdir = derived / "mimo_harness_wsfixture_workflow"
            hdir.mkdir(parents=True, exist_ok=True)
            payload = {"workspace_path": str(ws.resolve()), "result": "{}"}
            (hdir / "task123.json").write_text(json.dumps(payload), encoding="utf-8")
            (bridge / "task123.json").write_text(json.dumps(payload), encoding="utf-8")
            res = lint_mod.lint(ws, strict=False, derived_root=derived)
            self.assertEqual(res["flagged_count"], 0)
            self.assertEqual(res["verdict"], "pass-all-credited")


class TestAdvisoryEnvelopeRegression(unittest.TestCase):
    """Flag-unset == baseline regression: the lint mirrors lane_result_validator's
    WARN-default / STRICT-elevate envelope. This is the P26 baseline check (no fast
    runtime gate exists; the correct baseline is this unit-level default-unset
    assertion, per /tmp/qna-build-baselines/P26.txt)."""

    def _mk_uncredited_ws(self, tmp: Path) -> Path:
        ws = tmp / "ws_fixture"
        scdir = ws / ".auditooor" / "mvc_sidecar"
        scdir.mkdir(parents=True, exist_ok=True)
        (scdir / "mvc-vault-deposit.json").write_text(
            json.dumps(_genuine_perfn_sidecar("deposit", "vault")), encoding="utf-8"
        )
        (ws / ".auditooor" / "genuine_coverage_manifest.json").write_text(
            json.dumps({"verdicts": []}), encoding="utf-8"
        )
        return ws

    def test_default_unset_is_warn_rc0(self):
        """DEFAULT (env unset, no --strict): WARN verdict + rc 0. This is the
        byte-identical-to-today baseline for wave-1: no gate verdict flips."""
        env = dict(os.environ)
        env.pop(lint_mod.STRICT_ENV, None)
        with tempfile.TemporaryDirectory() as td:
            ws = self._mk_uncredited_ws(Path(td))
            proc = subprocess.run(
                [sys.executable, str(_LINT), "--workspace", str(ws), "--json"],
                capture_output=True, text=True, env=env,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            out = json.loads(proc.stdout)
            self.assertEqual(out["verdict"], "warn-uncredited-evidence")
            self.assertFalse(out["strict"])

    def test_strict_env_elevates_rc1(self):
        """ONLY under an explicit STRICT env does the same uncredited delta elevate
        to FAIL + rc 1 (mirrors AUDITOOOR_*_STRICT)."""
        env = dict(os.environ)
        env[lint_mod.STRICT_ENV] = "1"
        with tempfile.TemporaryDirectory() as td:
            ws = self._mk_uncredited_ws(Path(td))
            proc = subprocess.run(
                [sys.executable, str(_LINT), "--workspace", str(ws), "--json"],
                capture_output=True, text=True, env=env,
            )
            self.assertEqual(proc.returncode, 1, proc.stdout)
            out = json.loads(proc.stdout)
            self.assertEqual(out["verdict"], "fail-uncredited-evidence")
            self.assertTrue(out["strict"])

    def test_strict_flag_elevates_rc1(self):
        """--strict flag also elevates (parity with the env)."""
        env = dict(os.environ)
        env.pop(lint_mod.STRICT_ENV, None)
        with tempfile.TemporaryDirectory() as td:
            ws = self._mk_uncredited_ws(Path(td))
            proc = subprocess.run(
                [sys.executable, str(_LINT), "--workspace", str(ws), "--strict", "--json"],
                capture_output=True, text=True, env=env,
            )
            self.assertEqual(proc.returncode, 1, proc.stdout)
            self.assertEqual(json.loads(proc.stdout)["verdict"], "fail-uncredited-evidence")

    def test_all_credited_passes_rc0_both_modes(self):
        """A fully-credited ws is pass + rc 0 in BOTH default and strict - the lint
        never invents a false-red, so a genuine 0-delta workspace is unaffected."""
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            ws = _write_ws(
                tmp,
                sidecars={"mvc-vault-deposit.json": _genuine_perfn_sidecar("deposit", "vault")},
                manifest_genuine_fns=["deposit"],
            )
            for strict in (False, True):
                res = lint_mod.lint(ws, strict=strict)
                self.assertEqual(res["verdict"], "pass-all-credited")


class TestLoaderShape(unittest.TestCase):
    def test_loader_returns_typed_record_tolerant_of_empty_ws(self):
        """The loader never crashes on a bare ws (missing every artifact) and returns
        empty views + notes."""
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td) / "empty_ws"
            ws.mkdir()
            rec = loader_mod.load_credit_evidence(ws, derived_root=Path(td) / "no_derived")
            self.assertEqual(rec.schema, "auditooor.credit_evidence.v1")
            self.assertEqual(rec.mvc_on_disk_genuine, [])
            self.assertEqual(rec.hunt_derived_owned, [])
            self.assertFalse(rec.coverage_plane_present)
            self.assertTrue(rec.to_dict())  # serializable

    def test_loader_reuses_canonical_sidecar_is_genuine(self):
        """A vacuous sidecar (verdict != non-vacuous, no kill) is NOT loaded as
        genuine - proves the loader reuses mutation_kill.sidecar_is_genuine's
        fail-closed predicate rather than a weaker one."""
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            vac = {"function": "f", "verdict": "vacuous", "mutant_results": []}
            ws = _write_ws(tmp, sidecars={"mvc-vault-f.json": vac},
                           manifest_genuine_fns=[])
            rec = loader_mod.load_credit_evidence(ws)
            self.assertEqual(rec.mvc_on_disk_genuine, [])


if __name__ == "__main__":
    unittest.main()
