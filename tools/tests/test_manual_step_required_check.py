#!/usr/bin/env python3
# <!-- r36-rebuttal: lane WIRE-GO-COVERAGE-ENFORCE registered via agent-pathspec-register.py -->
"""Guard tests for tools/manual-step-required-check.py - the fail-closed
enforcement for REQUIRING-MANUAL-MODEL-ACTION steps (the operator's key ask: a
step that cannot be safely autorun must be detected as done+attested, else fail
closed printing the exact instruction).

NEVER-FALSE-PASS pins:
  - a Cosmos-Go-L1 with a go-ethereum fork + NO attestations -> both manual steps
    unattested -> fail-manual-step-unattested (WARN advisory / FAIL strict) with
    the exact instruction surfaced;
  - a valid attestation flips the step GREEN;
  - a rubber-stamp attestation (attested_by not in accepted set) stays RED;
  - a blank required field stays RED;
  - a non-applicable workspace (no cosmos, no go fork) -> pass-no-applicable;
  - the two seeded instruction strings are non-empty and name their step.
"""
from __future__ import annotations

import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

_TOOL = Path(__file__).resolve().parent.parent / "manual-step-required-check.py"


def _load():
    spec = importlib.util.spec_from_file_location("manual_step_required_check", _TOOL)
    m = importlib.util.module_from_spec(spec)
    sys.modules["manual_step_required_check"] = m
    spec.loader.exec_module(m)
    return m


_MOD = _load()

_COSMOS_GOMOD = (
    "module example.com/chain\n\ngo 1.21\n\n"
    "require github.com/cosmos/cosmos-sdk v0.50.1\n"
)


def _mk_cosmos_fork_ws(tmp: Path) -> Path:
    """A Cosmos-Go-L1 that also vendors a go-ethereum fork (both manual steps apply)."""
    ws = tmp
    (ws / ".auditooor").mkdir(parents=True, exist_ok=True)
    (ws / "go.mod").write_text(_COSMOS_GOMOD, encoding="utf-8")
    (ws / "app.go").write_text("package app\n", encoding="utf-8")
    # SCOPE.md naming a go-ethereum fork base -> _has_go_fork True
    (ws / "SCOPE.md").write_text(
        "# Scope\n## Fork Bases\nbor = ethereum/go-ethereum@v1.16.8\n",
        encoding="utf-8")
    return ws


def _mk_plain_ws(tmp: Path) -> Path:
    """A Solidity workspace: no cosmos go.mod, no go-ethereum fork."""
    ws = tmp
    (ws / ".auditooor").mkdir(parents=True, exist_ok=True)
    (ws / "Contract.sol").write_text("pragma solidity ^0.8.20;\n", encoding="utf-8")
    (ws / "SCOPE.md").write_text("# Scope\nin scope: Contract.sol\n", encoding="utf-8")
    return ws


def _write_attestation(ws: Path, step_id: str, obj: dict) -> None:
    d = ws / ".auditooor" / "manual_step_attestations"
    d.mkdir(parents=True, exist_ok=True)
    (d / f"{step_id}.json").write_text(json.dumps(obj), encoding="utf-8")


def _valid_attest(extra: dict) -> dict:
    base = {"completed_at": "2026-07-04T00:00:00Z",
            "attested_by": "operator", "summary": "did the step by hand"}
    base.update(extra)
    return base


class TestManualStepRequired(unittest.TestCase):
    def test_unattested_applicable_advisory_warns(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _mk_cosmos_fork_ws(Path(td))
            r = _MOD.evaluate(ws)  # advisory
            self.assertEqual(r["verdict"], "fail-manual-step-unattested")
            self.assertTrue(r["ok"])                # advisory: WARN
            self.assertTrue(r["reason"].startswith("WARN:"))
            self.assertEqual(r["applicable_count"], 2)
            ids = {u["id"] for u in r["unattested"]}
            self.assertIn("go-ethereum-fork-delta-prune-verify", ids)
            self.assertIn("entry-point-scoped-hunt-scoping", ids)
            for u in r["unattested"]:
                self.assertTrue(u["instruction"])   # exact instruction surfaced

    def test_unattested_applicable_strict_fails(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _mk_cosmos_fork_ws(Path(td))
            old = os.environ.get("AUDITOOOR_L37_STRICT")
            os.environ["AUDITOOOR_L37_STRICT"] = "1"
            try:
                r = _MOD.evaluate(ws)
            finally:
                if old is None:
                    os.environ.pop("AUDITOOOR_L37_STRICT", None)
                else:
                    os.environ["AUDITOOOR_L37_STRICT"] = old
            self.assertEqual(r["verdict"], "fail-manual-step-unattested")
            self.assertFalse(r["ok"])               # strict: hard fail
            self.assertFalse(r["reason"].startswith("WARN:"))

    def test_valid_attestations_pass(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _mk_cosmos_fork_ws(Path(td))
            _write_attestation(ws, "go-ethereum-fork-delta-prune-verify",
                               _valid_attest({"fork_base_resolved": True,
                                              "files_pruned_proven_unmodified": 12,
                                              "files_kept_with_delta_or_unresolved": 3}))
            _write_attestation(ws, "entry-point-scoped-hunt-scoping",
                               _valid_attest({"go_entry_surface_applied": True,
                                              "hunt_scoped_to_entry_point_residual": True}))
            old = os.environ.get("AUDITOOOR_L37_STRICT")
            os.environ["AUDITOOOR_L37_STRICT"] = "1"
            try:
                r = _MOD.evaluate(ws)
            finally:
                if old is None:
                    os.environ.pop("AUDITOOOR_L37_STRICT", None)
                else:
                    os.environ["AUDITOOOR_L37_STRICT"] = old
            self.assertEqual(r["verdict"], "pass-all-manual-steps-attested")
            self.assertTrue(r["ok"])

    def test_rubber_stamp_attested_by_stays_red(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _mk_cosmos_fork_ws(Path(td))
            # attest both, but one with a rubber-stamp attested_by
            _write_attestation(ws, "entry-point-scoped-hunt-scoping",
                               _valid_attest({"go_entry_surface_applied": True,
                                              "hunt_scoped_to_entry_point_residual": True}))
            bad = _valid_attest({"fork_base_resolved": True,
                                 "files_pruned_proven_unmodified": 1,
                                 "files_kept_with_delta_or_unresolved": 1})
            bad["attested_by"] = "claude"  # NOT in the accepted set
            _write_attestation(ws, "go-ethereum-fork-delta-prune-verify", bad)
            r = _MOD.evaluate(ws)
            self.assertEqual(r["verdict"], "fail-manual-step-unattested")
            ids = {u["id"] for u in r["unattested"]}
            self.assertIn("go-ethereum-fork-delta-prune-verify", ids)

    def test_blank_required_field_stays_red(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _mk_cosmos_fork_ws(Path(td))
            _write_attestation(ws, "entry-point-scoped-hunt-scoping",
                               _valid_attest({"go_entry_surface_applied": True,
                                              "hunt_scoped_to_entry_point_residual": True}))
            blank = _valid_attest({"fork_base_resolved": True,
                                   "files_pruned_proven_unmodified": 1,
                                   "files_kept_with_delta_or_unresolved": 1})
            blank["summary"] = "   "  # blank required field
            _write_attestation(ws, "go-ethereum-fork-delta-prune-verify", blank)
            r = _MOD.evaluate(ws)
            self.assertEqual(r["verdict"], "fail-manual-step-unattested")

    def test_missing_step_specific_field_stays_red(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _mk_cosmos_fork_ws(Path(td))
            _write_attestation(ws, "entry-point-scoped-hunt-scoping",
                               _valid_attest({"go_entry_surface_applied": True,
                                              "hunt_scoped_to_entry_point_residual": True}))
            # fork-delta attestation MISSING its step-specific fields
            _write_attestation(ws, "go-ethereum-fork-delta-prune-verify",
                               _valid_attest({}))
            r = _MOD.evaluate(ws)
            self.assertEqual(r["verdict"], "fail-manual-step-unattested")

    def test_non_applicable_workspace_passes(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _mk_plain_ws(Path(td))
            old = os.environ.get("AUDITOOOR_L37_STRICT")
            os.environ["AUDITOOOR_L37_STRICT"] = "1"
            try:
                r = _MOD.evaluate(ws)
            finally:
                if old is None:
                    os.environ.pop("AUDITOOOR_L37_STRICT", None)
                else:
                    os.environ["AUDITOOOR_L37_STRICT"] = old
            self.assertEqual(r["verdict"], "pass-no-applicable-manual-steps")
            self.assertTrue(r["ok"])
            self.assertEqual(r["applicable_count"], 0)

    def test_seeded_instruction_strings_present(self):
        by_id = {s["id"]: s for s in _MOD.MANUAL_STEPS}
        self.assertIn("go-ethereum-fork-delta-prune-verify", by_id)
        self.assertIn("entry-point-scoped-hunt-scoping", by_id)
        i1 = by_id["go-ethereum-fork-delta-prune-verify"]["instruction"]
        i2 = by_id["entry-point-scoped-hunt-scoping"]["instruction"]
        self.assertTrue(i1 and "fork-delta prune" in i1)
        self.assertTrue(i2 and "entry-point" in i2.lower())
        # no em/en-dash in the seeded instructions (chr() so this source file
        # itself stays dash-clean)
        em_dash, en_dash = chr(0x2014), chr(0x2013)
        for s in (i1, i2):
            self.assertNotIn(em_dash, s)
            self.assertNotIn(en_dash, s)


class TestForkDetectionNoFalseTrigger(unittest.TestCase):
    """Regression: a first-party Cosmos-Go workspace that only MENTIONS go-ethereum
    to DENY a fork must NOT trigger the go-ethereum-fork-delta manual step (NUVA
    2026-07-06: SCOPE.md 'NOT a fork of ... go-ethereum' + empty fork_bases.json
    was false-flagged as having a fork, hard-failing audit-complete)."""

    def _mk_cosmos_nofork_ws(self, tmp: Path, fork_bases: str | None = "{}") -> Path:
        ws = tmp
        (ws / ".auditooor").mkdir(parents=True, exist_ok=True)
        (ws / "go.mod").write_text(_COSMOS_GOMOD, encoding="utf-8")
        (ws / "app.go").write_text("package app\n", encoding="utf-8")
        (ws / "SCOPE.md").write_text(
            "# Scope\n## Fork Bases\nNUVA src/ contains NO upstream fork. The vault "
            "module and the Solidity contracts are FIRST-PARTY code, not a fork of "
            "bor / cosmos-sdk / cometbft / go-ethereum. The fork-base set is empty.\n",
            encoding="utf-8")
        if fork_bases is not None:
            (ws / ".auditooor" / "fork_bases.json").write_text(fork_bases, encoding="utf-8")
        return ws

    def test_negated_scope_mention_is_not_a_fork(self):
        with tempfile.TemporaryDirectory() as td:
            ws = self._mk_cosmos_nofork_ws(Path(td))
            self.assertFalse(_MOD._has_go_fork(ws))
            r = _MOD.evaluate(ws)
            ids = {u["id"] for u in r.get("unattested", [])} | \
                  {a["id"] for a in r.get("applicable", [])} if r.get("applicable") else \
                  {u["id"] for u in r.get("unattested", [])}
            self.assertNotIn("go-ethereum-fork-delta-prune-verify", ids)

    def test_empty_fork_bases_suppresses_even_affirmative_text(self):
        # An authoritative empty fork_bases.json means the prune has no base to
        # verify against -> N/A even if SCOPE.md names a base in prose.
        with tempfile.TemporaryDirectory() as td:
            ws = self._mk_cosmos_nofork_ws(Path(td), fork_bases="[]")
            (ws / "SCOPE.md").write_text(
                "# Scope\n## Fork Bases\nbor = ethereum/go-ethereum@v1.16.8\n",
                encoding="utf-8")
            self.assertFalse(_MOD._has_go_fork(ws))

    def test_resolved_fork_bases_json_applies(self):
        with tempfile.TemporaryDirectory() as td:
            ws = self._mk_cosmos_nofork_ws(
                Path(td), fork_bases='{"bor": "ethereum/go-ethereum@v1.16.8"}')
            self.assertTrue(_MOD._has_go_fork(ws))

    def test_affirmative_scope_row_still_applies_without_fork_bases_file(self):
        # No fork_bases.json at all + an affirmative Fork Bases row -> still a fork.
        with tempfile.TemporaryDirectory() as td:
            ws = self._mk_cosmos_nofork_ws(Path(td), fork_bases=None)
            (ws / "SCOPE.md").write_text(
                "# Scope\n## Fork Bases\nbor = ethereum/go-ethereum@v1.16.8\n",
                encoding="utf-8")
            self.assertTrue(_MOD._has_go_fork(ws))


if __name__ == "__main__":
    unittest.main()
