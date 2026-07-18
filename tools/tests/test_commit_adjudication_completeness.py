# <!-- r36-rebuttal: lane commit-adjudication-completeness registered via agent-pathspec-register.py -->
"""commit-adjudication-completeness: fail-closed when a security-shaped fix-commit
touching an IN-SCOPE file was classified by backward mining but never adjudicated
(strata 2026-07-02 operator-caught false-green).

Guarantees:
 - an in-scope residual security commit with NO adjudication -> fail (strict rc 1).
 - the same with a terminal adjudication record -> pass.
 - a residual commit touching ONLY out-of-scope files -> auto-OOS, pass.
 - no residual security commits -> pass.
"""
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

_TOOL = Path(__file__).resolve().parent.parent / "commit-adjudication-completeness-check.py"


def _load():
    spec = importlib.util.spec_from_file_location("commit_adj_check", _TOOL)
    m = importlib.util.module_from_spec(spec)
    sys.modules["commit_adj_check"] = m
    spec.loader.exec_module(m)
    return m


MOD = _load()


def _git(repo, *args):
    subprocess.run(["git", "-C", str(repo), *args], check=True,
                   capture_output=True, text=True)


class CommitAdjudicationTest(unittest.TestCase):
    def setUp(self):
        os.environ.pop("AUDITOOOR_COMMIT_ADJUDICATION_STRICT", None)
        os.environ.pop("AUDITOOOR_SCOPE_MODE", None)
        self.ws = Path(tempfile.mkdtemp())
        (self.ws / ".auditooor").mkdir()
        # a src git repo with an in-scope file and an out-of-scope file
        self.repo = self.ws / "src"
        (self.repo / "contracts").mkdir(parents=True)
        (self.repo / "strategies").mkdir(parents=True)
        _git(self.repo, "init", "-q")
        _git(self.repo, "config", "user.email", "t@t.t")
        _git(self.repo, "config", "user.name", "t")
        (self.ws / ".auditooor" / "inscope_units.jsonl").write_text(
            json.dumps({"file": "src/contracts/Vault.sol", "function": "f"}), encoding="utf-8")
        # in-scope commit
        (self.repo / "contracts" / "Vault.sol").write_text("// v1", encoding="utf-8")
        _git(self.repo, "add", "-A"); _git(self.repo, "commit", "-qm", "fix(Vault): boundary")
        self.sha_in = subprocess.run(["git", "-C", str(self.repo), "rev-parse", "HEAD"],
                                     capture_output=True, text=True).stdout.strip()
        # out-of-scope PRODUCTION commit (an OOS mechanism - must NOT auto-clear)
        (self.repo / "strategies" / "Strat.sol").write_text("// s1", encoding="utf-8")
        _git(self.repo, "add", "-A"); _git(self.repo, "commit", "-qm", "fix(Strat): x")
        self.sha_oos_prod = subprocess.run(["git", "-C", str(self.repo), "rev-parse", "HEAD"],
                                          capture_output=True, text=True).stdout.strip()
        # NON-production commit (test-only - safe to auto-clear)
        (self.repo / "test").mkdir()
        (self.repo / "test" / "Vault.t.sol").write_text("// test", encoding="utf-8")
        _git(self.repo, "add", "-A"); _git(self.repo, "commit", "-qm", "fix(tests): x")
        self.sha_nonprod = subprocess.run(["git", "-C", str(self.repo), "rev-parse", "HEAD"],
                                          capture_output=True, text=True).stdout.strip()

    def _ledger(self, shas):
        (self.ws / ".auditooor" / "commit_lifecycle_ledger.json").write_text(json.dumps({
            "lanes_residual": [{"classification": "security_shaped_commit", "sha": s, "hint": "h"}
                               for s in shas]}), encoding="utf-8")

    def _adj(self, recs):
        (self.ws / ".auditooor" / "commit_adjudications.jsonl").write_text(
            "\n".join(json.dumps(r) for r in recs), encoding="utf-8")

    def test_no_residual_passes(self):
        self._ledger([])
        self.assertEqual(MOD.check(self.ws)["verdict"], "pass-no-residual-security-commits")

    def test_inscope_unadjudicated_advisory_by_default(self):
        # advisory (warn) by default so it never retroactively bricks a prior audit
        self._ledger([self.sha_in])
        r = MOD.check(self.ws)
        self.assertEqual(r["verdict"], "warn-commit-adjudication-incomplete")
        self.assertEqual(r["actionable"], 1)

    def test_inscope_unadjudicated_fails_strict(self):
        self._ledger([self.sha_in])
        os.environ["AUDITOOOR_COMMIT_ADJUDICATION_STRICT"] = "1"
        try:
            self.assertEqual(MOD.check(self.ws)["verdict"], "fail-commit-adjudication-incomplete")
        finally:
            os.environ.pop("AUDITOOOR_COMMIT_ADJUDICATION_STRICT", None)

    def test_inscope_adjudicated_passes(self):
        self._ledger([self.sha_in])
        self._adj([{"sha": self.sha_in, "verdict": "complete",
                    "reason": "fix holds at pin; the guarded subtraction cannot underflow because the "
                              "setter validates the bound", "source_ref": "x:1"}])
        self.assertEqual(MOD.check(self.ws)["verdict"], "pass-commit-adjudication-complete")

    def test_rules_mode_oos_production_auto_cleared(self):
        # PRIMACY-OF-RULES (default): only enumerated in-scope items matter, so an
        # OOS production mechanism is genuinely out - auto-cleared.
        self._ledger([self.sha_oos_prod])
        r = MOD.check(self.ws)
        self.assertEqual(r["scope_mode"], "rules")
        self.assertEqual(r["verdict"], "pass-commit-adjudication-complete")
        self.assertEqual(r["oos_rules_auto_cleared"], 1)

    def test_impact_mode_oos_production_is_actionable(self):
        # PRIMACY-OF-IMPACT: an OOS PRODUCTION mechanism can drive an in-scope
        # IMPACT, so it must be adjudicated - NEVER auto-cleared by file location.
        os.environ["AUDITOOOR_SCOPE_MODE"] = "impact"
        try:
            self._ledger([self.sha_oos_prod])
            r = MOD.check(self.ws)
            self.assertEqual(r["scope_mode"], "impact")
            self.assertEqual(r["verdict"], "warn-commit-adjudication-incomplete")
            self.assertIs(r["violations"][0]["in_scope"], False)
        finally:
            os.environ.pop("AUDITOOOR_SCOPE_MODE", None)

    def test_impact_mode_from_scope_md_marker(self):
        (self.ws / "SCOPE.md").write_text(
            "In scope: X. Any bug that leads to loss of user funds is in scope "
            "regardless of the contract.", encoding="utf-8")
        self.assertEqual(MOD._scope_mode(self.ws), "impact")

    def test_negated_impact_mention_resolves_to_rules(self):
        # the strata trap: "Primacy of RULES (not Primacy of Impact)" must NOT match
        # "primacy of impact" inside the negation - explicit RULES wins.
        (self.ws / "SCOPE.md").write_text(
            "Primacy of RULES (not Primacy of Impact) - only the in-scope assets "
            "and in-scope impacts below qualify.", encoding="utf-8")
        self.assertEqual(MOD._scope_mode(self.ws), "rules")

    def test_impact_mode_oos_with_reachability_verdict_passes(self):
        os.environ["AUDITOOOR_SCOPE_MODE"] = "impact"
        try:
            self._ledger([self.sha_oos_prod])
            self._adj([{"sha": self.sha_oos_prod, "verdict": "oos",
                        "reason": "strategies/ OOS; no in-scope contract references this mechanism "
                                  "(grep-confirmed) so it cannot reach an in-scope impact",
                        "source_ref": "SCOPE.md"}])
            self.assertEqual(MOD.check(self.ws)["verdict"], "pass-commit-adjudication-complete")
        finally:
            os.environ.pop("AUDITOOOR_SCOPE_MODE", None)

    def test_nonproduction_commit_auto_cleared_both_modes(self):
        # test/mock/docs/CI files cannot ship a runtime impact -> auto-clear always
        self._ledger([self.sha_nonprod])
        r = MOD.check(self.ws)
        self.assertEqual(r["verdict"], "pass-commit-adjudication-complete")
        self.assertEqual(r["nonprod_auto_cleared"], 1)

    def test_impact_mode_bare_oos_reason_rejected(self):
        # an OOS verdict with a too-short (non-impact-reachability) reason does not
        # count - proving absence must be as hard as proving presence.
        os.environ["AUDITOOOR_SCOPE_MODE"] = "impact"
        try:
            self._ledger([self.sha_oos_prod])
            self._adj([{"sha": self.sha_oos_prod, "verdict": "oos", "reason": "OOS file"}])
            self.assertEqual(MOD.check(self.ws)["verdict"], "warn-commit-adjudication-incomplete")
        finally:
            os.environ.pop("AUDITOOOR_SCOPE_MODE", None)

    def test_strict_rc(self):
        self._ledger([self.sha_in])
        os.environ["AUDITOOOR_COMMIT_ADJUDICATION_STRICT"] = "1"
        try:
            rc = MOD.main(["--ws", str(self.ws)])
            self.assertEqual(rc, 1)
        finally:
            os.environ.pop("AUDITOOOR_COMMIT_ADJUDICATION_STRICT", None)

    def test_non_security_commit_ignored(self):
        (self.ws / ".auditooor" / "commit_lifecycle_ledger.json").write_text(json.dumps({
            "lanes_residual": [{"classification": "refactor", "sha": self.sha_in, "hint": "h"}]}),
            encoding="utf-8")
        self.assertEqual(MOD.check(self.ws)["verdict"], "pass-no-residual-security-commits")


if __name__ == "__main__":
    unittest.main(verbosity=2)
