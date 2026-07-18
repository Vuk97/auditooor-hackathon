"""Tests for tools/hunt-completeness-check.py (L35 hunt-completeness gate).

Each test builds a tmp fixture workspace and asserts the verdict + exit code
for every branch of the verdict vocabulary:
  pass-hunt-complete / fail-shallow-clone / fail-no-audit-deep /
  fail-no-coverage-matrix / fail-dark-families /
  fail-missing-cluster-coverage / fail-no-artifact-mining / error
plus the l35-rebuttal override paths.
"""
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import unittest
from pathlib import Path

TOOL = Path(__file__).resolve().parents[1] / "hunt-completeness-check.py"


def _resolve_real_git() -> str:
    """Return a git binary that is NOT the auditooor MCP-gate wrapper.

    The host installs a `git` shim at ~/.auditooor/bin/git that rejects
    write ops unless an MCP recall file exists. The fixture builders below
    need real commit history, so resolve the genuine binary the wrapper
    itself execs (AUDITOOOR_REAL_GIT or /usr/bin/git), falling back to
    whichever PATH git is not a symlink into .auditooor/.
    """
    cand = os.environ.get("AUDITOOOR_REAL_GIT")
    if cand and os.access(cand, os.X_OK):
        return cand
    if os.access("/usr/bin/git", os.X_OK):
        return "/usr/bin/git"
    found = shutil.which("git")
    if found and ".auditooor" not in str(Path(found).resolve()):
        return found
    return found or "git"


_GIT = _resolve_real_git()

_spec = importlib.util.spec_from_file_location("hunt_completeness_check", TOOL)
hcc = importlib.util.module_from_spec(_spec)
# Register before exec so @dataclass type resolution (Py3.14) can find the module.
sys.modules["hunt_completeness_check"] = hcc
_spec.loader.exec_module(hcc)


def _git_init_full(repo: Path):
    """Create a real git repo with >1 commit (full clone equivalent)."""
    repo.mkdir(parents=True, exist_ok=True)
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t",
        "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@t",
        "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_SYSTEM": "/dev/null",
        "HOME": str(repo),  # avoid touching real ~/.gitconfig
    }
    subprocess.run([_GIT, "init", "-q"], cwd=repo, check=True, env=env)
    for i in range(3):
        (repo / f"f{i}.txt").write_text(f"content {i}\n")
        subprocess.run([_GIT, "add", "-A"], cwd=repo, check=True, env=env)
        subprocess.run(
            [_GIT, "commit", "-q", "-m", f"rev {i}"],
            cwd=repo, check=True, env=env,
        )


def _git_init_shallow_like(repo: Path):
    """Create a git repo with a fabricated .git/shallow marker."""
    _git_init_full(repo)
    (repo / ".git" / "shallow").write_text("deadbeef\n")


class _Base(unittest.TestCase):
    def setUp(self):
        import tempfile
        self._td = tempfile.TemporaryDirectory()
        self.ws = Path(self._td.name) / "ws"
        self.ws.mkdir(parents=True)

    def tearDown(self):
        self._td.cleanup()

    # --- fixture builders --------------------------------------------------
    def add_dedup_skip_set(self, total=0):
        """L36 step-0 dedup skip-set; signal-0 precondition for a real hunt."""
        a = self.ws / ".auditooor"
        a.mkdir(parents=True, exist_ok=True)
        (a / "hunt_skip_set.json").write_text(json.dumps({
            "schema": "auditooor.l36_hunt_skip_set.v1",
            "source_counts": {"total_after_dedup": total},
        }))

    def add_full_clone(self):
        repo = self.ws / "external" / "target"
        _git_init_full(repo)
        (self.ws / "mining_rounds" / "2026-05-29-bidirectional-commit-mining").mkdir(parents=True)
        (self.ws / "mining_rounds" / "2026-05-29-bidirectional-commit-mining" / "manifest.json").write_text("{}")
        self.add_dedup_skip_set()

    def add_shallow_clone(self):
        repo = self.ws / "external" / "target"
        _git_init_shallow_like(repo)
        (self.ws / "mining_rounds" / "r1").mkdir(parents=True)
        (self.ws / "mining_rounds" / "r1" / "manifest.json").write_text("{}")
        self.add_dedup_skip_set()

    def add_audit_deep(self):
        logs = self.ws / ".audit_logs"
        logs.mkdir(parents=True, exist_ok=True)
        (logs / "audit_deep_all_manifest.json").write_text('{"profiles":[]}')

    def add_coverage_matrix(self, dark=False):
        rows = [
            "| Cluster | Reward Category | Status |",
            "|---|---|---|",
            "| chain-watcher | direct-loss | COVERED |",
            "| coop-exit | freeze | COVERED |",
        ]
        if dark:
            rows.append("| signing | direct-loss | DARK |")
        (self.ws / "MY_CAPABILITY_COVERAGE_MATRIX.md").write_text("\n".join(rows) + "\n")

    def add_scope(self, clusters=("chain-watcher", "coop-exit", "signing")):
        lines = ["# Scope", "", "## In scope"]
        for c in clusters:
            lines.append(f"- {c}")
        (self.ws / "SCOPE.md").write_text("\n".join(lines) + "\n")

    def add_sidecars(self, names=("chain-watcher", "coop-exit", "signing")):
        sc = self.ws / "hunt_findings_sidecars"
        sc.mkdir(parents=True, exist_ok=True)
        for n in names:
            (sc / f"{n}.json").write_text("{}")

    def add_learn_report(self):
        rep = self.ws / "reports"
        rep.mkdir(parents=True, exist_ok=True)
        (rep / "agent_artifact_mine_report.json").write_text('{"mined":1}')

    def add_all(self):
        self.add_full_clone()
        self.add_audit_deep()
        self.add_coverage_matrix(dark=False)
        self.add_scope()
        self.add_sidecars()
        self.add_learn_report()

    def run_tool(self):
        return hcc.evaluate(self.ws.resolve())


class TestPassComplete(_Base):
    def test_all_five_signals_pass(self):
        self.add_all()
        r = self.run_tool()
        self.assertEqual(r["verdict"], "pass-hunt-complete", r)

    def test_numbered_asset_table_uses_asset_column(self):
        self.add_full_clone()
        self.add_audit_deep()
        self.add_learn_report()
        scope = "\n".join([
            "# Scope",
            "",
            "| # | Asset | Repo |",
            "|---|---|---|",
            "| 1 | **v4-chain (protocol)** | dydxprotocol/v4-chain |",
            "| 2 | **v4-chain (indexer)** | dydxprotocol/v4-chain/indexer |",
        ]) + "\n"
        (self.ws / "SCOPE.md").write_text(scope)
        (self.ws / "MY_CAPABILITY_COVERAGE_MATRIX.md").write_text("\n".join([
            "| Cluster | Reward Category | Status |",
            "|---|---|---|",
            "| **v4-chain (protocol)** | direct-loss | COVERED |",
            "| **v4-chain (indexer)** | direct-loss | COVERED |",
        ]) + "\n")
        self.add_sidecars(names=("v4-chain-protocol", "v4-chain-indexer"))

        r = self.run_tool()

        self.assertEqual(r["verdict"], "pass-hunt-complete", r)
        cluster_signal = next(s for s in r["signals"] if s["signal"] == "cluster-coverage")
        self.assertEqual(
            cluster_signal["detail"]["clusters"],
            ["**v4-chain (protocol)**", "**v4-chain (indexer)**"],
        )
        self.assertEqual(r["failures"], [])


class TestShallowClone(_Base):
    def test_shallow_marker(self):
        self.add_shallow_clone()
        self.add_audit_deep()
        self.add_coverage_matrix()
        self.add_scope()
        self.add_sidecars()
        self.add_learn_report()
        r = self.run_tool()
        self.assertEqual(r["verdict"], "fail-shallow-clone", r)

    def test_no_clone_at_all(self):
        # everything else present, but no git repo
        self.add_audit_deep()
        self.add_coverage_matrix()
        self.add_scope()
        self.add_sidecars()
        self.add_learn_report()
        (self.ws / "mining_rounds" / "r1").mkdir(parents=True)
        (self.ws / "mining_rounds" / "r1" / "m.json").write_text("{}")
        self.add_dedup_skip_set()
        r = self.run_tool()
        self.assertEqual(r["verdict"], "fail-shallow-clone", r)

    def test_full_clone_but_no_mining_rounds(self):
        repo = self.ws / "external" / "target"
        _git_init_full(repo)
        self.add_dedup_skip_set()
        self.add_audit_deep()
        self.add_coverage_matrix()
        self.add_scope()
        self.add_sidecars()
        self.add_learn_report()
        r = self.run_tool()
        self.assertEqual(r["verdict"], "fail-shallow-clone", r)
        self.assertIn("mining_rounds", r["reason"])


class TestNoAuditDeep(_Base):
    def test_missing_audit_deep(self):
        self.add_full_clone()
        self.add_coverage_matrix()
        self.add_scope()
        self.add_sidecars()
        self.add_learn_report()
        r = self.run_tool()
        self.assertEqual(r["verdict"], "fail-no-audit-deep", r)


class TestNoCoverageMatrix(_Base):
    def test_missing_matrix(self):
        self.add_full_clone()
        self.add_audit_deep()
        self.add_scope()
        self.add_sidecars()
        self.add_learn_report()
        r = self.run_tool()
        self.assertEqual(r["verdict"], "fail-no-coverage-matrix", r)


class TestDarkFamilies(_Base):
    def test_matrix_with_dark_rows(self):
        self.add_full_clone()
        self.add_audit_deep()
        self.add_coverage_matrix(dark=True)
        self.add_scope()
        self.add_sidecars()
        self.add_learn_report()
        r = self.run_tool()
        self.assertEqual(r["verdict"], "fail-dark-families", r)
        # the dark-row detail must name the offending row
        dark_sig = next(s for s in r["signals"] if s["signal"] == "coverage-matrix-no-dark")
        self.assertFalse(dark_sig["ok"])

    def test_dark_matrix_rows_do_not_count_as_cluster_coverage(self):
        self.add_full_clone()
        self.add_audit_deep()
        self.add_scope(clusters=("chain-watcher", "coop-exit"))
        rows = [
            "| Cluster | Status | Evidence |",
            "|---|---|---|",
            "| chain-watcher | DARK | stale matrix row |",
            "| coop-exit | DARK | stale matrix row |",
        ]
        (self.ws / "HUNT_CAPABILITY_COVERAGE_MATRIX.md").write_text("\n".join(rows) + "\n")
        self.add_learn_report()

        r = self.run_tool()

        self.assertEqual(r["verdict"], "fail-dark-families", r)
        dark_sig = next(s for s in r["signals"] if s["signal"] == "coverage-matrix-no-dark")
        self.assertFalse(dark_sig["raw_ok"])
        cc = next(s for s in r["signals"] if s["signal"] == "cluster-coverage")
        self.assertFalse(cc["raw_ok"])
        self.assertEqual(set(cc["detail"]["uncovered"]), {"chain-watcher", "coop-exit"})

    def test_orphan_dark_row_for_out_of_scope_cluster_does_not_fail(self):
        """A stale / hand-authored sibling matrix DARK row whose cluster is
        NOT in the current SCOPE.md is stale bookkeeping, not a coverage gap;
        it must not zero the hunt. Regression for the morpho-midnight
        STRICT-log cascade where a prior-scope matrix DARK row fatally
        blocked the completeness gate even though every in-scope cluster was
        covered."""
        self.add_full_clone()
        self.add_audit_deep()
        # current scope: only chain-watcher + coop-exit, both covered.
        self.add_scope(clusters=("chain-watcher", "coop-exit"))
        self.add_sidecars(names=("chain-watcher", "coop-exit"))
        self.add_learn_report()
        # fresh in-scope matrix (all COVERED)
        rows = [
            "| Cluster | Status | Evidence |",
            "|---|---|---|",
            "| chain-watcher | COVERED | sidecar token match |",
            "| coop-exit | COVERED | sidecar token match |",
        ]
        (self.ws / "HUNT_CAPABILITY_COVERAGE_MATRIX.md").write_text("\n".join(rows) + "\n")
        # stale sibling matrix from a PRIOR scope: DARK row for a removed cluster
        stale = [
            "| Cluster | Status | Evidence |",
            "|---|---|---|",
            "| old-removed-module | DARK | left over from a prior scope |",
        ]
        (self.ws / "LEGACY_CAPABILITY_COVERAGE_MATRIX.md").write_text("\n".join(stale) + "\n")

        r = self.run_tool()

        self.assertEqual(r["verdict"], "pass-hunt-complete", r)
        dark_sig = next(s for s in r["signals"] if s["signal"] == "coverage-matrix-no-dark")
        self.assertTrue(dark_sig["ok"], dark_sig)
        # orphan row recorded as advisory detail, not a failure
        self.assertIn("orphan_dark_rows", dark_sig["detail"])

    def test_in_scope_dark_row_in_sibling_matrix_still_fails(self):
        """Honesty preserved: a DARK row whose cluster IS in the current
        SCOPE.md still fails the gate, even in a sibling matrix file."""
        self.add_full_clone()
        self.add_audit_deep()
        self.add_scope(clusters=("chain-watcher", "coop-exit"))
        self.add_sidecars(names=("chain-watcher", "coop-exit"))
        self.add_learn_report()
        rows = [
            "| Cluster | Status | Evidence |",
            "|---|---|---|",
            "| chain-watcher | COVERED | sidecar token match |",
            "| coop-exit | DARK | actually never hunted |",
        ]
        (self.ws / "HUNT_CAPABILITY_COVERAGE_MATRIX.md").write_text("\n".join(rows) + "\n")

        r = self.run_tool()

        self.assertEqual(r["verdict"], "fail-dark-families", r)


class TestMissingClusterCoverage(_Base):
    def test_uncovered_cluster(self):
        self.add_full_clone()
        self.add_audit_deep()
        self.add_coverage_matrix(dark=False)
        # SCOPE names an extra cluster with no sidecar/matrix row
        self.add_scope(clusters=("chain-watcher", "coop-exit", "signing", "orphan-module"))
        self.add_sidecars(names=("chain-watcher", "coop-exit", "signing"))
        self.add_learn_report()
        r = self.run_tool()
        self.assertEqual(r["verdict"], "fail-missing-cluster-coverage", r)
        cc = next(s for s in r["signals"] if s["signal"] == "cluster-coverage")
        self.assertIn("orphan-module", cc["detail"]["uncovered"])

    def test_title_scope_heading_does_not_hide_bullets(self):
        self.add_full_clone()
        self.add_audit_deep()
        (self.ws / "SCOPE.md").write_text("# Audit Scope\n- chain-watcher\n- coop-exit\n")
        self.add_coverage_matrix(dark=False)
        self.add_sidecars(names=("chain-watcher", "coop-exit"))
        self.add_learn_report()

        r = self.run_tool()

        self.assertEqual(r["verdict"], "pass-hunt-complete", r)
        cc = next(s for s in r["signals"] if s["signal"] == "cluster-coverage")
        self.assertEqual(cc["detail"]["clusters"], ["chain-watcher", "coop-exit"])

    def test_no_scope_file(self):
        self.add_full_clone()
        self.add_audit_deep()
        self.add_coverage_matrix(dark=False)
        # no SCOPE.md
        self.add_sidecars()
        self.add_learn_report()
        r = self.run_tool()
        self.assertEqual(r["verdict"], "fail-missing-cluster-coverage", r)


class TestNoArtifactMining(_Base):
    def test_sidecars_present_but_no_learn(self):
        self.add_full_clone()
        self.add_audit_deep()
        self.add_coverage_matrix(dark=False)
        self.add_scope()
        self.add_sidecars()
        # no learn report
        r = self.run_tool()
        self.assertEqual(r["verdict"], "fail-no-artifact-mining", r)

    def test_no_sidecars(self):
        self.add_full_clone()
        self.add_audit_deep()
        self.add_coverage_matrix(dark=False)
        # Scope only the clusters the matrix covers so cluster-coverage
        # PASSES via matrix rows; the genuine first failure is then
        # artifact-mining (no hunt_findings_sidecars/ dir at all).
        self.add_scope(clusters=("chain-watcher", "coop-exit"))
        self.add_learn_report()
        # deliberately no add_sidecars()
        r = self.run_tool()
        self.assertEqual(r["verdict"], "fail-no-artifact-mining", r)


class TestV2GenuineMiningReportNoSidecars(_Base):
    """FIX B: a GENUINE v2 agent-artifact-mining report credits artifact-mining
    even when hunt_findings_sidecars/ is absent (a clean workspace with 0
    sidecar findings is honest, not incomplete). A 0-artifacts run is genuine."""

    def _v2_report(self, total_artifacts, no_learning_reason):
        rep = self.ws / ".auditooor" / "agent_artifact_mining_report.json"
        rep.parent.mkdir(parents=True, exist_ok=True)
        rep.write_text(json.dumps({
            "schema_version": "auditooor.agent_artifact_mining.v2",
            "total_artifacts": total_artifacts,
            "no_learning_reason": no_learning_reason,
        }))

    def test_v2_report_with_artifacts_no_sidecars_passes(self):
        self.add_full_clone()
        self.add_audit_deep()
        self.add_coverage_matrix(dark=False)
        self.add_scope(clusters=("chain-watcher", "coop-exit"))
        self._v2_report(total_artifacts=1542, no_learning_reason=False)
        # deliberately no sidecars
        r = self.run_tool()
        self.assertEqual(r["verdict"], "pass-hunt-complete", r)
        sig = next(s for s in r["signals"] if s["signal"] == "artifact-mining")
        self.assertTrue(sig["ok"], sig)
        self.assertIn("clean workspace", sig["reason"])

    def test_v2_report_zero_artifacts_is_honest(self):
        # total_artifacts=0 + no_learning_reason=True: the miner ran and found
        # nothing to mine -> honest, not incomplete.
        self.add_full_clone()
        self.add_audit_deep()
        self.add_coverage_matrix(dark=False)
        self.add_scope(clusters=("chain-watcher", "coop-exit"))
        self._v2_report(total_artifacts=0, no_learning_reason=True)
        r = self.run_tool()
        self.assertEqual(r["verdict"], "pass-hunt-complete", r)
        sig = next(s for s in r["signals"] if s["signal"] == "artifact-mining")
        self.assertTrue(sig["ok"], sig)

    def test_legacy_nonv2_report_without_sidecars_still_fails(self):
        # A non-v2 stub report ({"mined":1}) without sidecars does NOT get the
        # v2-genuine credit (gate not weakened for the legacy stub case).
        self.add_full_clone()
        self.add_audit_deep()
        self.add_coverage_matrix(dark=False)
        self.add_scope(clusters=("chain-watcher", "coop-exit"))
        rep = self.ws / ".auditooor" / "agent_artifact_mining_report.json"
        rep.parent.mkdir(parents=True, exist_ok=True)
        rep.write_text('{"mined": 1}')
        r = self.run_tool()
        self.assertEqual(r["verdict"], "fail-no-artifact-mining", r)

    def test_v2_report_with_sidecars_lists_sidecar_first(self):
        # When BOTH a genuine v2 report and sidecars are present, the sidecar
        # dir is still listed first (back-compat with the legacy artifact list).
        self.add_full_clone()
        self.add_audit_deep()
        self.add_coverage_matrix(dark=False)
        self.add_scope()
        self.add_sidecars()
        self._v2_report(total_artifacts=5, no_learning_reason=False)
        r = self.run_tool()
        self.assertEqual(r["verdict"], "pass-hunt-complete", r)
        sig = next(s for s in r["signals"] if s["signal"] == "artifact-mining")
        self.assertTrue(sig["artifacts"][0].endswith("hunt_findings_sidecars"))


class TestAuditooorSidecarArtifactMining(_Base):
    def test_auditooor_sidecars_and_learning_report_count(self):
        self.add_full_clone()
        self.add_audit_deep()
        self.add_coverage_matrix(dark=False)
        self.add_scope()
        sc = self.ws / ".auditooor" / "hunt_findings_sidecars"
        sc.mkdir(parents=True, exist_ok=True)
        for name in ("chain-watcher", "coop-exit", "signing"):
            (sc / f"{name}.json").write_text("{}")
        report = self.ws / ".auditooor" / "agent_artifact_mining_report.json"
        report.write_text('{"total_artifacts": 3}')

        r = self.run_tool()

        self.assertEqual(r["verdict"], "pass-hunt-complete", r)
        artifact_signal = next(s for s in r["signals"] if s["signal"] == "artifact-mining")
        self.assertEqual(
            artifact_signal["artifacts"][0],
            str(sc.resolve()),
        )


class TestRebuttal(_Base):
    def test_all_rebuttal_flips_to_pass(self):
        # only failing signal is artifact-mining; rebut it
        self.add_full_clone()
        self.add_audit_deep()
        self.add_coverage_matrix(dark=False)
        self.add_scope()
        self.add_sidecars()
        # no learn report -> would fail artifact-mining
        rb = self.ws / ".auditooor"
        rb.mkdir(parents=True, exist_ok=True)
        (rb / "hunt_completeness_rebuttal.txt").write_text(
            "l35-rebuttal: artifact-mining: corpus ETL ran in shared pipeline, delta merged upstream\n"
        )
        r = self.run_tool()
        self.assertEqual(r["verdict"], "pass-hunt-complete", r)
        self.assertEqual(len(r["rebutted"]), 1)
        self.assertEqual(r["rebutted"][0]["signal"], "artifact-mining")

    def test_oversized_rebuttal_ignored(self):
        self.add_full_clone()
        self.add_audit_deep()
        self.add_coverage_matrix(dark=False)
        self.add_scope()
        self.add_sidecars()
        rb = self.ws / ".auditooor"
        rb.mkdir(parents=True, exist_ok=True)
        (rb / "hunt_completeness_rebuttal.txt").write_text(
            "l35-rebuttal: artifact-mining: " + ("x" * 250) + "\n"
        )
        r = self.run_tool()
        self.assertEqual(r["verdict"], "fail-no-artifact-mining", r)

    def test_bare_rebuttal_flips_all(self):
        self.add_full_clone()
        self.add_audit_deep()
        self.add_coverage_matrix(dark=False)
        self.add_scope()
        self.add_sidecars()
        rb = self.ws / ".auditooor"
        rb.mkdir(parents=True, exist_ok=True)
        (rb / "hunt_completeness_rebuttal.txt").write_text(
            "l35-rebuttal: release-tarball target with no upstream git history\n"
        )
        r = self.run_tool()
        self.assertEqual(r["verdict"], "pass-hunt-complete", r)


# r36-rebuttal: funnel-generic-fixes-wave3
class TestHuntProviderObligation(_Base):
    """Bug B regression: hunt_provider_obligation.json with
    status='orchestrator-dispatch-required' was silently ignored.

    Fix: check_hunt_provider_obligation reads the file and fails with
    fail-hunt-provider-obligation-unmet when status != 'completed'.
    """

    def _write_obligation(self, status: str, provider: str = "haiku-via-agent") -> None:
        a = self.ws / ".auditooor"
        a.mkdir(parents=True, exist_ok=True)
        (a / "hunt_provider_obligation.json").write_text(json.dumps({
            "schema": "auditooor.hunt_provider_obligation.v1",
            "hunt_provider": provider,
            "status": status,
            "reason": "test fixture",
            "next": ["dispatch each batch via Agent"],
        }))

    def test_absent_obligation_file_passes(self):
        """No hunt_provider_obligation.json = inline dispatch assumed."""
        self.add_all()
        obl = self.ws / ".auditooor" / "hunt_provider_obligation.json"
        if obl.exists():
            obl.unlink()
        r = self.run_tool()
        self.assertEqual(r["verdict"], "pass-hunt-complete", r)
        sig = next(s for s in r["signals"] if s["signal"] == "hunt-provider-obligation")
        self.assertTrue(sig["ok"], sig)
        self.assertFalse(sig["detail"].get("present", True))

    def test_orchestrator_dispatch_required_fails(self):
        """status='orchestrator-dispatch-required' must fail (was BUG: ignored)."""
        self.add_all()
        self._write_obligation("orchestrator-dispatch-required")
        r = self.run_tool()
        self.assertEqual(r["verdict"], "fail-hunt-provider-obligation-unmet", r)
        sig = next(s for s in r["signals"] if s["signal"] == "hunt-provider-obligation")
        self.assertFalse(sig["ok"], sig)
        self.assertEqual(sig["verdict"], "fail-hunt-provider-obligation-unmet")
        self.assertIn("orchestrator-dispatch-required", sig["reason"])

    def test_completed_status_passes(self):
        """status='completed' means dispatch happened; signal must pass."""
        self.add_all()
        self._write_obligation("completed")
        r = self.run_tool()
        self.assertEqual(r["verdict"], "pass-hunt-complete", r)
        sig = next(s for s in r["signals"] if s["signal"] == "hunt-provider-obligation")
        self.assertTrue(sig["ok"], sig)

    def test_residual_empty_with_pending_dispatch_instructions_fails(self):
        """A zero residual cannot green a queued-but-unexecuted hunt."""
        self.add_all()
        a = self.ws / ".auditooor"
        a.mkdir(parents=True, exist_ok=True)
        (a / "hunt_provider_obligation.json").write_text(json.dumps({
            "schema": "auditooor.hunt_provider_obligation.v1",
            "hunt_provider": "agent-via-orchestrator",
            "status": "residual-empty-no-hunt-required",
            "residual_surface_units": 0,
            "next": [
                "dispatch each _haiku_plan/agent_batch_*.md via Agent(model=sonnet)",
                "make mimo-corpus-mine WS=<ws>",
            ],
        }))
        r = self.run_tool()
        self.assertEqual(r["verdict"], "fail-hunt-provider-obligation-unmet", r)
        sig = next(s for s in r["signals"] if s["signal"] == "hunt-provider-obligation")
        self.assertFalse(sig["ok"], sig)
        self.assertIn("queued but never dispatched", sig["reason"])

    def test_unknown_non_completed_status_fails(self):
        """Any non-'completed' status must fail, not silently pass."""
        for status in ("pending", "queued", "in-progress", "dispatched-partial"):
            with self.subTest(status=status):
                self.setUp()
                self.add_all()
                self._write_obligation(status)
                r = self.run_tool()
                self.assertEqual(
                    r["verdict"], "fail-hunt-provider-obligation-unmet",
                    f"status={status!r} should have failed; got {r['verdict']!r}",
                )

    def test_obligation_fails_before_full_clone(self):
        """hunt-provider-obligation is checked before full-clone in signal order."""
        self.add_dedup_skip_set()
        self._write_obligation("orchestrator-dispatch-required")
        r = self.run_tool()
        self.assertEqual(r["verdict"], "fail-hunt-provider-obligation-unmet", r)

    def test_obligation_rebuttal_flips_signal(self):
        """The l35-rebuttal mechanism must also flip hunt-provider-obligation."""
        self.add_all()
        self._write_obligation("orchestrator-dispatch-required")
        a = self.ws / ".auditooor"
        (a / "hunt_completeness_rebuttal.txt").write_text(
            "l35-rebuttal: hunt-provider-obligation: dispatch ran via separate session\n"
        )
        r = self.run_tool()
        self.assertEqual(r["verdict"], "pass-hunt-complete", r)
        sig = next(s for s in r["signals"] if s["signal"] == "hunt-provider-obligation")
        self.assertEqual(sig["verdict"], "ok-rebuttal")

    def test_invalid_json_obligation_fails(self):
        """Unparseable hunt_provider_obligation.json must fail (fail-closed)."""
        self.add_all()
        a = self.ws / ".auditooor"
        a.mkdir(parents=True, exist_ok=True)
        (a / "hunt_provider_obligation.json").write_text("NOT JSON {{{")
        r = self.run_tool()
        self.assertEqual(r["verdict"], "fail-hunt-provider-obligation-unmet", r)

    def test_beanstalk_fixture_fails(self):
        """Exact beanstalk obligation payload must trigger
        fail-hunt-provider-obligation-unmet."""
        self.add_all()
        a = self.ws / ".auditooor"
        a.mkdir(parents=True, exist_ok=True)
        (a / "hunt_provider_obligation.json").write_text(json.dumps({
            "schema": "auditooor.hunt_provider_obligation.v1",
            "hunt_provider": "haiku-via-agent",
            "status": "orchestrator-dispatch-required",
            "reason": "deepseek/mimo unavailable",
            "next": [
                "dispatch each _haiku_plan/agent_batch_*.md via Agent(model=haiku)",
                "make mimo-corpus-mine WS=<ws>",
            ],
        }))
        r = self.run_tool()
        self.assertEqual(r["verdict"], "fail-hunt-provider-obligation-unmet", r)
        sig = next(s for s in r["signals"] if s["signal"] == "hunt-provider-obligation")
        self.assertIn("haiku-via-agent", sig["reason"])


class TestErrorAndExit(_Base):
    def test_missing_workspace_error(self):
        rc = hcc.main([str(self.ws / "does-not-exist"), "--json"])
        self.assertEqual(rc, 2)

    def test_exit_codes_via_main(self):
        # pass -> 0
        self.add_all()
        self.assertEqual(hcc.main([str(self.ws)]), 0)

    def test_fail_exit_one(self):
        # only audit-deep present -> fail -> exit 1
        self.add_full_clone()
        self.add_coverage_matrix()
        self.add_scope()
        self.add_sidecars()
        self.add_learn_report()
        self.assertEqual(hcc.main([str(self.ws)]), 1)

    def test_cli_subprocess_json(self):
        self.add_all()
        proc = subprocess.run(
            ["python3", str(TOOL), str(self.ws), "--json"],
            capture_output=True, text=True,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["verdict"], "pass-hunt-complete")
        self.assertEqual(payload["schema"], "auditooor.l35_hunt_completeness.v1")


class TestFirstFailureOrdering(_Base):
    def test_first_failing_signal_is_top_verdict(self):
        # nothing present at all: dedup-first (signal 0) fails first
        r = self.run_tool()
        self.assertEqual(r["verdict"], "fail-no-dedup-skip-set", r)
        # every signal should be reported as a failure
        self.assertTrue(len(r["failures"]) >= 6)

    def test_shallow_clone_is_top_verdict_when_dedup_present(self):
        # with dedup skip-set present, the next failing signal (a) surfaces
        self.add_dedup_skip_set()
        r = self.run_tool()
        self.assertEqual(r["verdict"], "fail-shallow-clone", r)


class TestCodifiedRuleWiring(unittest.TestCase):
    """Lock the L35 codified-rule artifacts: doc + inventory row + Makefile."""

    REPO = Path(__file__).resolve().parents[2]

    def test_codified_rule_doc_present(self):
        docs = list((self.REPO / "docs").glob("RULE_L35_*HUNT_COMPLETENESS*.md"))
        self.assertTrue(docs, "L35 codified rule doc missing under docs/")
        text = docs[0].read_text(encoding="utf-8")
        self.assertIn("L35-HUNT-COMPLETENESS", text)
        self.assertIn("auditooor.l35_hunt_completeness.v1", text)
        for v in (
            "fail-shallow-clone", "fail-no-audit-deep", "fail-no-coverage-matrix",
            "fail-dark-families", "fail-missing-cluster-coverage",
            "fail-no-artifact-mining",
        ):
            self.assertIn(v, text, f"verdict {v} not documented")

    def test_inventory_row_present_and_valid(self):
        inv = self.REPO / "reference" / "r_rules_inventory.jsonl"
        rows = []
        for line in inv.read_text(encoding="utf-8").splitlines():
            if line.strip():
                rows.append(json.loads(line))
        l35 = [r for r in rows if r.get("rule_id") == "L35"]
        self.assertEqual(len(l35), 1, "exactly one L35 inventory row expected")
        row = l35[0]
        self.assertEqual(row["check_name"], "L35-HUNT-COMPLETENESS")
        self.assertEqual(row["tool_path"], "tools/hunt-completeness-check.py")
        self.assertTrue(row["tool_exists"])
        self.assertTrue(row["fail_closed"])
        self.assertTrue((self.REPO / row["tool_path"]).is_file())

    def test_makefile_target_present(self):
        mk = (self.REPO / "Makefile").read_text(encoding="utf-8")
        self.assertIn("hunt-complete:", mk)
        self.assertIn("tools/hunt-completeness-check.py", mk)


if __name__ == "__main__":
    unittest.main()
