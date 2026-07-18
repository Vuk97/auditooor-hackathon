#!/usr/bin/env python3
"""Tests for tools/agent-preflight-check.py.

Hermetic: each test builds a throwaway git repo with a fabricated
``origin/main`` ref, applies the foot-gun in question on a feature branch,
and asserts the corresponding check FAILS / PASSES / SKIPS.

Coverage map (one positive + one negative per mechanical check):

  fixture_path
    - test_fixture_path_pass_canonical    canonical detectors/test_fixtures/.sol → PASS
    - test_fixture_path_fail_patterns_dir patterns/fixtures/.sol           → FAIL

  fixture_comment_leak
    - test_fixture_comment_leak_pass_neutral   neutral comments → PASS
    - test_fixture_comment_leak_fail_vuln_tag  // VULN comment   → FAIL

  standalone_md
    - test_standalone_md_pass_existing_edit   modified existing → PASS
    - test_standalone_md_fail_new_root_doc    new root .md      → FAIL
    - test_standalone_md_pass_allowlisted     new case_study/   → PASS
    - test_standalone_md_pass_exact_roadmap   canonical V4 doc  → PASS

  tier_a_promotion
    - test_tier_a_pass_with_noise_count    + tier: A + corpus_noise_count → PASS
    - test_tier_a_fail_without_noise_count + tier: A alone                → FAIL

  gh_api_placeholder
    - test_gh_api_pass_curly_braces  gh api repos/{owner}/{repo}/... → PASS
    - test_gh_api_fail_colon_style   gh api repos/:owner/:repo/...   → FAIL  # preflight-allow: gh_api_placeholder

  verified_push
    - test_verified_push_skip_no_network  --no-network → SKIP
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "tools" / "agent-preflight-check.py"


def _git(cwd: Path, *args: str) -> str:
    env = {
        "GIT_AUTHOR_NAME": "test",
        "GIT_AUTHOR_EMAIL": "test@example.com",
        "GIT_COMMITTER_NAME": "test",
        "GIT_COMMITTER_EMAIL": "test@example.com",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_SYSTEM": "/dev/null",
        "PATH": os.environ.get("PATH", ""),
        "HOME": str(cwd),
    }
    proc = subprocess.run(
        ["git", *args], cwd=str(cwd), env=env,
        capture_output=True, text=True, check=True,
    )
    return proc.stdout.strip()


def _build_feature_repo(tmp: Path) -> Path:
    """Create origin + work clone with a baseline commit on main and a
    feature branch checked out in work/.
    Returns the work/ path."""
    origin = tmp / "origin"
    work = tmp / "work"
    origin.mkdir()
    _git(origin, "init", "--initial-branch=main", ".")
    (origin / "README.md").write_text("seed\n")
    _git(origin, "add", "README.md")
    _git(origin, "commit", "-m", "initial")

    subprocess.run(
        ["git", "clone", str(origin), str(work)],
        check=True, capture_output=True,
        env={**os.environ,
             "GIT_CONFIG_GLOBAL": "/dev/null",
             "GIT_CONFIG_SYSTEM": "/dev/null"},
    )
    _git(work, "config", "user.name", "test")
    _git(work, "config", "user.email", "test@example.com")
    _git(work, "checkout", "-b", "feature")
    return work


def _commit(repo: Path, rel: str, content: str, msg: str) -> None:
    p = repo / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content)
    _git(repo, "add", "-f", rel)  # -f because some paths are gitignored in real repo
    _git(repo, "commit", "-m", msg)


def _run_preflight(
    repo: Path,
    *checks: str,
    no_network: bool = True,
    base: str = "origin/main",
) -> subprocess.CompletedProcess:
    args = [sys.executable, str(SCRIPT),
            "--repo", str(repo),
            "--base", base,
            "--json"]
    if no_network:
        args.append("--no-network")
    for c in checks:
        args.extend(["--check", c])
    return subprocess.run(args, capture_output=True, text=True)


def _load_results(proc: subprocess.CompletedProcess) -> dict:
    assert proc.stdout, f"no stdout; stderr={proc.stderr}"
    return json.loads(proc.stdout)


def _check(results: dict, name: str) -> dict:
    matches = [r for r in results["results"] if r["check"] == name]
    assert matches, f"check {name!r} not in results: {results}"
    return matches[0]


# ---- fixture_path ----------------------------------------------------------


class FixturePathTest(unittest.TestCase):
    def test_fixture_path_pass_canonical(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            work = _build_feature_repo(Path(td))
            _commit(work, "detectors/test_fixtures/foo_clean.sol",
                    "contract Foo {}\n", "add canonical fixture")
            proc = _run_preflight(work, "fixture_path")
            results = _load_results(proc)
            r = _check(results, "fixture_path")
            self.assertEqual(r["status"], "PASS",
                             f"got {r['status']}: {r['evidence']}")
            self.assertEqual(proc.returncode, 0)

    def test_fixture_path_fail_patterns_dir(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            work = _build_feature_repo(Path(td))
            _commit(work, "patterns/fixtures/bar_vulnerable.sol",
                    "contract Bar {}\n", "add bad-location fixture")
            proc = _run_preflight(work, "fixture_path")
            results = _load_results(proc)
            r = _check(results, "fixture_path")
            self.assertEqual(r["status"], "FAIL", f"evidence={r['evidence']}")
            self.assertTrue(any("patterns/fixtures/bar_vulnerable.sol" in ev
                                for ev in r["evidence"]))
            self.assertEqual(proc.returncode, 1)


# ---- fixture_comment_leak --------------------------------------------------


class FixtureCommentLeakTest(unittest.TestCase):
    def test_fixture_comment_leak_pass_neutral(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            work = _build_feature_repo(Path(td))
            body = (
                "contract Foo {\n"
                "  // reserves a trailing array of unused slots\n"
                "  uint256[50] __gap;\n"
                "}\n"
            )
            _commit(work, "detectors/test_fixtures/neutral_clean.sol", body,
                    "add fixture with neutral comments")
            proc = _run_preflight(work, "fixture_comment_leak")
            r = _check(_load_results(proc), "fixture_comment_leak")
            self.assertEqual(r["status"], "PASS",
                             f"got {r['status']}: {r['evidence']}")

    def test_fixture_comment_leak_fail_vuln_tag(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            work = _build_feature_repo(Path(td))
            body = (
                "contract Foo {\n"
                "  // VULN: missing access control\n"
                "  function pwn() external {}\n"
                "}\n"
            )
            _commit(work, "detectors/test_fixtures/leaky_vulnerable.sol", body,
                    "add fixture with leaky comment")
            proc = _run_preflight(work, "fixture_comment_leak")
            r = _check(_load_results(proc), "fixture_comment_leak")
            self.assertEqual(r["status"], "FAIL", f"evidence={r['evidence']}")
            joined = "\n".join(r["evidence"])
            self.assertIn("leaky_vulnerable.sol", joined)
            self.assertEqual(proc.returncode, 1)


# ---- standalone_md ---------------------------------------------------------


class StandaloneMdTest(unittest.TestCase):
    def test_standalone_md_pass_existing_edit(self) -> None:
        """Modifying README.md (already exists) is fine — only ADDED .md is flagged."""
        with tempfile.TemporaryDirectory() as td:
            work = _build_feature_repo(Path(td))
            (work / "README.md").write_text("seed\nupdated\n")
            _git(work, "add", "README.md")
            _git(work, "commit", "-m", "edit README")
            proc = _run_preflight(work, "standalone_md")
            r = _check(_load_results(proc), "standalone_md")
            self.assertEqual(r["status"], "PASS",
                             f"got {r['status']}: {r['evidence']}")

    def test_standalone_md_fail_new_root_doc(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            work = _build_feature_repo(Path(td))
            _commit(work, "REPORT.md", "# Report\n", "add new root doc")
            proc = _run_preflight(work, "standalone_md")
            r = _check(_load_results(proc), "standalone_md")
            self.assertEqual(r["status"], "FAIL", f"evidence={r['evidence']}")
            joined = "\n".join(r["evidence"])
            self.assertIn("REPORT.md", joined)
            self.assertEqual(proc.returncode, 1)

    def test_standalone_md_pass_allowlisted(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            work = _build_feature_repo(Path(td))
            _commit(work, "case_study/engagement_x_finding.md",
                    "# Finding\n", "add case study")
            proc = _run_preflight(work, "standalone_md")
            r = _check(_load_results(proc), "standalone_md")
            self.assertEqual(r["status"], "PASS",
                             f"got {r['status']}: {r['evidence']}")

    def test_standalone_md_pass_exact_roadmap(self) -> None:
        """The active Codex-owned roadmap is an exact exception, not docs/*."""
        with tempfile.TemporaryDirectory() as td:
            work = _build_feature_repo(Path(td))
            _commit(work, "docs/ROADMAP_10_OF_10_V4.md",
                    "# Roadmap\n", "add exact roadmap")
            proc = _run_preflight(work, "standalone_md")
            r = _check(_load_results(proc), "standalone_md")
            self.assertEqual(r["status"], "PASS",
                             f"got {r['status']}: {r['evidence']}")

    def test_standalone_md_pass_test_fixture(self) -> None:
        """Markdown fixtures under tools/tests/fixtures are test inputs, not docs."""
        with tempfile.TemporaryDirectory() as td:
            work = _build_feature_repo(Path(td))
            _commit(work, "tools/tests/fixtures/production_path/case.md",
                    "# Fixture\n", "add markdown fixture")
            proc = _run_preflight(work, "standalone_md")
            r = _check(_load_results(proc), "standalone_md")
            self.assertEqual(r["status"], "PASS",
                             f"got {r['status']}: {r['evidence']}")


# ---- tier_a_promotion ------------------------------------------------------


class TierAPromotionTest(unittest.TestCase):
    def _make_registry(self, work: Path) -> None:
        registry = (
            "version: 1\n"
            "tiers:\n"
            "  some-detector:\n"
            "    tier: E\n"
            "    reason: 'wave-1'\n"
        )
        _commit(work, "detectors/_tier_registry.yaml", registry,
                "seed tier registry")

    def test_tier_a_pass_with_noise_count(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            work = _build_feature_repo(Path(td))
            self._make_registry(work)
            promoted = (
                "version: 1\n"
                "tiers:\n"
                "  some-detector:\n"
                "    tier: A\n"
                "    corpus_noise_count: 0\n"
                "    reason: 'wave-1, baseline noise probe = 0'\n"
            )
            (work / "detectors" / "_tier_registry.yaml").write_text(promoted)
            _git(work, "add", "detectors/_tier_registry.yaml")
            _git(work, "commit", "-m", "promote some-detector E -> A with noise probe")
            proc = _run_preflight(work, "tier_a_promotion")
            r = _check(_load_results(proc), "tier_a_promotion")
            self.assertEqual(r["status"], "PASS",
                             f"got {r['status']}: {r['evidence']}")

    def test_tier_a_fail_without_noise_count(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            work = _build_feature_repo(Path(td))
            self._make_registry(work)
            promoted = (
                "version: 1\n"
                "tiers:\n"
                "  some-detector:\n"
                "    tier: A\n"
                "    reason: 'wave-1'\n"
            )
            (work / "detectors" / "_tier_registry.yaml").write_text(promoted)
            _git(work, "add", "detectors/_tier_registry.yaml")
            _git(work, "commit", "-m", "promote some-detector E -> A (no noise probe)")
            proc = _run_preflight(work, "tier_a_promotion")
            r = _check(_load_results(proc), "tier_a_promotion")
            self.assertEqual(r["status"], "FAIL", f"evidence={r['evidence']}")
            self.assertEqual(proc.returncode, 1)


# ---- gh_api_placeholder ----------------------------------------------------


class GhApiPlaceholderTest(unittest.TestCase):
    def test_gh_api_pass_curly_braces(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            work = _build_feature_repo(Path(td))
            _commit(work, "tools/foo.sh",
                    "#!/usr/bin/env bash\n"
                    "gh api repos/{owner}/{repo}/git/refs/heads/main\n",
                    "add good shell script")
            proc = _run_preflight(work, "gh_api_placeholder")
            r = _check(_load_results(proc), "gh_api_placeholder")
            self.assertEqual(r["status"], "PASS",
                             f"got {r['status']}: {r['evidence']}")

    def test_gh_api_fail_colon_style(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            work = _build_feature_repo(Path(td))
            # The fixture below intentionally contains the bad pattern; the
            # split-string form keeps preflight from flagging *this* file.
            bad_line = "gh api repos/" + ":owner/:repo/git/refs/heads/main"
            _commit(work, "tools/bar.sh",
                    f"#!/usr/bin/env bash\n{bad_line}\n",
                    "add bad shell script")
            proc = _run_preflight(work, "gh_api_placeholder")
            r = _check(_load_results(proc), "gh_api_placeholder")
            self.assertEqual(r["status"], "FAIL", f"evidence={r['evidence']}")
            joined = "\n".join(r["evidence"])
            self.assertIn("tools/bar.sh", joined)
            self.assertEqual(proc.returncode, 1)


# ---- verified_push ---------------------------------------------------------


class VerifiedPushTest(unittest.TestCase):
    def test_verified_push_skip_no_network(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            work = _build_feature_repo(Path(td))
            proc = _run_preflight(work, "verified_push", no_network=True)
            r = _check(_load_results(proc), "verified_push")
            self.assertEqual(r["status"], "SKIP",
                             f"got {r['status']}: {r['evidence']}")
            self.assertEqual(proc.returncode, 0)

    def test_verified_push_paragraph_present_on_remote_mismatch(self) -> None:
        """Codex test #3 — V5-P0-19: when LOCAL and REMOTE diverge, the
        FAIL evidence must include a 1-paragraph explanation of WHY the
        mismatch matters AND a suggested fix command. Snapshot the output
        text so the paragraph cannot be silently removed."""
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "agent_preflight_check", str(SCRIPT)
        )
        mod = importlib.util.module_from_spec(spec)
        sys.modules["agent_preflight_check"] = mod
        spec.loader.exec_module(mod)

        with tempfile.TemporaryDirectory() as td:
            work = _build_feature_repo(Path(td))
            bin_dir = Path(td) / "bin"
            bin_dir.mkdir()
            gh_shim = bin_dir / "gh"
            gh_shim.write_text(
                "#!/usr/bin/env bash\n"
                "echo deadbeef0123456789012345678901234567890a\n"
            )
            gh_shim.chmod(0o755)

            saved_path = os.environ["PATH"]
            try:
                os.environ["PATH"] = str(bin_dir) + os.pathsep + saved_path
                subprocess.run(
                    ["git", "remote", "set-url", "origin",
                     "https://github.com/example/example.git"],
                    cwd=work, check=True, capture_output=True,
                )
                r = mod.check_verified_push(
                    work, branch="feature", no_network=False
                )
            finally:
                os.environ["PATH"] = saved_path

            self.assertEqual(r.status, "FAIL",
                             f"expected FAIL, got {r.status}: {r.evidence}")
            joined = "\n".join(r.evidence)
            self.assertIn("V5-P0-19", joined)
            self.assertIn("foot-gun #10", joined.lower())
            self.assertIn("force-push", joined.lower())
            self.assertIn("suggested fix:", joined)


class VerifiedPushStandaloneToolTest(unittest.TestCase):
    """V5-P0-19 — `tools/verified-push-check.py` is the standalone gate
    operators wire into their PR-create workflow. Smoke-test invocation
    paths via PATH-shimmed `gh`."""

    def test_no_network_returns_2(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            work = _build_feature_repo(Path(td))
            tool = ROOT / "tools" / "verified-push-check.py"
            proc = subprocess.run(
                [sys.executable, str(tool),
                 "--repo", str(work), "--branch", "feature",
                 "--no-network", "--json"],
                capture_output=True, text=True,
            )
            self.assertEqual(proc.returncode, 2,
                             f"stdout: {proc.stdout}\nstderr: {proc.stderr}")
            doc = json.loads(proc.stdout)
            self.assertEqual(doc["status"], "FAIL")

    def test_remote_mismatch_returns_1_with_explanation(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            work = _build_feature_repo(Path(td))
            bin_dir = Path(td) / "bin"
            bin_dir.mkdir()
            gh_shim = bin_dir / "gh"
            gh_shim.write_text(
                "#!/usr/bin/env bash\n"
                "echo deadbeef0123456789012345678901234567890a\n"
            )
            gh_shim.chmod(0o755)
            saved_path = os.environ["PATH"]
            tool = ROOT / "tools" / "verified-push-check.py"
            try:
                os.environ["PATH"] = str(bin_dir) + os.pathsep + saved_path
                subprocess.run(
                    ["git", "remote", "set-url", "origin",
                     "https://github.com/example/example.git"],
                    cwd=work, check=True, capture_output=True,
                )
                proc = subprocess.run(
                    [sys.executable, str(tool),
                     "--repo", str(work), "--branch", "feature", "--json"],
                    capture_output=True, text=True,
                )
            finally:
                os.environ["PATH"] = saved_path
            self.assertEqual(proc.returncode, 1,
                             f"stdout: {proc.stdout}\nstderr: {proc.stderr}")
            doc = json.loads(proc.stdout)
            self.assertEqual(doc["status"], "FAIL")
            joined = "\n".join(doc["evidence"])
            self.assertIn("V5-P0-19", joined)
            self.assertIn("foot-gun #10", joined.lower())


# ---- aggregate behaviour ---------------------------------------------------


class AggregateExitCodeTest(unittest.TestCase):
    def test_clean_workspace_exits_zero(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            work = _build_feature_repo(Path(td))
            # Touch nothing controversial.
            _commit(work, "src/legit.py",
                    "# clean addition\nprint('hi')\n",
                    "add a benign python file")
            proc = _run_preflight(work)
            self.assertEqual(proc.returncode, 0,
                             f"expected 0, got {proc.returncode}\n"
                             f"stdout: {proc.stdout}\nstderr: {proc.stderr}")

    def test_any_fail_exits_one(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            work = _build_feature_repo(Path(td))
            _commit(work, "patterns/fixtures/bad.sol",
                    "contract Bad {}\n", "trigger fixture_path FAIL")
            proc = _run_preflight(work)
            self.assertEqual(proc.returncode, 1,
                             f"expected 1, got {proc.returncode}\n"
                             f"stdout: {proc.stdout}\nstderr: {proc.stderr}")


if __name__ == "__main__":
    unittest.main()
