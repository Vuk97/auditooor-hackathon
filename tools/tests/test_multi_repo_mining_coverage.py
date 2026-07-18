"""gapA-multirepo-mining guard tests.

Cover the reconcile / synthesize helpers on the DRIVER
(tools/audit-target-commit-mining.py) and the standalone fail-closed enforcement
tool (tools/multi-repo-mining-coverage-check.py).

The NON-VACUOUS NEGATIVE canary is
``test_two_distinct_upstream_repos_one_unmined_FAILS``: if the reconcile /
coverage logic were a no-op (always pass / ignore in_scope) it fails.
"""

from __future__ import annotations

import importlib.util
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest


REPO = pathlib.Path(__file__).resolve().parents[2]
DRIVER = REPO / "tools" / "audit-target-commit-mining.py"
CHECK = REPO / "tools" / "multi-repo-mining-coverage-check.py"


def _load(name: str, path: pathlib.Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"unable to load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


DRIVER_MOD = _load("audit_target_commit_mining", DRIVER)
CHECK_MOD = _load("multi_repo_mining_coverage_check", CHECK)


def _git(repo: pathlib.Path, args: list[str]) -> None:
    subprocess.run(
        ["git", "-C", str(repo), *args],
        text=True,
        capture_output=True,
        check=True,
    )


def _init_repo_with_origin(repo: pathlib.Path, owner_repo: str) -> None:
    """git init a dir + set a fake GitHub origin remote + one commit."""
    repo.mkdir(parents=True, exist_ok=True)
    _git(repo, ["init"])
    _git(repo, ["remote", "add", "origin", f"https://github.com/{owner_repo}.git"])
    (repo / "README.md").write_text("seed\n", encoding="utf-8")
    _git(repo, ["add", "."])
    _git(
        repo,
        [
            "-c", "user.name=Auditooor Test",
            "-c", "user.email=audit@example.invalid",
            "commit", "-m", "seed",
        ],
    )


def _write_scope(ws: pathlib.Path, in_scope: list[str], pin: str = "") -> None:
    payload: dict = {"in_scope": in_scope}
    if pin:
        payload["audit_pin_sha"] = pin
    (ws / "scope.json").write_text(json.dumps(payload, indent=2), encoding="utf-8")


def _write_manifest(ws: pathlib.Path, rows: list[dict], extra: dict | None = None) -> None:
    """Write a mining_rounds/<date>/commit_mining_manifest.json fixture."""
    rd = ws / "mining_rounds" / "2026-06-19-bidirectional-commit-mining"
    rd.mkdir(parents=True, exist_ok=True)
    payload = {
        "schema": "auditooor.audit_target_commit_mining_manifest.v1",
        "workspace": str(ws),
        "mode": "bidirectional",
        "window": 90,
        "rows": rows,
    }
    if extra:
        payload.update(extra)
    (rd / "commit_mining_manifest.json").write_text(
        json.dumps(payload, indent=2), encoding="utf-8"
    )


def _write_mining_report(ws: pathlib.Path, name: str, commits_scanned: int = 30) -> str:
    """Write a per-repo *_git_commits_mining.json with genuine-ran evidence."""
    rd = ws / "mining_rounds" / "2026-06-19-bidirectional-commit-mining"
    rd.mkdir(parents=True, exist_ok=True)
    p = rd / name
    p.write_text(
        json.dumps(
            {
                "schema": "auditooor.git_commits_mining.v1",
                "commits_scanned": commits_scanned,
                "security_fix_count": 1,
                "commits": [],
                "shaped_commits_index": [],
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    return str(p)


class TestOptimismMonorepoPasses(unittest.TestCase):
    def test_optimism_real_workspace_single_monorepo_passes(self) -> None:
        """4 in_scope roots all under ONE checkout (ethereum-optimism/optimism);
        one mining row + genuine report -> required={the monorepo}, missing empty,
        unresolved empty -> pass. Vendored-monorepo is NOT a false positive."""
        with tempfile.TemporaryDirectory() as td:
            ws = pathlib.Path(td)
            src = ws / "src"
            _init_repo_with_origin(src, "ethereum-optimism/optimism")
            # the 4 in_scope source roots all live under the one checkout
            for rel in (
                "packages/contracts-bedrock/src",
                "op-node",
                "op-dispute-mon",
                "rust/op-reth",
            ):
                (src / rel).mkdir(parents=True, exist_ok=True)
            _write_scope(
                ws,
                [
                    "src/packages/contracts-bedrock/src",
                    "src/op-node",
                    "src/op-dispute-mon",
                    "src/rust/op-reth",
                ],
            )
            report = _write_mining_report(
                ws, "ethereum-optimism_optimism_go_git_commits_mining.json"
            )
            _write_manifest(
                ws,
                [{
                    "owner_repo": "ethereum-optimism/optimism",
                    "status": "ok",
                    "output_path": report,
                }],
            )

            recon = DRIVER_MOD.reconcile_targets_with_inscope(ws, [])
            self.assertEqual(
                recon["inscope_owner_repos"], {"ethereum-optimism/optimism"}
            )
            self.assertEqual(recon["missing_from_targets"], {"ethereum-optimism/optimism"})
            self.assertEqual(recon["unresolved_roots"], [])

            res = CHECK_MOD.evaluate(ws)
            self.assertEqual(res["verdict"], "pass-multi-repo-mining-coverage")
            self.assertEqual(res["covered"], ["ethereum-optimism/optimism"])
            self.assertEqual(res["uncovered"], [])


class TestTwoDistinctReposOneUnmined(unittest.TestCase):
    def test_two_distinct_upstream_repos_one_unmined_FAILS(self) -> None:
        """NON-VACUOUS canary. Two in_scope roots -> two DISTINCT owner/repos,
        manifest only mines repoA -> fail naming repoB. If reconcile/coverage
        were a no-op this test fails."""
        with tempfile.TemporaryDirectory() as td:
            ws = pathlib.Path(td)
            top_a = ws / "src" / "repoA"
            top_b = ws / "src" / "repoB"
            _init_repo_with_origin(top_a, "orgA/repoA")
            _init_repo_with_origin(top_b, "orgB/repoB")
            _write_scope(ws, ["src/repoA", "src/repoB"])

            report = _write_mining_report(ws, "orgA_repoA_go_git_commits_mining.json")
            _write_manifest(
                ws,
                [{"owner_repo": "orgA/repoA", "status": "ok", "output_path": report}],
            )

            recon = DRIVER_MOD.reconcile_targets_with_inscope(ws, [])
            self.assertEqual(recon["missing_from_targets"], {"orgA/repoA", "orgB/repoB"})

            res = CHECK_MOD.evaluate(ws)
            self.assertTrue(
                res["verdict"].startswith("fail-"),
                msg=f"expected fail, got {res['verdict']}: {res['reason']}",
            )
            self.assertIn("orgB/repoB", res["uncovered"])
            self.assertIn("orgB/repoB", res["reason"])
            self.assertNotIn("orgA/repoA", res["uncovered"])


class TestExplicitLoggedSkipSatisfies(unittest.TestCase):
    def test_explicit_logged_skip_satisfies_coverage(self) -> None:
        """repoB has NO mining result but a logged skipped_unresolved_upstream row
        -> warn (covered-by-explicit-skip), NOT fail. No-silent-cap."""
        with tempfile.TemporaryDirectory() as td:
            ws = pathlib.Path(td)
            top_a = ws / "src" / "repoA"
            top_b = ws / "src" / "repoB"
            _init_repo_with_origin(top_a, "orgA/repoA")
            _init_repo_with_origin(top_b, "orgB/repoB")
            _write_scope(ws, ["src/repoA", "src/repoB"])

            report = _write_mining_report(ws, "orgA_repoA_go_git_commits_mining.json")
            _write_manifest(
                ws,
                [
                    {"owner_repo": "orgA/repoA", "status": "ok", "output_path": report},
                    {
                        "owner_repo": "orgB/repoB",
                        "status": "skipped_unresolved_upstream",
                        "output_path": "",
                        "reason": "no gh auth available",
                    },
                ],
            )

            res = CHECK_MOD.evaluate(ws)
            self.assertEqual(res["verdict"], "warn-multi-repo-mining-coverage")
            self.assertIn("orgB/repoB", res["skip_logged"])
            self.assertEqual(res["uncovered"], [])

    def test_skipped_no_gh_auth_is_logged_skip(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            ws = pathlib.Path(td)
            top_a = ws / "src" / "repoA"
            top_b = ws / "src" / "repoB"
            _init_repo_with_origin(top_a, "orgA/repoA")
            _init_repo_with_origin(top_b, "orgB/repoB")
            _write_scope(ws, ["src/repoA", "src/repoB"])
            report = _write_mining_report(ws, "orgA_repoA_go_git_commits_mining.json")
            _write_manifest(
                ws,
                [
                    {"owner_repo": "orgA/repoA", "status": "ok", "output_path": report},
                    {
                        "owner_repo": "orgB/repoB",
                        "status": "skipped_no_gh_auth",
                        "output_path": "",
                    },
                ],
            )
            res = CHECK_MOD.evaluate(ws)
            self.assertEqual(res["verdict"], "warn-multi-repo-mining-coverage")


class TestUnresolvedRootLogged(unittest.TestCase):
    def test_unresolved_root_is_logged_not_silent(self) -> None:
        """in_scope root NOT inside any git checkout -> unresolved_roots with a
        concrete reason; appears in verdict detail, never dropped."""
        with tempfile.TemporaryDirectory() as td:
            ws = pathlib.Path(td)
            # a plain dir, no .git up-tree
            (ws / "plain_src").mkdir(parents=True, exist_ok=True)
            _write_scope(ws, ["plain_src"])

            resolved = DRIVER_MOD.inscope_owner_repos(ws)
            self.assertEqual(resolved["owner_repos"], {})
            self.assertEqual(len(resolved["unresolved_roots"]), 1)
            ur = resolved["unresolved_roots"][0]
            self.assertEqual(ur["root"], "plain_src")
            self.assertIn("no git toplevel", ur["reason"])

            recon = DRIVER_MOD.reconcile_targets_with_inscope(ws, [])
            roots = [r["root"] for r in recon["unresolved_roots"]]
            self.assertIn("plain_src", roots)

            # No manifest logging this -> fail (unlogged unresolved root).
            res = CHECK_MOD.evaluate(ws)
            self.assertTrue(res["verdict"].startswith("fail-"))
            self.assertIn("plain_src", res["reason"])

    def test_unresolved_root_logged_in_manifest_warns(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            ws = pathlib.Path(td)
            (ws / "plain_src").mkdir(parents=True, exist_ok=True)
            _write_scope(ws, ["plain_src"])
            _write_manifest(
                ws,
                [{
                    "owner_repo": "",
                    "status": "skipped_unresolved_upstream",
                    "inscope_root": "plain_src",
                    "output_path": "",
                }],
                extra={"unresolved_inscope_roots": [
                    {"root": "plain_src", "reason": "no git toplevel"}
                ]},
            )
            res = CHECK_MOD.evaluate(ws)
            self.assertEqual(res["verdict"], "warn-multi-repo-mining-coverage")
            self.assertEqual(res["unlogged_unresolved_roots"], [])


class TestDriverSynthesizesMissingTarget(unittest.TestCase):
    def test_driver_synthesizes_missing_target(self) -> None:
        """reconcile + synthesize on the two-repo fixture: targets.tsv lists only
        repoA, but the post-reconcile target list contains BOTH repoA and repoB.
        Silent-skip closed at mine time."""
        with tempfile.TemporaryDirectory() as td:
            ws = pathlib.Path(td)
            top_a = ws / "src" / "repoA"
            top_b = ws / "src" / "repoB"
            _init_repo_with_origin(top_a, "orgA/repoA")
            _init_repo_with_origin(top_b, "orgB/repoB")
            _write_scope(ws, ["src/repoA", "src/repoB"], pin="a" * 40)
            (ws / "targets.tsv").write_text(
                "https://github.com/orgA/repoA.git\t" + "a" * 40 + "\trepoA\n",
                encoding="utf-8",
            )

            targets = DRIVER_MOD.load_targets(ws)
            self.assertEqual({t.owner_repo for t in targets}, {"orgA/repoA"})

            recon = DRIVER_MOD.reconcile_targets_with_inscope(ws, targets)
            self.assertEqual(recon["missing_from_targets"], {"orgB/repoB"})

            synth = DRIVER_MOD.synthesize_missing_targets(ws, targets, recon, "a" * 40)
            self.assertEqual(
                {t.owner_repo for t in synth}, {"orgA/repoA", "orgB/repoB"}
            )


class TestNoScopeJsonFailSafe(unittest.TestCase):
    def test_no_scope_json_fail_safe(self) -> None:
        """No scope.json / no in_scope -> inscope_owner_repos {}; reconcile leaves
        target set unchanged; coverage-check returns pass-or-na (back-compat)."""
        with tempfile.TemporaryDirectory() as td:
            ws = pathlib.Path(td)
            resolved = DRIVER_MOD.inscope_owner_repos(ws)
            self.assertEqual(resolved["owner_repos"], {})
            self.assertEqual(resolved["unresolved_roots"], [])

            recon = DRIVER_MOD.reconcile_targets_with_inscope(ws, [])
            self.assertEqual(recon["target_owner_repos"], set())
            self.assertEqual(recon["missing_from_targets"], set())

            res = CHECK_MOD.evaluate(ws)
            self.assertEqual(res["verdict"], "pass-multi-repo-mining-coverage")
            self.assertTrue(res.get("na"))

    def test_empty_in_scope_is_na(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            ws = pathlib.Path(td)
            _write_scope(ws, [])
            res = CHECK_MOD.evaluate(ws)
            self.assertEqual(res["verdict"], "pass-multi-repo-mining-coverage")
            self.assertTrue(res.get("na"))


if __name__ == "__main__":
    unittest.main()
