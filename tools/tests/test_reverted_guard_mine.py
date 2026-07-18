"""test_reverted_guard_mine — DETECTOR-CODIFY-1 Pattern 1 unit tests.

Tests the Tier-6 backward-mine class (b) detector via a synthetic git
repo built in a tempdir. Stdlib-only — no network calls, no external
deps. Covers:
  1. Module imports + CLI smoke (`--help`).
  2. Hermetic synthetic-repo positive: a revert commit whose body has a
     `Revert "Supply inflation guard"` header AND removes a function
     definition fires as a candidate.
  3. Hermetic synthetic-repo negative: an unrelated bugfix commit that
     happens to remove a function does NOT fire (no revert verb / no
     guard keyword).
  4. CLI integration: running the tool against the synthetic repo
     emits a JSON report with the candidate and matches the
     `auditooor.reverted_guard_mine.v1` schema shape.
"""
from __future__ import annotations

import importlib.util
import json
import os
import pathlib
import subprocess
import tempfile
import unittest


REPO = pathlib.Path(__file__).resolve().parents[2]
TOOL = REPO / "tools" / "reverted-guard-mine.py"


def _load_tool():
    spec = importlib.util.spec_from_file_location("reverted_guard_mine", TOOL)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"unable to load tool: {TOOL}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _git(repo_dir: pathlib.Path, *args: str) -> str:
    env = os.environ.copy()
    env.setdefault("GIT_AUTHOR_NAME", "test-bot")
    env.setdefault("GIT_AUTHOR_EMAIL", "bot@example.com")
    env.setdefault("GIT_COMMITTER_NAME", "test-bot")
    env.setdefault("GIT_COMMITTER_EMAIL", "bot@example.com")
    proc = subprocess.run(
        ["git", "-C", str(repo_dir), *args],
        capture_output=True,
        text=True,
        check=True,
        env=env,
    )
    return proc.stdout.strip()


def _build_synthetic_repo(repo_dir: pathlib.Path) -> tuple[str, str]:
    """Build a 4-commit history exercising both fire and non-fire shapes.

    Returns (audit_pin_sha, revert_commit_sha).
    """
    repo_dir.mkdir(parents=True, exist_ok=True)
    _git(repo_dir, "init", "--quiet", "--initial-branch=main")
    _git(repo_dir, "config", "commit.gpgsign", "false")

    # Commit 1: original code with a guard function.
    src = repo_dir / "src" / "Vault.sol"
    src.parent.mkdir(parents=True)
    src.write_text(
        "// SPDX-License-Identifier: MIT\n"
        "pragma solidity ^0.8.20;\n"
        "contract Vault {\n"
        "    function deposit(uint256 a) external {}\n"
        "    function _supplyInflationGuard(uint256 a) internal pure returns (bool) {\n"
        "        return a > 0;\n"
        "    }\n"
        "    function _otherHelper() internal {}\n"
        "}\n",
        encoding="utf-8",
    )
    _git(repo_dir, "add", "src/Vault.sol")
    _git(repo_dir, "commit", "--quiet", "-m", "Initial Vault impl")

    # Commit 2: unrelated bugfix that removes _otherHelper (no revert verb,
    # no guard keyword) — must NOT fire.
    src.write_text(
        "// SPDX-License-Identifier: MIT\n"
        "pragma solidity ^0.8.20;\n"
        "contract Vault {\n"
        "    function deposit(uint256 a) external {}\n"
        "    function _supplyInflationGuard(uint256 a) internal pure returns (bool) {\n"
        "        return a > 0;\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )
    _git(repo_dir, "add", "src/Vault.sol")
    _git(repo_dir, "commit", "--quiet", "-m", "remove unused helper")

    # Commit 3: the revert commit — removes the supply inflation guard.
    # Body contains the canonical `Revert "..."` header.
    src.write_text(
        "// SPDX-License-Identifier: MIT\n"
        "pragma solidity ^0.8.20;\n"
        "contract Vault {\n"
        "    function deposit(uint256 a) external {}\n"
        "}\n",
        encoding="utf-8",
    )
    _git(repo_dir, "add", "src/Vault.sol")
    _git(
        repo_dir,
        "commit",
        "--quiet",
        "-m",
        'Trust mitigations (#16)\n\n* Revert "Supply inflation guard (#17)"\n\n'
        "This reverts commit deadbeefcafebabe.",
    )
    revert_sha = _git(repo_dir, "rev-parse", "HEAD")

    # Commit 4: audit pin — unrelated polish commit.
    (repo_dir / "README.md").write_text("docs", encoding="utf-8")
    _git(repo_dir, "add", "README.md")
    _git(repo_dir, "commit", "--quiet", "-m", "docs: README")
    audit_pin_sha = _git(repo_dir, "rev-parse", "HEAD")

    return audit_pin_sha, revert_sha


class RevertedGuardMineModuleTest(unittest.TestCase):
    def test_module_imports_cleanly(self):
        mod = _load_tool()
        self.assertTrue(hasattr(mod, "mine_reverted_guards"))
        self.assertTrue(hasattr(mod, "main"))

    def test_cli_help_exits_zero(self):
        rc = subprocess.run(
            ["python3", str(TOOL), "--help"],
            capture_output=True,
            text=True,
            check=False,
        ).returncode
        self.assertEqual(rc, 0)


class RevertedGuardMineSyntheticPositiveTest(unittest.TestCase):
    def test_synthetic_revert_with_guard_keyword_fires(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = pathlib.Path(tmp) / "repo"
            audit_pin, revert_sha = _build_synthetic_repo(repo)

            mod = _load_tool()
            candidates = mod.mine_reverted_guards(
                repo_dir=repo,
                audit_pin=audit_pin,
                backward_window=10,
            )
            shas = [c["sha"] for c in candidates]
            self.assertIn(
                revert_sha,
                shas,
                f"expected {revert_sha!r} to fire; got {shas!r}",
            )
            cand = next(c for c in candidates if c["sha"] == revert_sha)
            self.assertEqual(cand["tier_6_class"], "b")
            self.assertTrue(cand["is_revert_body"])
            self.assertIn(
                "Supply inflation guard (#17)",
                cand["body_revert_headers"],
            )
            self.assertIn(
                "_supplyInflationGuard",
                cand["removed_function_signatures"],
            )
            # Audit-pin coverage — _supplyInflationGuard NOT present at pin.
            self.assertFalse(
                cand["audit_pin_coverage"]["_supplyInflationGuard"],
            )
            # Therefore candidate_finding == True.
            self.assertTrue(cand["candidate_finding"])


class RevertedGuardMineSyntheticNegativeTest(unittest.TestCase):
    def test_synthetic_unrelated_remove_does_not_fire(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = pathlib.Path(tmp) / "repo"
            # Build a 1-commit no-revert repo.
            repo.mkdir()
            _git(repo, "init", "--quiet", "--initial-branch=main")
            _git(repo, "config", "commit.gpgsign", "false")
            src = repo / "src" / "Foo.sol"
            src.parent.mkdir()
            src.write_text(
                "contract Foo { function _h() internal {} }\n",
                encoding="utf-8",
            )
            _git(repo, "add", "src/Foo.sol")
            _git(repo, "commit", "--quiet", "-m", "initial")
            src.write_text(
                "contract Foo {}\n",
                encoding="utf-8",
            )
            _git(repo, "add", "src/Foo.sol")
            _git(repo, "commit", "--quiet", "-m", "tidy: remove _h helper")
            audit_pin = _git(repo, "rev-parse", "HEAD")

            mod = _load_tool()
            candidates = mod.mine_reverted_guards(
                repo_dir=repo,
                audit_pin=audit_pin,
                backward_window=10,
            )
            self.assertEqual(
                candidates,
                [],
                "tidy/remove commit must NOT fire (no revert verb, no guard kw)",
            )


class RevertedGuardMineCliJsonTest(unittest.TestCase):
    def test_cli_emits_v1_schema_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = pathlib.Path(tmp) / "repo"
            audit_pin, _ = _build_synthetic_repo(repo)
            ws = pathlib.Path(tmp) / "ws"
            ws.mkdir()
            out = ws / "report.json"

            rc = subprocess.run(
                [
                    "python3",
                    str(TOOL),
                    "--workspace", str(ws),
                    "--repo-dir", str(repo),
                    "--audit-pin", audit_pin,
                    "--backward-window", "10",
                    "--out", str(out),
                ],
                capture_output=True,
                text=True,
                check=False,
            ).returncode
            self.assertEqual(rc, 0)
            report = json.loads(out.read_text(encoding="utf-8"))
            self.assertEqual(report["schema"], "auditooor.reverted_guard_mine.v1")
            self.assertEqual(report["schema_version"], "1.1")
            self.assertEqual(report["audit_pin"], audit_pin)
            self.assertEqual(report["backward_window"], 10)
            self.assertGreaterEqual(report["candidate_count"], 1)


if __name__ == "__main__":
    unittest.main()
