"""test_reverted_guard_mine_rust_go — Rust and Go extension tests.

Tests the Tier-6 backward-mine class (b) detector's --lang rust and --lang go
extensions via synthetic git repos built in tempdirs. Stdlib-only — no
network calls, no external deps. Covers:

  Rust:
    1. Positive: revert commit whose body has `Revert "supply cap guard"`
       AND removes a `fn validate_supply_cap(` fires as a candidate.
    2. Negative: commit that removes a fn without revert verb/guard keyword
       does NOT fire.
    3. Auto-detect: a repo containing only .rs files resolves lang=rust
       automatically without --lang rust.

  Go:
    4. Positive: revert commit that removes a `func validateTransferLeavesStatus(`
       fires as a candidate.
    5. Negative: tidy commit removing a func without guard keyword does NOT
       fire.
    6. Auto-detect: a repo containing only .go files resolves lang=go
       automatically without --lang go.

  Cross-lang:
    7. CLI integration for --lang rust emits schema_version "1.1" and
       includes "detected_lang" == "rust" in candidate entries.
    8. CLI integration for --lang go emits schema_version "1.1" and
       includes "detected_lang" == "go" in candidate entries.
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


# ─────────────────────────────────────────────────────────────────
# Rust synthetic repo builder
# ─────────────────────────────────────────────────────────────────

def _build_rust_synthetic_repo(repo_dir: pathlib.Path) -> tuple[str, str]:
    """Build a 4-commit Rust repo history.

    Commit 1: initial vault with validate_supply_cap guard.
    Commit 2: unrelated tidy (removes a helper, no revert verb/guard kw).
    Commit 3: revert commit — removes validate_supply_cap.
    Commit 4: audit-pin doc commit.

    Returns (audit_pin_sha, revert_commit_sha).
    """
    repo_dir.mkdir(parents=True, exist_ok=True)
    _git(repo_dir, "init", "--quiet", "--initial-branch=main")
    _git(repo_dir, "config", "commit.gpgsign", "false")

    src = repo_dir / "src" / "vault.rs"
    src.parent.mkdir(parents=True)

    # Commit 1: guard present
    src.write_text(
        "pub struct Vault { pub balance: u64 }\n"
        "impl Vault {\n"
        "    pub fn validate_supply_cap(&self, amount: u64, cap: u64)"
        " -> Result<(), &'static str> {\n"
        "        if self.balance.saturating_add(amount) > cap {\n"
        "            return Err(\"cap exceeded\");\n"
        "        }\n"
        "        Ok(())\n"
        "    }\n"
        "    fn _internal_helper(&self) -> bool { true }\n"
        "    pub fn deposit(&mut self, amount: u64, cap: u64)"
        " -> Result<(), &'static str> {\n"
        "        self.validate_supply_cap(amount, cap)?;\n"
        "        self.balance += amount;\n"
        "        Ok(())\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )
    _git(repo_dir, "add", "src/vault.rs")
    _git(repo_dir, "commit", "--quiet", "-m", "feat: initial Vault impl with supply guard")

    # Commit 2: tidy — removes _internal_helper; no revert verb, no guard kw
    src.write_text(
        "pub struct Vault { pub balance: u64 }\n"
        "impl Vault {\n"
        "    pub fn validate_supply_cap(&self, amount: u64, cap: u64)"
        " -> Result<(), &'static str> {\n"
        "        if self.balance.saturating_add(amount) > cap {\n"
        "            return Err(\"cap exceeded\");\n"
        "        }\n"
        "        Ok(())\n"
        "    }\n"
        "    pub fn deposit(&mut self, amount: u64, cap: u64)"
        " -> Result<(), &'static str> {\n"
        "        self.validate_supply_cap(amount, cap)?;\n"
        "        self.balance += amount;\n"
        "        Ok(())\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )
    _git(repo_dir, "add", "src/vault.rs")
    _git(repo_dir, "commit", "--quiet", "-m", "tidy: remove unused internal helper")

    # Commit 3: revert commit — removes validate_supply_cap
    src.write_text(
        "pub struct Vault { pub balance: u64 }\n"
        "impl Vault {\n"
        "    pub fn deposit(&mut self, amount: u64, _cap: u64)"
        " -> Result<(), &'static str> {\n"
        "        self.balance += amount;\n"
        "        Ok(())\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )
    _git(repo_dir, "add", "src/vault.rs")
    _git(
        repo_dir,
        "commit",
        "--quiet",
        "-m",
        'Trust mitigations (#8)\n\n* Revert "supply cap guard (#7)"\n\n'
        "This reverts commit deadbeef12345678.",
    )
    revert_sha = _git(repo_dir, "rev-parse", "HEAD")

    # Commit 4: audit-pin doc
    (repo_dir / "README.md").write_text("Rust vault docs", encoding="utf-8")
    _git(repo_dir, "add", "README.md")
    _git(repo_dir, "commit", "--quiet", "-m", "docs: README")
    audit_pin_sha = _git(repo_dir, "rev-parse", "HEAD")

    return audit_pin_sha, revert_sha


# ─────────────────────────────────────────────────────────────────
# Go synthetic repo builder
# ─────────────────────────────────────────────────────────────────

def _build_go_synthetic_repo(repo_dir: pathlib.Path) -> tuple[str, str]:
    """Build a 4-commit Go repo history.

    Commit 1: initial code with validateTransferLeavesStatus guard.
    Commit 2: unrelated tidy (no revert verb/guard kw).
    Commit 3: revert commit — removes validateTransferLeavesStatus.
    Commit 4: audit-pin doc commit.

    Returns (audit_pin_sha, revert_commit_sha).
    """
    repo_dir.mkdir(parents=True, exist_ok=True)
    _git(repo_dir, "init", "--quiet", "--initial-branch=main")
    _git(repo_dir, "config", "commit.gpgsign", "false")

    src = repo_dir / "transfer" / "vault.go"
    src.parent.mkdir(parents=True)

    # Commit 1: guard present
    src.write_text(
        'package transfer\n\nimport "errors"\n\n'
        "type Vault struct { Balance uint64 }\n\n"
        "// validateTransferLeavesStatus guards against exited-leaf transfers.\n"
        'func validateTransferLeavesStatus(leafStatus string) error {\n'
        '    if leafStatus == "exited" {\n'
        '        return errors.New("leaf exited")\n'
        "    }\n"
        "    return nil\n"
        "}\n\n"
        "func _unusedHelper() bool { return true }\n\n"
        "func (v *Vault) Transfer(amount uint64, leafStatus string) error {\n"
        "    if err := validateTransferLeavesStatus(leafStatus); err != nil {\n"
        "        return err\n"
        "    }\n"
        "    v.Balance += amount\n"
        "    return nil\n"
        "}\n",
        encoding="utf-8",
    )
    _git(repo_dir, "add", "transfer/vault.go")
    _git(repo_dir, "commit", "--quiet", "-m", "feat: initial vault with leaf-status guard")

    # Commit 2: tidy — removes _unusedHelper; no revert verb, no guard kw
    src.write_text(
        'package transfer\n\nimport "errors"\n\n'
        "type Vault struct { Balance uint64 }\n\n"
        'func validateTransferLeavesStatus(leafStatus string) error {\n'
        '    if leafStatus == "exited" {\n'
        '        return errors.New("leaf exited")\n'
        "    }\n"
        "    return nil\n"
        "}\n\n"
        "func (v *Vault) Transfer(amount uint64, leafStatus string) error {\n"
        "    if err := validateTransferLeavesStatus(leafStatus); err != nil {\n"
        "        return err\n"
        "    }\n"
        "    v.Balance += amount\n"
        "    return nil\n"
        "}\n",
        encoding="utf-8",
    )
    _git(repo_dir, "add", "transfer/vault.go")
    _git(repo_dir, "commit", "--quiet", "-m", "tidy: remove unused helper")

    # Commit 3: revert commit — removes validateTransferLeavesStatus
    src.write_text(
        "package transfer\n\n"
        "type Vault struct { Balance uint64 }\n\n"
        "func (v *Vault) Transfer(amount uint64, leafStatus string) error {\n"
        "    v.Balance += amount\n"
        "    return nil\n"
        "}\n",
        encoding="utf-8",
    )
    _git(repo_dir, "add", "transfer/vault.go")
    _git(
        repo_dir,
        "commit",
        "--quiet",
        "-m",
        'Trust mitigations (#12)\n\n* Revert "leaf-status validate guard (#11)"\n\n'
        "This reverts commit cafecafe12345678.",
    )
    revert_sha = _git(repo_dir, "rev-parse", "HEAD")

    # Commit 4: audit-pin doc
    (repo_dir / "README.md").write_text("Go vault docs", encoding="utf-8")
    _git(repo_dir, "add", "README.md")
    _git(repo_dir, "commit", "--quiet", "-m", "docs: README")
    audit_pin_sha = _git(repo_dir, "rev-parse", "HEAD")

    return audit_pin_sha, revert_sha


# ─────────────────────────────────────────────────────────────────
# Tests: Rust
# ─────────────────────────────────────────────────────────────────

class RustRevertedGuardPositiveTest(unittest.TestCase):
    def test_rust_revert_with_guard_keyword_fires(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = pathlib.Path(tmp) / "repo"
            audit_pin, revert_sha = _build_rust_synthetic_repo(repo)

            mod = _load_tool()
            candidates = mod.mine_reverted_guards(
                repo_dir=repo,
                audit_pin=audit_pin,
                backward_window=10,
                lang="rust",
            )
            shas = [c["sha"] for c in candidates]
            self.assertIn(
                revert_sha,
                shas,
                f"expected rust revert {revert_sha!r} to fire; got {shas!r}",
            )
            cand = next(c for c in candidates if c["sha"] == revert_sha)
            self.assertEqual(cand["tier_6_class"], "b")
            self.assertTrue(cand["is_revert_body"])
            self.assertIn("validate_supply_cap", cand["removed_function_signatures"])
            # validate_supply_cap should NOT be present at audit-pin
            self.assertFalse(cand["audit_pin_coverage"]["validate_supply_cap"])
            self.assertTrue(cand["candidate_finding"])
            self.assertEqual(cand["detected_lang"], "rust")


class RustRevertedGuardNegativeTest(unittest.TestCase):
    def test_rust_tidy_remove_does_not_fire(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = pathlib.Path(tmp) / "repo"
            repo.mkdir()
            _git(repo, "init", "--quiet", "--initial-branch=main")
            _git(repo, "config", "commit.gpgsign", "false")
            src = repo / "src" / "lib.rs"
            src.parent.mkdir()
            src.write_text(
                "fn _unused_helper() -> bool { true }\n"
                "pub fn main_logic() {}\n",
                encoding="utf-8",
            )
            _git(repo, "add", "src/lib.rs")
            _git(repo, "commit", "--quiet", "-m", "initial")
            src.write_text(
                "pub fn main_logic() {}\n",
                encoding="utf-8",
            )
            _git(repo, "add", "src/lib.rs")
            _git(repo, "commit", "--quiet", "-m", "tidy: remove unused helper")
            audit_pin = _git(repo, "rev-parse", "HEAD")

            mod = _load_tool()
            candidates = mod.mine_reverted_guards(
                repo_dir=repo,
                audit_pin=audit_pin,
                backward_window=10,
                lang="rust",
            )
            self.assertEqual(
                candidates,
                [],
                "tidy commit must NOT fire for Rust (no revert verb, no guard kw)",
            )


class RustAutoDetectTest(unittest.TestCase):
    def test_auto_detects_rust_from_rs_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = pathlib.Path(tmp) / "repo"
            audit_pin, revert_sha = _build_rust_synthetic_repo(repo)

            mod = _load_tool()
            # lang="auto" should detect rust from .rs files
            candidates = mod.mine_reverted_guards(
                repo_dir=repo,
                audit_pin=audit_pin,
                backward_window=10,
                lang="auto",
            )
            shas = [c["sha"] for c in candidates]
            self.assertIn(
                revert_sha,
                shas,
                "auto-detect should resolve rust and fire on the revert commit",
            )
            cand = next(c for c in candidates if c["sha"] == revert_sha)
            self.assertEqual(cand["detected_lang"], "rust")


# ─────────────────────────────────────────────────────────────────
# Tests: Go
# ─────────────────────────────────────────────────────────────────

class GoRevertedGuardPositiveTest(unittest.TestCase):
    def test_go_revert_with_guard_keyword_fires(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = pathlib.Path(tmp) / "repo"
            audit_pin, revert_sha = _build_go_synthetic_repo(repo)

            mod = _load_tool()
            candidates = mod.mine_reverted_guards(
                repo_dir=repo,
                audit_pin=audit_pin,
                backward_window=10,
                lang="go",
            )
            shas = [c["sha"] for c in candidates]
            self.assertIn(
                revert_sha,
                shas,
                f"expected go revert {revert_sha!r} to fire; got {shas!r}",
            )
            cand = next(c for c in candidates if c["sha"] == revert_sha)
            self.assertEqual(cand["tier_6_class"], "b")
            self.assertTrue(cand["is_revert_body"])
            self.assertIn(
                "validateTransferLeavesStatus",
                cand["removed_function_signatures"],
            )
            # Guard not present at audit-pin
            self.assertFalse(cand["audit_pin_coverage"]["validateTransferLeavesStatus"])
            self.assertTrue(cand["candidate_finding"])
            self.assertEqual(cand["detected_lang"], "go")


class GoRevertedGuardNegativeTest(unittest.TestCase):
    def test_go_tidy_remove_does_not_fire(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = pathlib.Path(tmp) / "repo"
            repo.mkdir()
            _git(repo, "init", "--quiet", "--initial-branch=main")
            _git(repo, "config", "commit.gpgsign", "false")
            src = repo / "pkg" / "foo.go"
            src.parent.mkdir()
            src.write_text(
                "package pkg\nfunc unusedHelper() bool { return true }\n"
                "func MainLogic() {}\n",
                encoding="utf-8",
            )
            _git(repo, "add", "pkg/foo.go")
            _git(repo, "commit", "--quiet", "-m", "initial")
            src.write_text(
                "package pkg\nfunc MainLogic() {}\n",
                encoding="utf-8",
            )
            _git(repo, "add", "pkg/foo.go")
            _git(repo, "commit", "--quiet", "-m", "tidy: remove unused helper")
            audit_pin = _git(repo, "rev-parse", "HEAD")

            mod = _load_tool()
            candidates = mod.mine_reverted_guards(
                repo_dir=repo,
                audit_pin=audit_pin,
                backward_window=10,
                lang="go",
            )
            self.assertEqual(
                candidates,
                [],
                "tidy commit must NOT fire for Go (no revert verb, no guard kw)",
            )


class GoAutoDetectTest(unittest.TestCase):
    def test_auto_detects_go_from_go_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = pathlib.Path(tmp) / "repo"
            audit_pin, revert_sha = _build_go_synthetic_repo(repo)

            mod = _load_tool()
            # lang="auto" should detect go from .go files
            candidates = mod.mine_reverted_guards(
                repo_dir=repo,
                audit_pin=audit_pin,
                backward_window=10,
                lang="auto",
            )
            shas = [c["sha"] for c in candidates]
            self.assertIn(
                revert_sha,
                shas,
                "auto-detect should resolve go and fire on the revert commit",
            )
            cand = next(c for c in candidates if c["sha"] == revert_sha)
            self.assertEqual(cand["detected_lang"], "go")


# ─────────────────────────────────────────────────────────────────
# Tests: CLI schema v1.1 integration
# ─────────────────────────────────────────────────────────────────

class CliSchemaV11RustTest(unittest.TestCase):
    def test_cli_rust_emits_v11_schema(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = pathlib.Path(tmp) / "repo"
            audit_pin, _ = _build_rust_synthetic_repo(repo)
            ws = pathlib.Path(tmp) / "ws"
            ws.mkdir()
            out = ws / "report.json"

            rc = subprocess.run(
                [
                    "python3", str(TOOL),
                    "--workspace", str(ws),
                    "--repo-dir", str(repo),
                    "--audit-pin", audit_pin,
                    "--backward-window", "10",
                    "--lang", "rust",
                    "--out", str(out),
                ],
                capture_output=True,
                text=True,
                check=False,
            ).returncode
            self.assertEqual(rc, 0, "CLI must exit 0 for rust lang")
            report = json.loads(out.read_text(encoding="utf-8"))
            self.assertEqual(report["schema"], "auditooor.reverted_guard_mine.v1")
            self.assertEqual(report["schema_version"], "1.1")
            self.assertEqual(report["lang"], "rust")
            self.assertGreaterEqual(report["candidate_count"], 1)
            # Check first candidate has detected_lang field
            candidates = report["candidates"]
            fired = [c for c in candidates if c.get("candidate_finding")]
            self.assertGreaterEqual(len(fired), 1)
            self.assertEqual(fired[0]["detected_lang"], "rust")


class CliSchemaV11GoTest(unittest.TestCase):
    def test_cli_go_emits_v11_schema(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = pathlib.Path(tmp) / "repo"
            audit_pin, _ = _build_go_synthetic_repo(repo)
            ws = pathlib.Path(tmp) / "ws"
            ws.mkdir()
            out = ws / "report.json"

            rc = subprocess.run(
                [
                    "python3", str(TOOL),
                    "--workspace", str(ws),
                    "--repo-dir", str(repo),
                    "--audit-pin", audit_pin,
                    "--backward-window", "10",
                    "--lang", "go",
                    "--out", str(out),
                ],
                capture_output=True,
                text=True,
                check=False,
            ).returncode
            self.assertEqual(rc, 0, "CLI must exit 0 for go lang")
            report = json.loads(out.read_text(encoding="utf-8"))
            self.assertEqual(report["schema"], "auditooor.reverted_guard_mine.v1")
            self.assertEqual(report["schema_version"], "1.1")
            self.assertEqual(report["lang"], "go")
            self.assertGreaterEqual(report["candidate_count"], 1)
            candidates = report["candidates"]
            fired = [c for c in candidates if c.get("candidate_finding")]
            self.assertGreaterEqual(len(fired), 1)
            self.assertEqual(fired[0]["detected_lang"], "go")


if __name__ == "__main__":
    unittest.main()
