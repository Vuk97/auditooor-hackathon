#!/usr/bin/env python3
"""Offline tests for the `--hyperbridge-patches` mode of
`tools/workspace-bootstrap.py` (CAPABILITY-GAP-6-SP1-BEEFY-PATCHES).

All tests run in tempfile.TemporaryDirectory() sandboxes; no network calls
are made, no system `cargo` invocation is required. The validation that
`cargo metadata` exits 0 against a real audit-pin checkout is owned by the
lane's results.md and recorded out-of-band in the sidecar, not in this
unit test (the unit-test environment cannot assume `cargo` is installed
and reachable, and even when it is reachable the metadata fetch costs
~60s of network IO).

Test list:

  1. test_detect_hyperbridge_true_when_modules_ismp_present
  2. test_detect_hyperbridge_true_when_tesseract_present
  3. test_detect_hyperbridge_false_on_unrelated_workspace
  4. test_plan_reports_files_to_create_on_clean_tree
  5. test_execute_creates_stub_crates
  6. test_execute_rewrites_zk_beefy_cargo_toml_in_place
  7. test_execute_preserves_original_block_as_comments
  8. test_execute_emits_sidecar_with_sha256
  9. test_execute_is_idempotent_on_rerun
 10. test_execute_refuses_non_hyperbridge_workspace
 11. test_execute_refuses_missing_zk_beefy_cargo_toml
 12. test_cli_dry_run_prints_plan_without_writing
 13. test_cli_refuses_non_hyperbridge_workspace
 14. test_rewrite_helper_skips_when_marker_present
 15. test_rewrite_helper_raises_on_missing_block
"""

from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOLS = ROOT / "tools"


def _load_bootstrap():
    path = TOOLS / "workspace-bootstrap.py"
    spec = importlib.util.spec_from_file_location("workspace_bootstrap", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


bootstrap = _load_bootstrap()


# Minimal sp1-beefy-bearing Cargo.toml fixture matching the audit-pin
# (70c8429d9b5c) shape of
# tesseract/consensus/beefy/zk/Cargo.toml. We intentionally include
# extra unrelated fields so the rewrite must locate the right blocks
# without false-positive matches.
ZK_BEEFY_CARGO_TOML_FIXTURE = """\
[package]
name = "zk-beefy"
version = "0.1.0"
edition = "2021"

[dependencies]
tracing = { workspace = true }
anyhow = "1.0.79"

[dependencies.sp1-beefy]
git = "ssh://git@github.com/polytope-labs/sp1-beefy.git"
tag = "v1.0.0"

[dependencies.sp1-beefy-primitives]
git = "ssh://git@github.com/polytope-labs/sp1-beefy.git"
tag = "v1.0.0"

[dev-dependencies]
serde = "1"

[features]
default = ["local"]
cluster = ["sp1-beefy/cluster"]
local = ["sp1-beefy/local"]
"""


def _seed_hyperbridge_workspace(root: Path) -> Path:
    """Create a minimal hyperbridge-shaped workspace under `root` and
    return its path. The workspace contains src/hyperbridge/modules/ismp
    and a fixture zk-beefy Cargo.toml at the expected location."""
    ws = root / "ws"
    ws.mkdir()
    # The detector accepts any of HYPERBRIDGE_DETECT_PATHS; we seed two
    # of them so detection cannot accidentally regress to a one-path
    # check.
    (ws / "src" / "hyperbridge" / "modules" / "ismp").mkdir(parents=True)
    (ws / "src" / "hyperbridge" / "tesseract").mkdir(parents=True)
    zk_dir = (
        ws
        / "src"
        / "hyperbridge"
        / "tesseract"
        / "consensus"
        / "beefy"
        / "zk"
    )
    zk_dir.mkdir(parents=True)
    (zk_dir / "Cargo.toml").write_text(ZK_BEEFY_CARGO_TOML_FIXTURE)
    return ws


def _seed_hyperbridge_workspace_missing_zk_beefy(root: Path) -> Path:
    """Hyperbridge-shaped workspace WITHOUT the zk-beefy Cargo.toml.
    Used to assert the explicit refusal path."""
    ws = root / "ws"
    ws.mkdir()
    (ws / "src" / "hyperbridge" / "modules" / "ismp").mkdir(parents=True)
    return ws


def _call_cli(argv: list[str]) -> tuple[int, str, str]:
    out = io.StringIO()
    err = io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        rc = bootstrap.main(argv)
    return rc, out.getvalue(), err.getvalue()


class TestHyperbridgeDetection(unittest.TestCase):
    def test_detect_hyperbridge_true_when_modules_ismp_present(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td) / "ws"
            ws.mkdir()
            (ws / "src" / "hyperbridge" / "modules" / "ismp").mkdir(
                parents=True
            )
            self.assertTrue(bootstrap._detect_hyperbridge(ws))

    def test_detect_hyperbridge_true_when_tesseract_present(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td) / "ws"
            ws.mkdir()
            (ws / "src" / "hyperbridge" / "tesseract").mkdir(parents=True)
            self.assertTrue(bootstrap._detect_hyperbridge(ws))

    def test_detect_hyperbridge_false_on_unrelated_workspace(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td) / "ws"
            ws.mkdir()
            (ws / "src" / "some_other_project").mkdir(parents=True)
            self.assertFalse(bootstrap._detect_hyperbridge(ws))


class TestHyperbridgePlan(unittest.TestCase):
    def test_plan_reports_files_to_create_on_clean_tree(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _seed_hyperbridge_workspace(Path(td))
            plan = bootstrap.plan_hyperbridge_patches(ws)
            self.assertTrue(plan["detected"])
            self.assertFalse(plan["already_patched"])
            actions = {p: a for p, a in plan["files"]}
            # Four stub files should be marked "create" and the
            # Cargo.toml should be marked "rewrite".
            create_count = sum(1 for a in actions.values() if a == "create")
            rewrite_count = sum(
                1 for a in actions.values() if a == "rewrite"
            )
            self.assertEqual(create_count, 4)
            self.assertEqual(rewrite_count, 1)


class TestHyperbridgeExecute(unittest.TestCase):
    def test_execute_creates_stub_crates(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _seed_hyperbridge_workspace(Path(td))
            bootstrap.execute_hyperbridge_patches(ws)
            stubs_dir = ws / "src" / "hyperbridge" / "stubs"
            expected = [
                stubs_dir / "sp1-beefy" / "Cargo.toml",
                stubs_dir / "sp1-beefy" / "src" / "lib.rs",
                stubs_dir / "sp1-beefy-primitives" / "Cargo.toml",
                stubs_dir / "sp1-beefy-primitives" / "src" / "lib.rs",
            ]
            for path in expected:
                self.assertTrue(
                    path.is_file(), f"missing stub: {path}"
                )
            # Stub Cargo.toml must carry version 1.0.0 (the matching tag
            # of the unreachable upstream).
            sp1_cargo = (
                stubs_dir / "sp1-beefy" / "Cargo.toml"
            ).read_text()
            self.assertIn("version = \"1.0.0\"", sp1_cargo)
            # Stub Cargo.toml must declare local + cluster features so
            # the consuming `[features]` block resolves.
            self.assertIn("local = []", sp1_cargo)
            self.assertIn("cluster = []", sp1_cargo)

    def test_execute_rewrites_zk_beefy_cargo_toml_in_place(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _seed_hyperbridge_workspace(Path(td))
            zk_toml = (
                ws
                / "src"
                / "hyperbridge"
                / "tesseract"
                / "consensus"
                / "beefy"
                / "zk"
                / "Cargo.toml"
            )
            original = zk_toml.read_text()
            bootstrap.execute_hyperbridge_patches(ws)
            rewritten = zk_toml.read_text()
            self.assertNotEqual(original, rewritten)
            # The rewritten file must use path-based deps for sp1-beefy
            # AND sp1-beefy-primitives.
            self.assertIn(
                "path = \"../../../../stubs/sp1-beefy\"", rewritten
            )
            self.assertIn(
                "path = \"../../../../stubs/sp1-beefy-primitives\"",
                rewritten,
            )

    def test_execute_preserves_original_block_as_comments(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _seed_hyperbridge_workspace(Path(td))
            zk_toml = (
                ws
                / "src"
                / "hyperbridge"
                / "tesseract"
                / "consensus"
                / "beefy"
                / "zk"
                / "Cargo.toml"
            )
            bootstrap.execute_hyperbridge_patches(ws)
            rewritten = zk_toml.read_text()
            # The original git URL line should be commented out, not
            # deleted, so `git diff` and `git blame` carry the audit
            # trail forward.
            self.assertIn(
                "# git = \"ssh://git@github.com/polytope-labs/"
                "sp1-beefy.git\"",
                rewritten,
            )
            self.assertIn("# tag = \"v1.0.0\"", rewritten)
            # Both marker comments must be present.
            self.assertIn(
                bootstrap.HYPERBRIDGE_PATCH_MARKER_BEGIN, rewritten
            )
            self.assertIn(
                bootstrap.HYPERBRIDGE_PATCH_MARKER_END, rewritten
            )

    def test_execute_emits_sidecar_with_sha256(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _seed_hyperbridge_workspace(Path(td))
            sidecar = bootstrap.execute_hyperbridge_patches(ws)
            sidecar_path = (
                ws / ".auditooor" / "hyperbridge_patches.json"
            )
            self.assertTrue(sidecar_path.is_file())
            on_disk = json.loads(sidecar_path.read_text())
            self.assertEqual(
                on_disk["schema"],
                "auditooor.hyperbridge_patches.v1",
            )
            self.assertEqual(
                on_disk["version"], bootstrap.HYPERBRIDGE_PATCH_VERSION
            )
            # Every file record carries a SHA256 (or null if missing).
            for record in on_disk["files"]:
                self.assertIn("sha256", record)
                self.assertIn("action", record)
                self.assertIn("path", record)
            # Spot-check that one stub SHA matches the actual file.
            sp1_cargo = (
                ws
                / "src"
                / "hyperbridge"
                / "stubs"
                / "sp1-beefy"
                / "Cargo.toml"
            )
            expected_sha = hashlib.sha256(
                sp1_cargo.read_bytes()
            ).hexdigest()
            actual_record = next(
                r for r in on_disk["files"]
                if r["path"] == str(sp1_cargo)
            )
            self.assertEqual(actual_record["sha256"], expected_sha)
            # Returned dict mirrors on-disk sidecar.
            self.assertEqual(sidecar["schema"], on_disk["schema"])

    def test_execute_is_idempotent_on_rerun(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _seed_hyperbridge_workspace(Path(td))
            zk_toml = (
                ws
                / "src"
                / "hyperbridge"
                / "tesseract"
                / "consensus"
                / "beefy"
                / "zk"
                / "Cargo.toml"
            )
            bootstrap.execute_hyperbridge_patches(ws)
            sha_after_first = hashlib.sha256(
                zk_toml.read_bytes()
            ).hexdigest()
            # Second run should be a no-op on every tracked file.
            sidecar_second = bootstrap.execute_hyperbridge_patches(ws)
            sha_after_second = hashlib.sha256(
                zk_toml.read_bytes()
            ).hexdigest()
            self.assertEqual(sha_after_first, sha_after_second)
            # Sidecar should record "skipped" for every file on rerun.
            actions = {r["action"] for r in sidecar_second["files"]}
            self.assertEqual(actions, {"skipped"})

    def test_execute_refuses_non_hyperbridge_workspace(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td) / "not_hyperbridge"
            ws.mkdir()
            with self.assertRaises(FileNotFoundError):
                bootstrap.execute_hyperbridge_patches(ws)

    def test_execute_refuses_missing_zk_beefy_cargo_toml(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _seed_hyperbridge_workspace_missing_zk_beefy(
                Path(td)
            )
            with self.assertRaises(FileNotFoundError):
                bootstrap.execute_hyperbridge_patches(ws)


class TestHyperbridgeCli(unittest.TestCase):
    def test_cli_dry_run_prints_plan_without_writing(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _seed_hyperbridge_workspace(Path(td))
            zk_toml = (
                ws
                / "src"
                / "hyperbridge"
                / "tesseract"
                / "consensus"
                / "beefy"
                / "zk"
                / "Cargo.toml"
            )
            sha_before = hashlib.sha256(zk_toml.read_bytes()).hexdigest()
            rc, out, err = _call_cli(
                ["--hyperbridge-patches", str(ws), "--dry-run"]
            )
            self.assertEqual(rc, 0)
            self.assertIn("DRY RUN", out)
            self.assertIn("Hyperbridge tree detected: True", out)
            # The dry-run must not touch the filesystem.
            sha_after = hashlib.sha256(zk_toml.read_bytes()).hexdigest()
            self.assertEqual(sha_before, sha_after)
            self.assertFalse(
                (ws / "src" / "hyperbridge" / "stubs").exists()
            )
            self.assertFalse(
                (ws / ".auditooor" / "hyperbridge_patches.json").exists()
            )

    def test_cli_refuses_non_hyperbridge_workspace(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td) / "not_hyperbridge"
            ws.mkdir()
            rc, out, err = _call_cli(
                ["--hyperbridge-patches", str(ws)]
            )
            self.assertEqual(rc, 2)
            self.assertIn("does not contain a hyperbridge tree", err)


class TestHyperbridgeRewriteHelper(unittest.TestCase):
    def test_rewrite_helper_skips_when_marker_present(self):
        # If the marker is already in the input string, the helper
        # returns the input unchanged - even if other text looks like
        # it should be patched.
        text_with_marker = (
            bootstrap.HYPERBRIDGE_PATCH_MARKER_BEGIN
            + "\n[dependencies.sp1-beefy]\n"
            + "path = \"already-patched\"\n"
            + bootstrap.HYPERBRIDGE_PATCH_MARKER_END
        )
        out = bootstrap._rewrite_zk_beefy_cargo_toml(
            text_with_marker,
            "stubs/sp1-beefy",
            "stubs/sp1-beefy-primitives",
        )
        self.assertEqual(out, text_with_marker)

    def test_rewrite_helper_raises_on_missing_block(self):
        # A Cargo.toml that lacks the expected sp1-beefy headers must
        # cause the helper to refuse rather than silently produce a
        # malformed output.
        text_missing = (
            "[package]\nname = \"zk-beefy\"\nversion = \"0.1.0\"\n"
        )
        with self.assertRaises(ValueError):
            bootstrap._rewrite_zk_beefy_cargo_toml(
                text_missing,
                "stubs/sp1-beefy",
                "stubs/sp1-beefy-primitives",
            )


if __name__ == "__main__":
    unittest.main()
