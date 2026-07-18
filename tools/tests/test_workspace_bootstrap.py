#!/usr/bin/env python3
"""Offline tests for tools/workspace-bootstrap.py.

All tests run in tempfile.TemporaryDirectory() sandboxes; nothing under
~/audits/ is touched. No network, no subprocess to external tools.

Test list (5 original + 4 V5-P0-06 engage-stubs cases):

  1. test_bootstrap_creates_full_dir_structure
  2. test_bootstrap_refuses_to_overwrite_existing_workspace
  3. test_bootstrap_validates_platform_against_valid_platforms
  4. test_bootstrap_dry_run_prints_plan_without_creating
  5. test_bootstrap_name_slug_validation
  6. test_engage_stubs_creates_minimal_set_in_existing_workspace
  7. test_engage_stubs_is_idempotent_on_rerun
  8. test_engage_stubs_preserves_curated_operator_content
  9. test_engage_stubs_dry_run_does_not_write
"""

from __future__ import annotations

import importlib.util
import io
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOLS = ROOT / "tools"


def _load_bootstrap():
    """Load tools/workspace-bootstrap.py despite the hyphen."""
    path = TOOLS / "workspace-bootstrap.py"
    spec = importlib.util.spec_from_file_location("workspace_bootstrap", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


bootstrap = _load_bootstrap()


def _call(argv: list[str]) -> tuple[int, str, str]:
    """Invoke bootstrap.main with argv. Return (rc, stdout, stderr)."""
    out = io.StringIO()
    err = io.StringIO()
    try:
        with redirect_stdout(out), redirect_stderr(err):
            rc = bootstrap.main(argv)
    except SystemExit as exc:  # argparse uses SystemExit on --help / errors
        rc = int(exc.code or 0)
    return rc, out.getvalue(), err.getvalue()


class TestWorkspaceBootstrap(unittest.TestCase):
    # ---------- case 1 ----------
    def test_bootstrap_creates_full_dir_structure(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            audits = Path(tmp)
            rc, out, err = _call([
                "--name", "snowbridge-test",
                "--platform", "hackenproof",
                "--scope-url", "https://hackenproof.com/bounties/snowbridge",
                "--audits-dir", str(audits),
            ])
            self.assertEqual(rc, 0, f"stderr={err!r}")

            ws = audits / "snowbridge-test"
            self.assertTrue(ws.is_dir(), f"workspace not created: {ws}")

            # Expected directory shape.
            expected_dirs = [
                ws / "reference",
                ws / "submissions",
                ws / "submissions" / "staging",
                ws / "submissions" / "packaged",
                ws / "agent_outputs",
            ]
            for d in expected_dirs:
                self.assertTrue(d.is_dir(), f"missing dir: {d}")

            # Expected files.
            scope = ws / "SCOPE.md"
            outcomes = ws / "reference" / "outcomes.jsonl"
            meta = ws / "BOOTSTRAP_ITER7.md"
            self.assertTrue(scope.is_file(), "SCOPE.md missing")
            self.assertTrue(outcomes.is_file(), "outcomes.jsonl missing")
            self.assertTrue(meta.is_file(), "BOOTSTRAP_ITER7.md missing")

            # outcomes.jsonl starts empty (append-only stream convention).
            self.assertEqual(outcomes.read_text(), "")

            # SCOPE.md header carries the scope URL and platform.
            scope_text = scope.read_text()
            self.assertIn("https://hackenproof.com/bounties/snowbridge", scope_text)
            self.assertIn("hackenproof", scope_text)
            self.assertIn("snowbridge-test", scope_text)

            # BOOTSTRAP_ITER7.md records the CLI args.
            meta_text = meta.read_text()
            self.assertIn("snowbridge-test", meta_text)
            self.assertIn("hackenproof", meta_text)

    # ---------- case 2 ----------
    def test_bootstrap_refuses_to_overwrite_existing_workspace(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            audits = Path(tmp)
            ws = audits / "already-here"
            ws.mkdir(parents=True)
            # Seed a file so we can prove no overwrite happened.
            (ws / "existing.txt").write_text("operator data")

            rc, out, err = _call([
                "--name", "already-here",
                "--platform", "cantina",
                "--scope-url", "https://cantina.xyz/bounty/test",
                "--audits-dir", str(audits),
            ])

            self.assertEqual(rc, 2, f"expected exit 2 on existing dir, got {rc}")
            self.assertIn("already exists", err)
            # Existing file was preserved untouched.
            self.assertEqual(
                (ws / "existing.txt").read_text(),
                "operator data",
            )
            # None of the bootstrap files were created.
            self.assertFalse((ws / "SCOPE.md").exists())
            self.assertFalse((ws / "BOOTSTRAP_ITER7.md").exists())
            self.assertFalse((ws / "reference").exists())

    # ---------- case 2b: --force completes scaffold non-destructively ----------
    def test_bootstrap_force_completes_existing_scaffold_nondestructive(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            audits = Path(tmp)
            ws = audits / "re-pinned"
            # Simulate a re-pinned/re-audited target: ws exists with curated
            # prior_audits/ + an authored SCOPE.md, but no bootstrap scaffold.
            (ws / "prior_audits").mkdir(parents=True)
            (ws / "prior_audits" / "audit1.pdf.txt").write_text("PRIOR AUDIT")
            (ws / "SCOPE.md").write_text("AUTHORED SCOPE - do not clobber")

            rc, out, err = _call([
                "--name", "re-pinned",
                "--platform", "cantina",
                "--scope-url", "https://cantina.xyz/bounty/test",
                "--audits-dir", str(audits),
                "--force",
            ])

            self.assertEqual(rc, 0, f"--force should succeed, got {rc}: {err}")
            # Missing scaffold dirs are now created.
            for d in ("reference", "submissions", "submissions/staging",
                      "submissions/packaged", "agent_outputs"):
                self.assertTrue((ws / d).is_dir(), f"missing dir {d}")
            self.assertTrue((ws / "targets.tsv").exists())
            # Curated content is PRESERVED (never overwritten).
            self.assertEqual(
                (ws / "prior_audits" / "audit1.pdf.txt").read_text(), "PRIOR AUDIT")
            self.assertEqual(
                (ws / "SCOPE.md").read_text(), "AUTHORED SCOPE - do not clobber")

    def test_bootstrap_force_is_idempotent_on_rerun(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            audits = Path(tmp)
            argv = [
                "--name", "idem", "--platform", "cantina",
                "--scope-url", "https://cantina.xyz/bounty/test",
                "--audits-dir", str(audits), "--force",
            ]
            # First run on a non-existent ws (force on fresh = normal create).
            rc1, _, e1 = _call(argv)
            self.assertEqual(rc1, 0, e1)
            # Second run (ws now exists) must also succeed as an idempotent complete.
            rc2, _, e2 = _call(argv)
            self.assertEqual(rc2, 0, f"re-run with --force should be rc=0, got {rc2}: {e2}")

    # ---------- case 3 ----------
    def test_bootstrap_validates_platform_against_valid_platforms(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            audits = Path(tmp)
            rc, out, err = _call([
                "--name", "ws-bad-platform",
                "--platform", "foobar",
                "--scope-url", "https://example.com/x",
                "--audits-dir", str(audits),
            ])
            self.assertNotEqual(rc, 0, "platform validation should fail")
            self.assertIn("foobar", err)
            # Error message names the allowlist so operator sees valid
            # tokens at the point of failure.
            # VALID_PLATFORMS must be cross-checked here, not hardcoded.
            for p in sorted(bootstrap.VALID_PLATFORMS):
                self.assertIn(p, err)
            # No workspace created.
            self.assertFalse((audits / "ws-bad-platform").exists())

    # ---------- case 4 ----------
    def test_bootstrap_dry_run_prints_plan_without_creating(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            audits = Path(tmp)
            rc, out, err = _call([
                "--name", "dry-run-ws",
                "--platform", "sherlock",
                "--scope-url", "https://sherlock.xyz/x",
                "--audits-dir", str(audits),
                "--dry-run",
            ])
            self.assertEqual(rc, 0, f"stderr={err!r}")
            # Plan lists each file / dir that would be created.
            self.assertIn("DRY RUN", out)
            self.assertIn("SCOPE.md", out)
            self.assertIn("BOOTSTRAP_ITER7.md", out)
            self.assertIn("reference", out)
            self.assertIn("submissions", out)
            self.assertIn("staging", out)
            self.assertIn("packaged", out)
            self.assertIn("agent_outputs", out)

            # Hard negative: NOTHING was written to disk.
            ws = audits / "dry-run-ws"
            self.assertFalse(ws.exists(), "dry-run must not create workspace")
            # audits_dir itself is allowed to remain (pre-existed), but
            # must have zero children for this temp.
            self.assertEqual(list(audits.iterdir()), [])

    # ---------- case 5 ----------
    def test_bootstrap_name_slug_validation(self) -> None:
        """Uppercase, special chars, and spaces are all rejected."""
        bad_names = [
            "Uppercase",
            "has space",
            "has_underscore",
            "has.dot",
            "-leading-hyphen",
            "has/slash",
            "",
        ]
        for bad in bad_names:
            with tempfile.TemporaryDirectory() as tmp:
                audits = Path(tmp)
                # Empty string triggers argparse itself; catch both.
                argv = [
                    "--name", bad,
                    "--platform", "other",
                    "--scope-url", "https://example.com/x",
                    "--audits-dir", str(audits),
                ]
                rc, out, err = _call(argv)
                self.assertNotEqual(
                    rc,
                    0,
                    f"slug {bad!r} should have been rejected",
                )
                # Workspace directory must not exist after a rejection.
                if bad:
                    self.assertFalse((audits / bad).exists())


class TestEngageStubs(unittest.TestCase):
    """V5-P0-06 / Gap 16 — `--engage-stubs <ws>` idempotent stub seeding.

    The engage chain expects a small set of operator files (SCOPE.md,
    OOS_CHECKLIST.md, SEVERITY_CAPS.md, ...) to be present in the
    workspace before downstream stages can run truthfully. Bootstrap
    seeds minimal stubs once, with a marker line, and never overwrites
    them on re-run.
    """

    EXPECTED_STUBS = [
        "SCOPE.md",
        "AUDIT.md",
        "SESSION_LOG.md",
        "FINDINGS.md",
        "SEVERITY.md",
        "RUBRIC_COVERAGE.md",
        "targets.tsv",
        "SEVERITY_CAPS.md",
        "OOS_CHECKLIST.md",
        "concolic/SUMMARY.md",
        "economic_hypotheses.md",
    ]

    # Markers from tools/workspace-bootstrap.py.
    MARKER_MD = "<!-- auditooor.bootstrap-version: 1 -->"
    MARKER_HASH = "# auditooor.bootstrap-version: 1"

    def test_engage_stubs_creates_minimal_set_in_existing_workspace(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "fresh-ws"
            ws.mkdir(parents=True)

            rc, out, err = _call(["--engage-stubs", str(ws)])
            self.assertEqual(rc, 0, f"stderr={err!r}; stdout={out!r}")

            for rel in self.EXPECTED_STUBS:
                target = ws / rel
                self.assertTrue(
                    target.is_file(),
                    f"engage-stub missing: {target}",
                )
                content = target.read_text()
                # Every stub carries one of the bootstrap markers.
                if rel.endswith(".tsv"):
                    self.assertIn(self.MARKER_HASH, content, rel)
                else:
                    self.assertIn(self.MARKER_MD, content, rel)
                # Operator-edit cue is present in every stub.
                self.assertIn("TBD", content, rel)

            # `concolic/` parent dir was created on demand.
            self.assertTrue((ws / "concolic").is_dir())
            targets_text = (ws / "targets.tsv").read_text()
            self.assertIn("repo_url<TAB>pinned_40_hex_commit<TAB>local_name", targets_text)
            self.assertIn("Required before make audit", targets_text)

    def test_engage_stubs_is_idempotent_on_rerun(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "rerun-ws"
            ws.mkdir(parents=True)

            rc1, _o1, e1 = _call(["--engage-stubs", str(ws)])
            self.assertEqual(rc1, 0, e1)

            # Snapshot all stub contents + mtimes.
            before = {}
            for rel in self.EXPECTED_STUBS:
                p = ws / rel
                before[rel] = (p.read_text(), p.stat().st_mtime_ns)

            # Re-run: every file should be reported as already-present
            # and untouched.
            rc2, out2, err2 = _call(["--engage-stubs", str(ws)])
            self.assertEqual(rc2, 0, err2)
            self.assertIn("skipped", out2.lower())

            for rel in self.EXPECTED_STUBS:
                p = ws / rel
                after_text = p.read_text()
                after_mtime = p.stat().st_mtime_ns
                self.assertEqual(
                    before[rel][0],
                    after_text,
                    f"stub content changed on rerun: {rel}",
                )
                self.assertEqual(
                    before[rel][1],
                    after_mtime,
                    f"stub mtime changed on rerun: {rel}",
                )

    def test_engage_stubs_preserves_curated_operator_content(self) -> None:
        """Operator who edits SCOPE.md before bootstrap re-runs must keep
        their work. Bootstrap never overwrites an existing file."""
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "curated-ws"
            ws.mkdir(parents=True)

            # Operator handcrafts SCOPE.md and OOS_CHECKLIST.md without
            # any bootstrap marker. (Mirrors a real Monetrix-style flow
            # where the operator started filing manual stubs before this
            # tool existed.)
            curated_scope = (
                "# Operator scope note\n\n"
                "In-scope: contracts/Foo.sol, contracts/Bar.sol\n"
            )
            curated_oos = (
                "# Operator OOS\n\n"
                "- known: stale frontend cache\n"
            )
            (ws / "SCOPE.md").write_text(curated_scope)
            (ws / "OOS_CHECKLIST.md").write_text(curated_oos)
            # Half-bootstrapped: SEVERITY.md exists with the marker (a
            # previous bootstrap left it). Must remain untouched.
            (ws / "SEVERITY.md").write_text(
                f"# placeholder\n\n{self.MARKER_MD}\n\nTBD — operator edit.\n"
            )

            rc, out, err = _call(["--engage-stubs", str(ws)])
            self.assertEqual(rc, 0, err)

            # Curated content was preserved byte-for-byte.
            self.assertEqual((ws / "SCOPE.md").read_text(), curated_scope)
            self.assertEqual(
                (ws / "OOS_CHECKLIST.md").read_text(),
                curated_oos,
            )

            # Half-bootstrapped marker file was left as is.
            self.assertIn(
                self.MARKER_MD,
                (ws / "SEVERITY.md").read_text(),
            )

            # Stubs that were missing got created (e.g. AUDIT.md).
            self.assertTrue((ws / "AUDIT.md").is_file())
            self.assertIn(
                self.MARKER_MD,
                (ws / "AUDIT.md").read_text(),
            )

    def test_engage_stubs_dry_run_does_not_write(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp) / "dry-ws"
            ws.mkdir(parents=True)

            rc, out, err = _call(["--engage-stubs", str(ws), "--dry-run"])
            self.assertEqual(rc, 0, err)
            self.assertIn("DRY RUN", out)
            # Each catalog entry shows up in the plan.
            for rel in self.EXPECTED_STUBS:
                self.assertIn(rel, out, f"missing from plan: {rel}")

            # Hard negative: no files were materialized.
            for rel in self.EXPECTED_STUBS:
                self.assertFalse(
                    (ws / rel).exists(),
                    f"dry-run wrote {rel} to disk",
                )
            # Not even the `concolic/` directory was created.
            self.assertFalse((ws / "concolic").exists())


class TestEngageStubsBackwardCompat(unittest.TestCase):
    """Sanity: --name flow still rejects missing args even though those
    flags are no longer marked `required=True` at the argparse layer
    (engage-stubs mode is the alternate entry point).
    """

    def test_name_required_when_engage_stubs_not_used(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            audits = Path(tmp)
            rc, out, err = _call([
                "--platform", "hackenproof",
                "--scope-url", "https://example.com/x",
                "--audits-dir", str(audits),
            ])
            self.assertNotEqual(rc, 0, "missing --name should fail")
            self.assertIn("name", err.lower())

    def test_platform_required_when_engage_stubs_not_used(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            audits = Path(tmp)
            rc, out, err = _call([
                "--name", "x",
                "--scope-url", "https://example.com/x",
                "--audits-dir", str(audits),
            ])
            self.assertNotEqual(rc, 0)
            self.assertIn("platform", err.lower())

    def test_scope_url_required_when_engage_stubs_not_used(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            audits = Path(tmp)
            rc, out, err = _call([
                "--name", "x",
                "--platform", "hackenproof",
                "--audits-dir", str(audits),
            ])
            self.assertNotEqual(rc, 0)
            self.assertIn("scope-url", err.lower())


if __name__ == "__main__":
    unittest.main()
