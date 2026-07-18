"""Tests for tools/wave2-a-pre-merge-preflight.py.

Exercises the JSON envelope shape and the four expected outcome shapes:

  1. PASS  - everything present, defaults patched.
  2. FAIL-stale-fixture - pr726-checklist still references wave-1 defaults.
  3. FAIL-coverage - close-readiness companion missing.
  4. FAIL-schema - v1 or v1.1 schema file missing.
"""
from __future__ import annotations

import importlib.util
import json
import shutil
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL_PATH = REPO_ROOT / "tools" / "wave2-a-pre-merge-preflight.py"


def _load_module():
    spec = importlib.util.spec_from_file_location(
        "wave2_a_pre_merge_preflight", TOOL_PATH
    )
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


class FakeWorkspaceBuilder:
    """Build a minimal in-tmpdir workspace that satisfies preflight sub-checks."""

    def __init__(self, root: Path) -> None:
        self.root = root

    def write_pre_merge_py(self, *, with_overrides: bool = False) -> None:
        tools = self.root / "tools"
        tools.mkdir(parents=True, exist_ok=True)
        override_clause = ""
        if with_overrides:
            override_clause = '"PR_NUMBER=728", "BRANCH=wave-2-corpus-migration",'
        (tools / "hackerman-pre-merge.py").write_text(
            "STEPS: list = [\n"
            "    {\n"
            f"        'argv': ['make', 'hackerman-pr726-merge-checklist', {override_clause}],\n"
            "    },\n"
            "]\n\n"
            "def compute_overall(steps):\n"
            "    return 'PASS'\n",
            encoding="utf-8",
        )

    def write_makefile(self, *, missing: list[str] | None = None) -> None:
        targets = [
            "hackerman-all",
            "docs-check",
            "hackerman-docs-cross-link-audit",
            "hackerman-pr726-merge-checklist",
            "hackerman-mcp-smoke-test",
        ]
        missing_set = set(missing or [])
        body = ""
        for t in targets:
            if t in missing_set:
                continue
            body += f"{t}:\n\t@echo {t}\n\n"
        (self.root / "Makefile").write_text(body, encoding="utf-8")

    def write_pr726_checklist(
        self,
        *,
        pr_default: int = 726,
        branch_default: str = "wave-1-hackerman-capability-lift",
    ) -> None:
        tools = self.root / "tools"
        tools.mkdir(parents=True, exist_ok=True)
        (tools / "hackerman-pr726-merge-checklist.py").write_text(
            f"DEFAULT_PR_NUMBER = {pr_default}\n"
            f'DEFAULT_BRANCH = "{branch_default}"\n',
            encoding="utf-8",
        )

    def write_schemas(self, *, missing: list[str] | None = None) -> None:
        sch = self.root / "audit" / "corpus_tags" / "schemas"
        sch.mkdir(parents=True, exist_ok=True)
        names = [
            "auditooor.hackerman_record.v1.schema.json",
            "auditooor.hackerman_record.v1.1.schema.json",
        ]
        missing_set = set(missing or [])
        for n in names:
            if n in missing_set:
                continue
            (sch / n).write_text("{}", encoding="utf-8")

    def write_close_readiness(self, *, present: bool = True) -> None:
        tools = self.root / "tools"
        tools.mkdir(parents=True, exist_ok=True)
        if present:
            (tools / "wave2-a-close-readiness.py").write_text(
                "# stub\n", encoding="utf-8"
            )

    def build_pass(self) -> None:
        self.write_pre_merge_py(with_overrides=True)
        self.write_makefile()
        self.write_pr726_checklist(pr_default=728, branch_default="wave-2-corpus-migration")
        self.write_schemas()
        self.write_close_readiness(present=True)


class PreflightTests(unittest.TestCase):
    def setUp(self) -> None:
        self.mod = _load_module()
        self.tmpdir = Path(tempfile.mkdtemp(prefix="wave2a_preflight_"))

    def tearDown(self) -> None:
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_pass_when_everything_present_and_defaults_patched(self) -> None:
        builder = FakeWorkspaceBuilder(self.tmpdir)
        builder.build_pass()
        payload = self.mod.run_preflight(self.tmpdir, "2026-05-16T00:00:00Z")
        self.assertEqual(payload["schema"], self.mod.SCHEMA)
        self.assertEqual(payload["overall_status"], "READY")
        statuses = {c["name"]: c["status"] for c in payload["sub_checks"]}
        self.assertEqual(statuses["pre_merge_script_present"], "PASS")
        self.assertEqual(statuses["step_dependencies_resolvable"], "PASS")
        self.assertEqual(statuses["pr726_checklist_stale_branch"], "PASS")
        self.assertEqual(statuses["schema_files_present"], "PASS")
        self.assertEqual(statuses["close_readiness_companion_present"], "PASS")
        # Re-serialize round-trip.
        as_str = json.dumps(payload, sort_keys=True)
        self.assertIn("auditooor.wave2_a_pre_merge_preflight.v1", as_str)

    def test_fail_stale_fixture_pr726_defaults(self) -> None:
        builder = FakeWorkspaceBuilder(self.tmpdir)
        builder.write_pre_merge_py(with_overrides=False)
        builder.write_makefile()
        builder.write_pr726_checklist(
            pr_default=726, branch_default="wave-1-hackerman-capability-lift"
        )
        builder.write_schemas()
        builder.write_close_readiness(present=True)
        payload = self.mod.run_preflight(self.tmpdir, "2026-05-16T00:00:00Z")
        self.assertEqual(payload["overall_status"], "BLOCKED")
        statuses = {c["name"]: c["status"] for c in payload["sub_checks"]}
        self.assertEqual(statuses["pr726_checklist_stale_branch"], "FAIL")
        # Identify the stale-fixture sub-check carries the detail clue.
        stale = next(
            c for c in payload["sub_checks"]
            if c["name"] == "pr726_checklist_stale_branch"
        )
        self.assertIn("DEFAULT_PR_NUMBER", stale["detail"])
        self.assertIn("728", stale["detail"])

    def test_fail_coverage_close_readiness_missing(self) -> None:
        builder = FakeWorkspaceBuilder(self.tmpdir)
        builder.write_pre_merge_py(with_overrides=True)
        builder.write_makefile()
        builder.write_pr726_checklist(
            pr_default=728, branch_default="wave-2-corpus-migration"
        )
        builder.write_schemas()
        builder.write_close_readiness(present=False)
        payload = self.mod.run_preflight(self.tmpdir, "2026-05-16T00:00:00Z")
        # close-readiness missing is PARTIAL, not BLOCKED.
        self.assertEqual(payload["overall_status"], "PARTIAL")
        statuses = {c["name"]: c["status"] for c in payload["sub_checks"]}
        self.assertEqual(statuses["close_readiness_companion_present"], "FAIL")
        self.assertEqual(statuses["pr726_checklist_stale_branch"], "PASS")

    def test_fail_schema_v1_1_missing(self) -> None:
        builder = FakeWorkspaceBuilder(self.tmpdir)
        builder.write_pre_merge_py(with_overrides=True)
        builder.write_makefile()
        builder.write_pr726_checklist(
            pr_default=728, branch_default="wave-2-corpus-migration"
        )
        builder.write_schemas(missing=["auditooor.hackerman_record.v1.1.schema.json"])
        builder.write_close_readiness(present=True)
        payload = self.mod.run_preflight(self.tmpdir, "2026-05-16T00:00:00Z")
        self.assertEqual(payload["overall_status"], "PARTIAL")
        statuses = {c["name"]: c["status"] for c in payload["sub_checks"]}
        self.assertEqual(statuses["schema_files_present"], "FAIL")
        # Workspace path round-trips.
        self.assertEqual(payload["workspace"], str(self.tmpdir))

    def test_makefile_missing_target_fails_dependencies_check(self) -> None:
        builder = FakeWorkspaceBuilder(self.tmpdir)
        builder.write_pre_merge_py(with_overrides=True)
        builder.write_makefile(missing=["hackerman-mcp-smoke-test"])
        builder.write_pr726_checklist(
            pr_default=728, branch_default="wave-2-corpus-migration"
        )
        builder.write_schemas()
        builder.write_close_readiness(present=True)
        payload = self.mod.run_preflight(self.tmpdir, "2026-05-16T00:00:00Z")
        statuses = {c["name"]: c["status"] for c in payload["sub_checks"]}
        self.assertEqual(statuses["step_dependencies_resolvable"], "FAIL")
        self.assertEqual(payload["overall_status"], "PARTIAL")

    def test_expected_post_phase3_field_populated(self) -> None:
        builder = FakeWorkspaceBuilder(self.tmpdir)
        builder.build_pass()
        payload = self.mod.run_preflight(self.tmpdir, "2026-05-16T00:00:00Z")
        self.assertIn("expected_post_phase3", payload)
        self.assertIsInstance(payload["expected_post_phase3"], list)
        self.assertTrue(
            any("hackerman-all" in s for s in payload["expected_post_phase3"]),
            "expected_post_phase3 should reference hackerman-all sub-stages",
        )


if __name__ == "__main__":
    unittest.main()
