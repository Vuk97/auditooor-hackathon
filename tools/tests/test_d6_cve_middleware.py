from __future__ import annotations

import importlib.util
import json
import sys
import unittest
from io import StringIO
from contextlib import redirect_stdout
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL_PATH = REPO_ROOT / "tools" / "cve-middleware-reachability.py"
FIX_DIR = REPO_ROOT / "tools" / "detectors" / "fixtures" / "d6_cve_middleware"


def _load():
    spec = importlib.util.spec_from_file_location("cve_middleware_reachability", TOOL_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load cve-middleware-reachability tool")
    mod = importlib.util.module_from_spec(spec)
    sys.modules["cve_middleware_reachability"] = mod
    spec.loader.exec_module(mod)
    return mod


tool = _load()


def _run(middleware_file: Path, advisory_list: Path, fork: Path | None = None,
         strict: bool = False) -> tuple[dict, int]:
    argv = ["--middleware-file", str(middleware_file),
            "--advisory-list", str(advisory_list)]
    if fork is not None:
        argv += ["--fork-clone-path", str(fork)]
    if strict:
        argv += ["--strict"]
    buf = StringIO()
    with redirect_stdout(buf):
        rc = tool.main(argv)
    return json.loads(buf.getvalue()), rc


class TestD6CveMiddleware(unittest.TestCase):

    def test_stage2_detects_ibc_hooks_presence(self):
        report, rc = _run(
            FIX_DIR / "app_with_ibc_hooks.go",
            FIX_DIR / "advisory_list_sample.yaml",
        )
        self.assertEqual(rc, 0)
        by_id = {r["advisory_id"]: r for r in report["advisories"]}
        ibc_hooks = by_id["TEST-IBC-HOOKS-001"]
        self.assertEqual(ibc_hooks["reachability_status"], "open")
        self.assertIn("IBCHooksKeeper", ibc_hooks["matched_middleware"])
        self.assertEqual(ibc_hooks["blocking_middleware"], [])

    def test_stage2_detects_ibc_hooks_absence_blocks(self):
        report, rc = _run(
            FIX_DIR / "app_without_ibc_hooks.go",
            FIX_DIR / "advisory_list_sample.yaml",
        )
        self.assertEqual(rc, 0)
        by_id = {r["advisory_id"]: r for r in report["advisories"]}
        ibc_hooks = by_id["TEST-IBC-HOOKS-001"]
        self.assertEqual(ibc_hooks["reachability_status"], "blocked-by-middleware")
        self.assertEqual(ibc_hooks["matched_middleware"], [])
        self.assertIn("IBCHooksKeeper", ibc_hooks["blocking_middleware"])

        # cosmwasm should also be blocked on this fixture
        cw = by_id["TEST-CW-EXECUTE-001"]
        self.assertEqual(cw["reachability_status"], "blocked-by-middleware")
        self.assertIn("WasmKeeper", cw["blocking_middleware"])

        # ICA host IS wired -> open
        ica = by_id["TEST-ICA-HOST-001"]
        self.assertEqual(ica["reachability_status"], "open")
        self.assertIn("ICAHostKeeper", ica["matched_middleware"])

    def test_sentinel_condition_emitted_correctly(self):
        report, _ = _run(
            FIX_DIR / "app_without_ibc_hooks.go",
            FIX_DIR / "advisory_list_sample.yaml",
        )
        by_id = {r["advisory_id"]: r for r in report["advisories"]}
        sentinel = by_id["TEST-IBC-HOOKS-001"]["sentinel_fires_if"]
        self.assertIn("IBCHooksKeeper", sentinel)
        self.assertIn("fork adds", sentinel)

        # On the open-fixture, the sentinel should describe a monitor rather
        # than a fire-condition.
        report_open, _ = _run(
            FIX_DIR / "app_with_ibc_hooks.go",
            FIX_DIR / "advisory_list_sample.yaml",
        )
        by_id_open = {r["advisory_id"]: r for r in report_open["advisories"]}
        self.assertIn("already open", by_id_open["TEST-IBC-HOOKS-001"]["sentinel_fires_if"])

    def test_stage1_softskips_without_fork_clone_path(self):
        report, rc = _run(
            FIX_DIR / "app_without_ibc_hooks.go",
            FIX_DIR / "advisory_list_sample.yaml",
        )
        self.assertEqual(rc, 0)
        for adv in report["advisories"]:
            self.assertEqual(adv["ancestry_status"], "unknown")
            self.assertIn("Stage 1 skipped", adv["ancestry_evidence"])

    def test_schema_field_and_summary_present(self):
        report, _ = _run(
            FIX_DIR / "app_without_ibc_hooks.go",
            FIX_DIR / "advisory_list_sample.yaml",
        )
        self.assertEqual(report["schema"], "auditooor.cve_middleware_reachability.v1")
        self.assertEqual(report["count"], 3)
        self.assertIn("summary", report)
        self.assertIn("fix_missing_and_open", report["summary"])
        self.assertIn("fix_missing_and_blocked", report["summary"])


if __name__ == "__main__":
    unittest.main()
