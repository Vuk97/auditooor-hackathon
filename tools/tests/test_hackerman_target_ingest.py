#!/usr/bin/env python3
"""Tests for ``tools/hackerman-target-as-destination-ingest.py``.

Lane CAPABILITY-GAPS-33-35-HACKER-MCP-USABILITY (2026-05-26): Gap #35.
Active-audit workspaces (e.g. ``/Users/wolf/audits/hyperbridge``) were
NOT in the hackerman corpus, so MCP ``target_repo`` filter returned 0
rows on every live workspace. The ingest pipeline emits tier-3 synthetic
records derived from the workspace's own LIVE_TARGET_REPORT.json and
engage_report.md so the existing MCP callables surface them via the
target_repo filter.

These tests exercise the synthetic workspace fixtures (no real audit
workspace required) plus a basic end-to-end sanity test against the live
Hyperbridge workspace when present.
"""
from __future__ import annotations

import importlib.util
import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL_PATH = REPO_ROOT / "tools" / "hackerman-target-as-destination-ingest.py"
HYPERBRIDGE_WORKSPACE = Path("/Users/wolf/audits/hyperbridge")


def _load_module():
    spec = importlib.util.spec_from_file_location("target_ingest_for_tests", TOOL_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load {TOOL_PATH}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules["target_ingest_for_tests"] = mod
    spec.loader.exec_module(mod)
    return mod


MOD = _load_module()


def _make_synthetic_workspace(tmp: Path, slug: str = "exampleproj") -> Path:
    """Create a minimal workspace with LIVE_TARGET_REPORT + engage_report."""
    ws = tmp / slug
    ws.mkdir(parents=True, exist_ok=True)
    (ws / "src").mkdir(exist_ok=True)
    (ws / "src" / "Foo.sol").write_text("contract Foo {}\n")
    (ws / "src" / "Bar.sol").write_text("contract Bar {}\n")
    (ws / "docs").mkdir(exist_ok=True)
    live = {
        "schema": "auditooor.live_target_intelligence.v3",
        "workspace": str(ws),
        "entry_points": [
            {
                "cluster_id": "fee-on-transfer-not-accounted",
                "file_line": f"{ws}/src/Foo.sol:42",
                "hunt_priority": "HIGH-PRIORITY-HUNT",
                "matched_anti_patterns": ["solidity.fee-on-transfer", "solidity.wrapper-refund"],
                "engage_severity_score": 50.0,
            },
            {
                "cluster_id": "fee-on-transfer-not-accounted",
                "file_line": f"{ws}/src/Foo.sol:55",
                "hunt_priority": "MEDIUM-PRIORITY",
                "matched_anti_patterns": ["solidity.fee-on-transfer"],
                "engage_severity_score": 30.0,
            },
            {
                "cluster_id": "delegatecall-to-state-variable",
                "file_line": f"{ws}/src/Bar.sol:11",
                "hunt_priority": "HIGH-PRIORITY-HUNT",
                "matched_anti_patterns": ["solidity.delegatecall-untrusted"],
                "engage_severity_score": 60.0,
            },
        ],
    }
    (ws / "docs" / "LIVE_TARGET_REPORT.json").write_text(json.dumps(live, indent=2))
    engage_md = """# Engagement Report - exampleproj

## Clusters

### Cluster: `external-call-before-state-update` (1 hits)

- **[LOW] `external-call-before-state-update`** -- `src/Foo.sol:100`
  - snippet: `(bool sent,) = beneficiary.call{value: amount}("");`

### Cluster: `division-by-zero-division-to-zero-solvency` (1 hits)

- **[LOW] `division-to-zero-solvency`** -- `src/Bar.sol:200`
  - snippet: `uint256 a = total / scale;`
"""
    (ws / "engage_report.md").write_text(engage_md)
    return ws


class TestTargetIngest(unittest.TestCase):
    def test_workspace_slug_strips_main_suffix(self):
        ws_dir = Path("/some/path/exampleproj-main")
        # We synthesise the path; only the name matters.
        self.assertEqual(MOD._detect_workspace_slug(ws_dir), "exampleproj")

    def test_workspace_slug_strips_master_suffix(self):
        ws_dir = Path("/some/path/exampleproj-master")
        self.assertEqual(MOD._detect_workspace_slug(ws_dir), "exampleproj")

    def test_workspace_slug_preserves_other_dashes(self):
        ws_dir = Path("/some/path/dlt-workflow-gaps")
        self.assertEqual(MOD._detect_workspace_slug(ws_dir), "dlt-workflow-gaps")

    def test_detect_target_domain_known(self):
        self.assertEqual(MOD._detect_target_domain("hyperbridge"), "bridge")
        self.assertEqual(MOD._detect_target_domain("polymarket"), "dex")
        self.assertEqual(MOD._detect_target_domain("dydx"), "dex")

    def test_detect_target_domain_unknown_defaults_to_bridge(self):
        self.assertEqual(MOD._detect_target_domain("never-heard-of"), "bridge")

    def test_detect_language_by_extension(self):
        self.assertEqual(MOD._detect_language("foo/bar.sol"), "solidity")
        self.assertEqual(MOD._detect_language("foo/bar.rs"), "rust")
        self.assertEqual(MOD._detect_language("foo/bar.go"), "go")
        self.assertEqual(MOD._detect_language("foo/bar.move"), "move")
        self.assertEqual(MOD._detect_language("foo/bar.unknown"), "unknown")

    def test_parse_engage_clusters(self):
        text = """### Cluster: `cluster-a` (2 hits)

- **[HIGH] `det-a`** -- `path/a.sol:10`
  - snippet: `bad code here`
- **[MEDIUM] `det-a`** -- `path/a.sol:20`
  - snippet: `another bad line`

### Cluster: `cluster-b` (1 hits)

- **[LOW] `det-b`** -- `path/b.sol:5`
  - snippet: `low risk`
"""
        clusters = MOD._parse_engage_clusters(text)
        self.assertEqual(len(clusters), 2)
        self.assertEqual(clusters[0]["cluster_id"], "cluster-a")
        self.assertEqual(len(clusters[0]["hits"]), 2)
        self.assertEqual(clusters[0]["hits"][0]["severity"], "HIGH")
        self.assertEqual(clusters[0]["hits"][0]["line_number"], 10)
        self.assertEqual(clusters[1]["hits"][0]["snippet"], "low risk")

    def test_ingest_synthetic_workspace_emits_records(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            ws = _make_synthetic_workspace(tmp_path)
            tags_root = tmp_path / "tags"
            portable_root = tmp_path / "portable"
            result = MOD.ingest(
                ws,
                tags_root=tags_root,
                portable_root=portable_root,
            )
            self.assertTrue(result["ok"])
            self.assertEqual(result["workspace_slug"], "exampleproj")
            # LIVE has 3 entry_points (one cluster has 2, all unique file:line)
            # engage has 2 hits in different clusters/files -> 5 dedup'd.
            self.assertGreaterEqual(result["records_emitted"], 4)
            # Portable JSONL exists and is non-empty
            portable_path = portable_root / "exampleproj" / "hackerman_target_records.jsonl"
            self.assertTrue(portable_path.is_file())
            lines = [
                ln for ln in portable_path.read_text(encoding="utf-8").splitlines()
                if ln.strip()
            ]
            self.assertEqual(len(lines), result["records_emitted"])
            # Each record is a valid hackerman_record.v1.1 envelope
            for ln in lines[:3]:
                rec = json.loads(ln)
                self.assertEqual(rec["schema_version"], MOD.SCHEMA_VERSION)
                # target_repo uses owner/repo schema; for live workspaces
                # we synthesise `local-workspace/<slug>` so the corpus
                # validator accepts the record.
                self.assertEqual(rec["target_repo"], "local-workspace/exampleproj")
                self.assertEqual(rec["target_domain"], "bridge")
                self.assertEqual(rec["verification_tier"], "tier-3-synthetic-taxonomy-anchored")
                self.assertIn("function_shape", rec)
                self.assertIn("shape_tags", rec["function_shape"])

    def test_ingest_idempotent(self):
        """Running ingest twice should produce the same output set."""
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            ws = _make_synthetic_workspace(tmp_path)
            tags_root = tmp_path / "tags"
            portable_root = tmp_path / "portable"
            r1 = MOD.ingest(ws, tags_root=tags_root, portable_root=portable_root)
            r2 = MOD.ingest(ws, tags_root=tags_root, portable_root=portable_root)
            self.assertEqual(r1["records_emitted"], r2["records_emitted"])

    def test_ingest_emit_passes_existing_record_validator(self):
        """Emit shape must parse through the existing extractor without errors."""
        # Load the existing extract_rows validator
        ep_path = REPO_ROOT / "tools" / "hackerman-exploit-predicates.py"
        spec = importlib.util.spec_from_file_location("hep_for_test", ep_path)
        hep = importlib.util.module_from_spec(spec)
        sys.modules["hep_for_test"] = hep
        spec.loader.exec_module(hep)
        import yaml

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            ws = _make_synthetic_workspace(tmp_path)
            tags_root = tmp_path / "tags"
            portable_root = tmp_path / "portable"
            MOD.ingest(ws, tags_root=tags_root, portable_root=portable_root)
            subtree = tags_root / "exampleproj_target"
            self.assertTrue(subtree.is_dir())
            yaml_files = list(subtree.glob("*/record.yaml"))
            self.assertGreater(len(yaml_files), 0)
            for yp in yaml_files[:5]:
                doc = yaml.safe_load(yp.read_text(encoding="utf-8"))
                self.assertTrue(hep._is_record(doc), f"{yp} not recognised as hackerman_record")
                errors = hep._validate_record(doc)
                self.assertEqual(errors, [], f"{yp} validator errors: {errors}")

    def test_ingest_dry_run_no_writes(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            ws = _make_synthetic_workspace(tmp_path)
            tags_root = tmp_path / "tags"
            portable_root = tmp_path / "portable"
            result = MOD.ingest(
                ws,
                tags_root=tags_root,
                portable_root=portable_root,
                dry_run=True,
            )
            self.assertTrue(result["ok"])
            self.assertGreater(result["records_emitted"], 0)
            self.assertTrue(result["dry_run"])
            # No files written
            self.assertFalse(tags_root.exists())
            self.assertFalse(portable_root.exists())

    def test_ingest_missing_workspace_returns_error(self):
        result = MOD.ingest(Path("/nonexistent/path/abcdef"))
        self.assertFalse(result["ok"])
        self.assertIn("workspace_not_found", result["reason"])
        self.assertEqual(result["records_emitted"], 0)

    def test_max_per_cluster_caps_emissions(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            ws = _make_synthetic_workspace(tmp_path)
            # The synthetic ws has 2 fee-on-transfer entries; cap to 1
            tags_root = tmp_path / "tags"
            portable_root = tmp_path / "portable"
            result = MOD.ingest(
                ws,
                tags_root=tags_root,
                portable_root=portable_root,
                max_per_cluster=1,
            )
            # Manually inspect: live had 2 fee-on-transfer + 1 delegatecall = 3
            # capped to 1 each = 2; engage adds 2 more clusters -> 4 total
            self.assertLessEqual(result["live_hits"], 2)

    @unittest.skipUnless(
        HYPERBRIDGE_WORKSPACE.is_dir(),
        f"Hyperbridge workspace not present at {HYPERBRIDGE_WORKSPACE}",
    )
    def test_ingest_hyperbridge_live_anchor(self):
        """L33-anchor smoke test against the live Hyperbridge workspace.

        Writes to a tempdir (NOT the canonical corpus) so the test is
        independent of corpus state.
        """
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            tags_root = tmp_path / "tags"
            portable_root = tmp_path / "portable"
            result = MOD.ingest(
                HYPERBRIDGE_WORKSPACE,
                tags_root=tags_root,
                portable_root=portable_root,
            )
            self.assertTrue(result["ok"])
            self.assertEqual(result["workspace_slug"], "hyperbridge")
            # Should emit at least 10 records (acceptance criterion)
            self.assertGreaterEqual(result["records_emitted"], 10)
            portable = portable_root / "hyperbridge" / "hackerman_target_records.jsonl"
            self.assertTrue(portable.is_file())


def _extract_make_target_body(makefile_text: str, target: str) -> str:
    """Return the recipe body for ``target`` (lines until the next target/blank-rule).

    A make target body is the run of lines after ``<target>:`` that are either
    indented with a tab (recipe lines) or blank. We stop at the first line that
    looks like a new rule header (``name:`` at column 0) or EOF.
    """
    lines = makefile_text.splitlines()
    out: list[str] = []
    capturing = False
    for line in lines:
        if not capturing:
            # Match `<target>:` possibly with prereqs, at column 0.
            stripped = line.rstrip()
            if stripped == f"{target}:" or stripped.startswith(f"{target}:"):
                capturing = True
            continue
        # We are inside the body. Recipe lines are tab-indented; allow blanks.
        if line.startswith("\t"):
            out.append(line)
            continue
        if line.strip() == "":
            out.append(line)
            continue
        # A non-tab, non-blank line ends the recipe.
        break
    return "\n".join(out)


class TestTargetIngestMakeWiring(unittest.TestCase):
    """Wave-2 #17 wiring guard: a future edit that drops the ingest wiring must
    fail CI (fails pre-fix, passes post-fix)."""

    def setUp(self):
        self.makefile = (REPO_ROOT / "Makefile").read_text(encoding="utf-8")

    def test_hackerman_target_ingest_target_exists(self):
        # A non-phony recipe target must exist at column 0.
        self.assertRegex(
            self.makefile,
            r"(?m)^hackerman-target-ingest:",
            "Makefile is missing the `hackerman-target-ingest:` recipe target",
        )

    def test_ingest_target_runs_producer_and_both_sidecars(self):
        body = _extract_make_target_body(self.makefile, "hackerman-target-ingest")
        self.assertIn(
            "hackerman-target-as-destination-ingest.py",
            body,
            "ingest target must invoke the producer",
        )
        self.assertIn(
            "hackerman-exploit-predicates-sidecar.py",
            body,
            "ingest target must refresh the exploit-predicates sidecar",
        )
        self.assertIn(
            "hackerman-chain-candidates-sidecar.py",
            body,
            "ingest target must refresh the chain-candidates sidecar",
        )

    def test_engage_target_references_ingest(self):
        body = _extract_make_target_body(self.makefile, "engage")
        self.assertIn(
            "hackerman-target-ingest",
            body,
            "the `engage` target must auto-invoke `hackerman-target-ingest` so "
            "every engage run makes the workspace queryable (wiring guard)",
        )


class TestTargetIngestFunctionalCLI(unittest.TestCase):
    """Functional smoke: drive the producer the way the make target does, but
    redirect tags/portable roots into a tempdir so the canonical corpus is not
    touched. Asserts records land + are idempotent across re-runs."""

    def test_cli_emits_records_and_is_idempotent(self):
        import subprocess

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            ws = _make_synthetic_workspace(tmp_path, slug="wiredproj")
            tags_root = tmp_path / "tags"
            portable_root = tmp_path / "portable"

            def _run() -> dict:
                proc = subprocess.run(
                    [
                        sys.executable,
                        str(TOOL_PATH),
                        "--workspace",
                        str(ws),
                        "--tags-root",
                        str(tags_root),
                        "--portable-root",
                        str(portable_root),
                        "--json",
                    ],
                    capture_output=True,
                    text=True,
                )
                self.assertEqual(
                    proc.returncode, 0, f"ingest CLI failed: {proc.stderr}\n{proc.stdout}"
                )
                # The CLI prints a JSON summary on stdout under --json.
                return json.loads(proc.stdout.strip().splitlines()[-1])

            r1 = _run()
            self.assertTrue(r1["ok"])
            self.assertEqual(r1["workspace_slug"], "wiredproj")
            self.assertGreaterEqual(r1["records_emitted"], 1)

            # (a) tags subtree has >=1 record.yaml
            subtree = tags_root / "wiredproj_target"
            self.assertTrue(subtree.is_dir())
            yaml_files = list(subtree.glob("*/record.yaml"))
            self.assertGreaterEqual(len(yaml_files), 1)

            # (b) portable JSONL has the records
            portable = portable_root / "wiredproj" / "hackerman_target_records.jsonl"
            self.assertTrue(portable.is_file())
            jsonl_lines = [
                ln for ln in portable.read_text(encoding="utf-8").splitlines() if ln.strip()
            ]
            self.assertEqual(len(jsonl_lines), r1["records_emitted"])

            # (c) idempotency: re-run yields the same record count + jsonl line count
            r2 = _run()
            self.assertEqual(r2["records_emitted"], r1["records_emitted"])
            jsonl_lines_2 = [
                ln for ln in portable.read_text(encoding="utf-8").splitlines() if ln.strip()
            ]
            self.assertEqual(len(jsonl_lines_2), len(jsonl_lines))


if __name__ == "__main__":
    unittest.main()
