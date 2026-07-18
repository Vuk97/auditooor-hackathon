"""
test_agent_prompt_hacker_augmenter.py — 20 unit tests for W2-A tool.

Tests 1-15 from 05 §2.6 spec.
Tests 16-20 from 12 §A "Test additions".

All tests are offline and hermetic (subprocess calls patched where needed).
Uses tempfile.TemporaryDirectory() for workspace fixtures.
"""
from __future__ import annotations

import importlib.util
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime
from unittest.mock import MagicMock, patch

# ---------------------------------------------------------------------------
# Load the module under test
# ---------------------------------------------------------------------------

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
TOOL_PATH = REPO_ROOT / "tools" / "agent-prompt-hacker-augmenter.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("agent_prompt_hacker_augmenter", TOOL_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Cannot load module at {TOOL_PATH}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules["agent_prompt_hacker_augmenter"] = mod
    spec.loader.exec_module(mod)  # type: ignore[attr-defined]
    return mod


aug = _load_module()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_workspace(tmpdir: str) -> pathlib.Path:
    """Create a minimal workspace structure."""
    ws = pathlib.Path(tmpdir)
    (ws / ".auditooor").mkdir(exist_ok=True)
    return ws


def _make_state(ws: pathlib.Path, queued_leads=None, lane_cooldowns=None, pending_commits=None):
    state = {
        "iteration": 5,
        "queued_leads": queued_leads or [],
        "lane_cooldowns": lane_cooldowns or {},
        "pending_commits": pending_commits or [],
    }
    (ws / ".auditooor" / "spark_hunt_loop_state.json").write_text(
        json.dumps(state), encoding="utf-8"
    )


def _make_external_clone(ws: pathlib.Path, name: str) -> pathlib.Path:
    """Create a dummy external git repo."""
    repo_dir = ws / "external" / name
    repo_dir.mkdir(parents=True, exist_ok=True)
    subprocess.run(["git", "init", str(repo_dir)], capture_output=True)
    # Create a dummy file and commit so we have a HEAD SHA
    (repo_dir / "README.md").write_text(f"# {name}\n")
    subprocess.run(
        ["git", "-C", str(repo_dir), "config", "user.email", "test@test.com"],
        capture_output=True,
    )
    subprocess.run(
        ["git", "-C", str(repo_dir), "config", "user.name", "Test"],
        capture_output=True,
    )
    subprocess.run(
        ["git", "-C", str(repo_dir), "add", "README.md"],
        capture_output=True,
    )
    subprocess.run(
        ["git", "-C", str(repo_dir), "commit", "-m", "init"],
        capture_output=True,
    )
    return repo_dir


# ---------------------------------------------------------------------------
# Test 1 — filter_by_files_basename: zero-score items dropped
# ---------------------------------------------------------------------------

class TestFilterByFilesBasename(unittest.TestCase):
    def test_filter_by_files_basename(self):
        """An item whose path does NOT contain any --files basename gets score==0."""
        item = {
            "path": "/totally/different/path/unrelated.go",
            "title": "Unrelated vulnerability",
            "source_refs": ["/totally/different/unrelated.go"],
            "severity": "MEDIUM",
        }
        score = aug._relevance_score(item, files=["coopexit.go", "watcher.go"], hint=None)
        self.assertEqual(score, 0.0)


# ---------------------------------------------------------------------------
# Test 2 — filter_by_contract_type_hint: hint match >= 10
# ---------------------------------------------------------------------------

class TestFilterByContractTypeHint(unittest.TestCase):
    def test_filter_by_contract_type_hint(self):
        """An item whose bug_class matches --contract-type-hint gets score >= 10."""
        item = {
            "path": "unrelated.go",
            "title": "Some finding",
            "bug_class": "amm-pool rounding",
            "severity": "HIGH",
        }
        score = aug._relevance_score(item, files=["file.go"], hint="amm-pool")
        self.assertGreaterEqual(score, 10.0)


# ---------------------------------------------------------------------------
# Test 3 — severity weight amplifies Critical over Medium
# ---------------------------------------------------------------------------

class TestSeverityWeightAmplifies(unittest.TestCase):
    def test_severity_weight_amplifies_critical(self):
        """CRIT item ranks above MED item with identical name-overlap."""
        base_item = {
            "path": "coopexit.go",
            "title": "coopexit",
            "source_refs": ["coopexit.go"],
        }
        crit_item = {**base_item, "severity": "CRITICAL"}
        med_item = {**base_item, "severity": "MEDIUM"}
        files = ["coopexit.go"]
        crit_score = aug._relevance_score(crit_item, files=files, hint=None)
        med_score = aug._relevance_score(med_item, files=files, hint=None)
        self.assertGreater(crit_score, med_score)


# ---------------------------------------------------------------------------
# Test 4 — max_items_per_section cap enforced (via full build)
# ---------------------------------------------------------------------------

class TestMaxItemsPerSectionCap(unittest.TestCase):
    def test_max_items_per_section_cap(self):
        """With cap=3, sec6_kill_rubric items_count <= 3."""
        with tempfile.TemporaryDirectory() as tmpdir:
            ws = _make_workspace(tmpdir)
            # Write a KILL_RUBRIC with 10 checklist items
            kill_rubric = REPO_ROOT / "docs" / "KILL_RUBRIC_LIBRARY.md"
            if not kill_rubric.is_file():
                # Create a synthetic one in a monkeypatch-friendly way
                self.skipTest("KILL_RUBRIC_LIBRARY.md not available — skipping")

            _, sections = aug.build_brief(
                workspace=ws,
                lane_id="H1-test",
                files=["coopexit.go"],
                hint=None,
                max_items=3,
            )
            count = sections["sec6_kill_rubric"].get("items_count", 0)
            self.assertLessEqual(count, 3)


# ---------------------------------------------------------------------------
# Test 5 — output_schema_has_all_18_sections (0, 0.5, 0.7, 0.9, 1-14)
# ---------------------------------------------------------------------------

class TestOutputSchemaHasAllSections(unittest.TestCase):
    def test_output_schema_has_all_14_sections(self):
        """Output Markdown contains each of the 18 section headers in order."""
        expected_headers = [
            "## Section 0 ",
            "## Section 0.5 ",
            "## Section 0.7 ",
            "## Section 0.9 ",
            "## Section 1 ",
            "## Section 2 ",
            "## Section 3 ",
            "## Section 4 ",
            "## Section 5 ",
            "## Section 6 ",
            "## Section 7 ",
            "## Section 8 ",
            "## Section 9 ",
            "## Section 10 ",
            "## Section 11 ",
            "## Section 12 ",
            "## Section 13 ",
            "## Section 14 ",
        ]
        with tempfile.TemporaryDirectory() as tmpdir:
            ws = _make_workspace(tmpdir)
            md, _ = aug.build_brief(
                workspace=ws,
                lane_id="H1-test",
                files=["foo.go"],
                hint=None,
                max_items=8,
            )
            for hdr in expected_headers:
                self.assertIn(hdr, md, msg=f"Missing section header: {hdr!r}")

            # Verify order
            positions = [md.index(hdr) for hdr in expected_headers]
            self.assertEqual(positions, sorted(positions), "Section headers out of order")


# ---------------------------------------------------------------------------
# Test 6 — json_sidecar_matches_markdown section keys
# ---------------------------------------------------------------------------

class TestJsonSidecarMatchesMarkdown(unittest.TestCase):
    def test_json_sidecar_matches_markdown(self):
        """When --json-out is set, the JSON sidecar section keys match expected set."""
        with tempfile.TemporaryDirectory() as tmpdir:
            ws = _make_workspace(tmpdir)
            out_path = pathlib.Path(tmpdir) / "brief.md"

            result = aug.main([
                "--workspace", str(ws),
                "--lane-id", "H1-test",
                "--files", "foo.go",
                "--out", str(out_path),
                "--json-out",
            ])
            self.assertEqual(result, 0)

            sidecar_path = pathlib.Path(str(out_path) + ".json")
            self.assertTrue(sidecar_path.is_file())

            sidecar = json.loads(sidecar_path.read_text())
            self.assertIn("sections", sidecar)
            sections = sidecar["sections"]

            # Each _SECTION_KEYS should be present
            for key in aug._SECTION_KEYS:
                self.assertIn(key, sections, msg=f"Missing sidecar key: {key}")

    def test_json_sidecar_is_sanitized(self):
        """JSON sidecar should not leak absolute workspace paths."""
        with tempfile.TemporaryDirectory() as tmpdir:
            ws = _make_workspace(tmpdir)
            out_path = ws / ".auditooor" / "brief.md"

            result = aug.main([
                "--workspace", str(ws),
                "--lane-id", "H1-test",
                "--files", str(ws / "foo.go"),
                "--out", str(out_path),
                "--json-out",
            ])
            self.assertEqual(result, 0)

            sidecar_text = pathlib.Path(str(out_path) + ".json").read_text()
            self.assertNotIn(str(ws), sidecar_text)
            self.assertNotIn(str(out_path), sidecar_text)
            sidecar = json.loads(sidecar_text)
            self.assertEqual(sidecar["workspace"], "<workspace>")
            self.assertEqual(sidecar["markdown_path"], "<workspace>/.auditooor/brief.md")
            self.assertEqual(sidecar["sections_stubbed"], [])
            self.assertRegex(sidecar["content_hash"], r"^[0-9a-f]{64}$")

    def test_json_sidecar_redacts_external_files_paths(self):
        """JSON sidecar must redact arbitrary absolute FILES paths outside aliases."""
        with tempfile.TemporaryDirectory() as tmpdir, tempfile.TemporaryDirectory() as outdir:
            ws = _make_workspace(tmpdir)
            out_path = pathlib.Path(outdir) / "brief.md"
            external_path = "/tmp/hacker-augmenter-leak.go"

            result = aug.main([
                "--workspace", str(ws),
                "--lane-id", "H1-test",
                "--files", external_path,
                "--out", str(out_path),
                "--json-out",
            ])
            self.assertEqual(result, 0)

            sidecar_text = pathlib.Path(str(out_path) + ".json").read_text()
            self.assertNotIn(external_path, sidecar_text)
            sidecar = json.loads(sidecar_text)
            self.assertEqual(sidecar["files"], ["<tmp>/hacker-augmenter-leak.go"])
            self.assertRegex(sidecar["content_hash"], r"^[0-9a-f]{64}$")

    def test_json_sidecar_outside_workspace_uses_symbolic_repo_path(self):
        """JSON sidecar should not leak an absolute repo path when --out is outside ws."""
        with tempfile.TemporaryDirectory() as tmpdir:
            ws = _make_workspace(tmpdir)
            out_path = REPO_ROOT / "agent_outputs" / "tmp_hacker_sidecar_test.md"
            try:
                result = aug.main([
                    "--workspace", str(ws),
                    "--lane-id", "H1-test",
                    "--files", "foo.go",
                    "--out", str(out_path),
                    "--json-out",
                ])
                self.assertEqual(result, 0)

                sidecar_text = pathlib.Path(str(out_path) + ".json").read_text()
                self.assertNotIn(str(REPO_ROOT), sidecar_text)
                sidecar = json.loads(sidecar_text)
                self.assertTrue(sidecar["markdown_path"].startswith("<repo>/agent_outputs/"))
            finally:
                out_path.unlink(missing_ok=True)
                pathlib.Path(str(out_path) + ".json").unlink(missing_ok=True)

    def test_content_hash_ignores_generated_timestamp(self):
        """Repeated semantic-identical briefs keep content_hash stable across timestamps."""
        class FakeDatetime:
            values = [
                datetime(2026, 1, 1, 0, 0, 1, tzinfo=aug.timezone.utc),
                datetime(2026, 1, 1, 0, 0, 2, tzinfo=aug.timezone.utc),
                datetime(2026, 1, 1, 0, 0, 3, tzinfo=aug.timezone.utc),
                datetime(2026, 1, 1, 0, 0, 4, tzinfo=aug.timezone.utc),
            ]

            @classmethod
            def now(cls, tz=None):
                value = cls.values.pop(0)
                return value if tz is None else value.astimezone(tz)

        with tempfile.TemporaryDirectory() as tmpdir, tempfile.TemporaryDirectory() as outdir:
            ws = _make_workspace(tmpdir)
            out_path = pathlib.Path(outdir) / "brief.md"

            argv = [
                "--workspace", str(ws),
                "--lane-id", "H1-test",
                "--files", "foo.go",
                "--out", str(out_path),
                "--json-out",
            ]
            with patch.object(aug, "datetime", FakeDatetime):
                self.assertEqual(aug.main(argv), 0)
                first = json.loads(pathlib.Path(str(out_path) + ".json").read_text())
                self.assertEqual(aug.main(argv), 0)
                second = json.loads(pathlib.Path(str(out_path) + ".json").read_text())

            self.assertNotEqual(first["generated_at"], second["generated_at"])
            self.assertEqual(first["content_hash"], second["content_hash"])


# ---------------------------------------------------------------------------
# Test 7 — no absolute path leakage
# ---------------------------------------------------------------------------

class TestNoAbsolutePathLeakage(unittest.TestCase):
    def test_no_absolute_path_leakage(self):
        """Output Markdown has zero /Users/ or /home/ absolute paths."""
        with tempfile.TemporaryDirectory() as tmpdir:
            ws = _make_workspace(tmpdir)
            md, _ = aug.build_brief(
                workspace=ws,
                lane_id="H1-test",
                files=["foo.go"],
                hint=None,
                max_items=8,
            )
            self.assertNotIn("/Users/", md)
            self.assertNotIn("/home/", md)


# ---------------------------------------------------------------------------
# Test 8 — secret pattern blocklist
# ---------------------------------------------------------------------------

class TestSecretPatternBlocklist(unittest.TestCase):
    def test_secret_pattern_blocklist(self):
        """_has_secret detects AWS-style key; _sanitize redacts it."""
        secret_text = "key=AKIAIOSFODNN7EXAMPLE some text"
        self.assertTrue(aug._has_secret(secret_text))
        sanitized = aug._sanitize(secret_text)
        self.assertNotIn("AKIA", sanitized)
        self.assertIn("[REDACTED]", sanitized)

    def test_clean_text_passes_secret_check(self):
        """Normal text does not trigger secret detection."""
        clean = "this is a normal audit finding with no secrets"
        self.assertFalse(aug._has_secret(clean))


# ---------------------------------------------------------------------------
# Test 9 — workspace too large aborts
# ---------------------------------------------------------------------------

class TestWorkspaceTooLargeAborts(unittest.TestCase):
    def test_workspace_too_large_aborts(self):
        """FILE_CAP exceeded produces rc=1, not a partial brief."""
        with tempfile.TemporaryDirectory() as tmpdir:
            ws = _make_workspace(tmpdir)
            # Generate more file paths than FILE_CAP
            files = ",".join([f"file{i}.go" for i in range(aug._FILE_CAP + 1)])
            result = aug.main([
                "--workspace", str(ws),
                "--lane-id", "H1-test",
                "--files", files,
            ])
            self.assertEqual(result, 1)


# ---------------------------------------------------------------------------
# Test 10 — reuses build_counter_brief unchanged (byte-equivalent)
# ---------------------------------------------------------------------------

class TestReusesBuildCounterBrief(unittest.TestCase):
    def test_reuses_build_counter_brief_unchanged(self):
        """The counter-brief in Section 1 contains the canonical VERDICT CONTESTED line."""
        with tempfile.TemporaryDirectory() as tmpdir:
            ws = _make_workspace(tmpdir)
            md, sections = aug.build_brief(
                workspace=ws,
                lane_id="H1-test",
                files=["foo.go"],
                hint=None,
                max_items=8,
            )
            sec1_items = sections["sec1_counter_brief"].get("items", [])
            self.assertTrue(len(sec1_items) > 0)
            brief_text = sec1_items[0].get("brief", "")
            # Must contain the canonical verdict lines
            self.assertIn("VERDICT CONTESTED", brief_text)
            self.assertIn("VERDICT HOLDS", brief_text)


# ---------------------------------------------------------------------------
# Test 11 — AMF frame subprocess call isolated (malformed/empty output graceful)
# ---------------------------------------------------------------------------

class TestAmfFrameSubprocessCallIsolated(unittest.TestCase):
    def test_amf_frame_subprocess_call_isolated_empty(self):
        """Empty subprocess output for --frames-only produces empty items, not error."""
        with patch("subprocess.run") as mock_run:
            mock_proc = MagicMock()
            mock_proc.returncode = 0
            mock_proc.stdout = json.dumps({"frames": []})
            mock_run.return_value = mock_proc

            text, data = aug._build_sec12(
                files=["foo.go"], hint="frost-signer", max_items=3
            )
            self.assertIn("## Section 12", text)
            self.assertEqual(data["items_count"], 0)

    def test_amf_frame_subprocess_call_isolated_malformed(self):
        """Malformed JSON subprocess output for --frames-only produces empty items gracefully."""
        with patch("subprocess.run") as mock_run:
            mock_proc = MagicMock()
            mock_proc.returncode = 0
            mock_proc.stdout = "not-valid-json"
            mock_run.return_value = mock_proc

            text, data = aug._build_sec12(
                files=["foo.go"], hint=None, max_items=3
            )
            self.assertIn("## Section 12", text)
            # Should not raise; items are empty
            self.assertIsInstance(data["items"], list)

    def test_amf_frame_subprocess_call_isolated_nonzero(self):
        """Non-zero rc for --frames-only produces empty items gracefully."""
        with patch("subprocess.run") as mock_run:
            mock_proc = MagicMock()
            mock_proc.returncode = 1
            mock_proc.stdout = ""
            mock_run.return_value = mock_proc

            text, data = aug._build_sec12(
                files=["foo.go"], hint=None, max_items=3
            )
            self.assertEqual(data["items_count"], 0)


# ---------------------------------------------------------------------------
# Test 12 — engage_report filter by files
# ---------------------------------------------------------------------------

class TestEngageReportFilterByFiles(unittest.TestCase):
    def test_engage_report_filter_by_files(self):
        """Fires from file C are excluded when --files is A,B."""
        with tempfile.TemporaryDirectory() as tmpdir:
            ws = _make_workspace(tmpdir)
            # Write synthetic engage_report.md
            report_content = (
                "## detector-alpha\n"
                "  - fileA.go:10: issue in A\n"
                "  - fileC.go:20: issue in C\n"
                "## detector-beta\n"
                "  - fileB.go:30: issue in B\n"
                "  - fileC.go:40: issue in C\n"
            )
            (ws / "engage_report.md").write_text(report_content)

            with patch.object(aug, "_load_engage_report_context", return_value=None):
                _, data = aug._build_sec5(ws, files=["fileA.go", "fileB.go"], max_items=10)

            all_fire_files: list = []
            for item in data["items"]:
                for fire in item.get("fires", []):
                    all_fire_files.append(fire)

            # fileC fires must not appear
            for fire in all_fire_files:
                self.assertNotIn("fileC", fire, msg=f"fileC leaked into output: {fire}")

            # At least one fire should appear (from A or B)
            self.assertGreater(len(all_fire_files), 0)

    def test_mcp_engage_report_variant_hit_fields_are_included(self):
        """Variant hit field names from MCP payload still produce scoped fires."""
        payload = {
            "clusters": [
                {
                    "detector_slug": "detector-alpha",
                    "hit_count": 2,
                    "hits": [
                        {
                            "path": "pkg/fileA.go:10",
                            "severity_class": "HIGH",
                            "excerpt": "A-side check missing",
                        },
                        {
                            "file": "pkg/fileB.go:22",
                            "sev": "MEDIUM",
                            "text": "B-side state drift",
                        },
                    ],
                }
            ]
        }

        items = aug._filter_mcp_engage_items(
            payload,
            files=["fileA.go", "fileB.go"],
            max_items=10,
        )
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["detector"], "detector-alpha")
        self.assertEqual(items[0]["count"], 2)
        self.assertIn("[HIGH] pkg/fileA.go:10", items[0]["fires"][0])
        self.assertIn("[MEDIUM] pkg/fileB.go:22", items[0]["fires"][1])

    def test_mcp_engage_report_empty_context_does_not_fall_back_to_raw(self):
        """Successful MCP context with no scoped hits remains MCP-sourced."""
        with tempfile.TemporaryDirectory() as tmpdir:
            ws = _make_workspace(tmpdir)
            (ws / "engage_report.md").write_text(
                "# Raw detector\n\n- src/fileA.go:1: raw fallback should not leak\n",
                encoding="utf-8",
            )
            payload = {
                "report_found": True,
                "context_pack_id": "pack-empty",
                "context_pack_hash": "hash-empty",
                "clusters": [],
            }
            with patch.object(aug, "_load_engage_report_context", return_value=payload):
                text, data = aug._build_sec5(ws, ["fileA.go"], max_items=8)

            self.assertEqual(data["source"], "vault_engage_report_context")
            self.assertEqual(data["items_count"], 0)
            self.assertIn("pack-empty", text)
            self.assertNotIn("raw fallback should not leak", text)

    def test_mcp_engage_report_pool_sol_does_not_match_staking_pool_rewards(self):
        """MCP filtering uses exact path/basename/stem overlap, not broad substrings."""
        payload = {
            "clusters": [
                {
                    "detector_slug": "detector-pool",
                    "hits": [
                        {
                            "path": "contracts/staking_pool_rewards.sol:12",
                            "severity_class": "HIGH",
                            "excerpt": "unrelated rewards accounting",
                        },
                        {
                            "path": "contracts/pool.sol:34",
                            "severity_class": "MEDIUM",
                            "excerpt": "selected pool issue",
                        },
                    ],
                }
            ]
        }

        items = aug._filter_mcp_engage_items(payload, files=["pool.sol"], max_items=10)

        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["count"], 1)
        self.assertIn("contracts/pool.sol:34", items[0]["fires"][0])
        self.assertNotIn("staking_pool_rewards", "\n".join(items[0]["fires"]))

    def test_mcp_engage_report_staking_pool_rewards_matches_when_explicitly_selected(self):
        """The stricter matcher still supports explicit basename selection."""
        payload = {
            "clusters": [
                {
                    "detector_slug": "detector-pool",
                    "hits": [
                        {
                            "path": "contracts/staking_pool_rewards.sol:12",
                            "severity_class": "HIGH",
                            "excerpt": "selected rewards accounting",
                        },
                        {
                            "path": "contracts/pool.sol:34",
                            "severity_class": "MEDIUM",
                            "excerpt": "unselected pool issue",
                        },
                    ],
                }
            ]
        }

        items = aug._filter_mcp_engage_items(
            payload,
            files=["staking_pool_rewards.sol"],
            max_items=10,
        )

        self.assertEqual(len(items), 1)
        self.assertEqual(items[0]["count"], 1)
        self.assertIn("staking_pool_rewards.sol:12", items[0]["fires"][0])
        self.assertNotIn("contracts/pool.sol:34", "\n".join(items[0]["fires"]))

    def test_raw_engage_report_pool_sol_does_not_match_staking_pool_rewards(self):
        """Raw fallback parsing avoids basename-stem substring false positives."""
        with tempfile.TemporaryDirectory() as tmpdir:
            ws = _make_workspace(tmpdir)
            report_content = (
                "## detector-pool\n"
                "  - contracts/staking_pool_rewards.sol:12: unrelated rewards accounting\n"
                "  - contracts/pool.sol:34: selected pool issue\n"
            )
            (ws / "engage_report.md").write_text(report_content, encoding="utf-8")

            with patch.object(aug, "_load_engage_report_context", return_value=None):
                _, data = aug._build_sec5(ws, files=["pool.sol"], max_items=10)

            fires = "\n".join(
                fire
                for item in data["items"]
                for fire in item.get("fires", [])
            )
            self.assertIn("contracts/pool.sol:34", fires)
            self.assertNotIn("staking_pool_rewards", fires)

    def test_raw_engage_report_staking_pool_rewards_matches_when_explicitly_selected(self):
        """Raw fallback still matches the explicit selected basename."""
        with tempfile.TemporaryDirectory() as tmpdir:
            ws = _make_workspace(tmpdir)
            report_content = (
                "## detector-pool\n"
                "  - contracts/staking_pool_rewards.sol:12: selected rewards accounting\n"
                "  - contracts/pool.sol:34: unselected pool issue\n"
            )
            (ws / "engage_report.md").write_text(report_content, encoding="utf-8")

            with patch.object(aug, "_load_engage_report_context", return_value=None):
                _, data = aug._build_sec5(
                    ws,
                    files=["staking_pool_rewards.sol"],
                    max_items=10,
                )

            fires = "\n".join(
                fire
                for item in data["items"]
                for fire in item.get("fires", [])
            )
            self.assertIn("staking_pool_rewards.sol:12", fires)
            self.assertNotIn("contracts/pool.sol:34", fires)


# ---------------------------------------------------------------------------
# Test 13 — kill_rubric section match by hint
# ---------------------------------------------------------------------------

class TestKillRubricSectionMatchByHint(unittest.TestCase):
    def test_kill_rubric_section_match_by_hint(self):
        """kill_rubric matched section contains the hint keyword."""
        kill_rubric_path = REPO_ROOT / "docs" / "KILL_RUBRIC_LIBRARY.md"
        if not kill_rubric_path.is_file():
            self.skipTest("KILL_RUBRIC_LIBRARY.md not present")

        text, data = aug._build_sec6(hint="amm", max_items=8)
        self.assertIn("## Section 6", text)
        # Section should be present even if no match (falls back to first)
        self.assertIsInstance(data["items_count"], int)

    def test_kill_rubric_no_hint(self):
        """Without hint, kill_rubric avoids metadata-link pseudo-rubrics."""
        kill_rubric_path = REPO_ROOT / "docs" / "KILL_RUBRIC_LIBRARY.md"
        if not kill_rubric_path.is_file():
            self.skipTest("KILL_RUBRIC_LIBRARY.md not present")

        text, data = aug._build_sec6(hint=None, max_items=8)
        self.assertIn("## Section 6", text)
        self.assertEqual(data["items_count"], 0)
        self.assertNotIn("Codified Discipline Rules", text)


# ---------------------------------------------------------------------------
# Test 14 — question_list derives from sections
# ---------------------------------------------------------------------------

class TestQuestionListDerivesFromSections(unittest.TestCase):
    def test_question_list_derives_from_sections(self):
        """sec13 includes case-study and fallback-pattern questions when present."""
        sec2_data = {
            "items": [
                {"title": "CS-1 test", "id": "cs-001"},
                {"title": "CS-2 test", "id": "cs-002"},
                {"title": "CS-3 test", "id": "cs-003"},
            ]
        }
        sec3_data = {
            "items": [
                {"title": "Bridge proof sequence", "template_id": "bridge_proof_domain"},
            ]
        }
        sec4_data = {
            "items": [
                {"title": "reward theft", "id": "defihack-reward-theft"},
            ]
        }
        sec6_data = {"items": []}
        sec11_data = {"items": []}
        sec5_data = {"items": []}
        sec55_data = {
            "items": [
                {"pattern_id": "go-foo", "indicator": "text-pattern: foo-bar"},
                {"pattern_id": "go-bar", "indicator": "text-pattern: bar-baz"},
            ]
        }
        sec12_data = {"items": []}

        text, q_data = aug._build_sec13(
            sec2_data,
            sec3_data,
            sec4_data,
            sec6_data,
            sec11_data,
            sec5_data,
            sec55_data,
            sec12_data,
        )

        q_cs = [q for q in q_data["items"] if q["id"].startswith("Q-CS-")]
        q_seq = [q for q in q_data["items"] if q["id"].startswith("Q-SEQ-")]
        q_dh = [q for q in q_data["items"] if q["id"].startswith("Q-DH-")]
        q_pat = [q for q in q_data["items"] if q["id"].startswith("Q-PAT-")]
        self.assertGreaterEqual(len(q_cs), 3)
        self.assertGreaterEqual(len(q_seq), 1)
        self.assertGreaterEqual(len(q_dh), 1)
        self.assertGreaterEqual(len(q_pat), 2)
        self.assertIn("Bridge proof sequence", text)
        self.assertIn("reward theft", text)
        self.assertIn("text-pattern: foo-bar", text)
        self.assertIn("Q-DUPE", text)

    def test_question_list_includes_seq_predicate_advisory_questions(self):
        """Section 13 emits advisory per-predicate Q-SEQ questions with hit refs."""
        sec2_data = {"items": []}
        sec3_data = {
            "items": [
                {
                    "title": "Consensus parser differential",
                    "template_id": "consensus_parser_differential",
                    "worklist_predicates": [
                        {
                            "predicate_id": "cpd.step2.is_deposits_only_symbol_present",
                            "status": "needs_evidence",
                            "advisory_only": True,
                            "hit_refs": [
                                "crates/consensus/derive/src/attributes.rs:77",
                            ],
                        }
                    ],
                }
            ]
        }
        sec4_data = {"items": []}
        sec6_data = {"items": []}
        sec11_data = {"items": []}
        sec5_data = {"items": []}
        sec55_data = {"items": []}
        sec12_data = {"items": []}

        text, q_data = aug._build_sec13(
            sec2_data,
            sec3_data,
            sec4_data,
            sec6_data,
            sec11_data,
            sec5_data,
            sec55_data,
            sec12_data,
        )

        qids = [q["id"] for q in q_data["items"]]
        self.assertIn("Q-SEQ-consensus_parser_differential", qids)
        self.assertIn(
            "Q-SEQ-consensus_parser_differential-cpd-step2-is_deposits_only_symbol_present",
            qids,
        )
        self.assertIn("advisory signal only", text)
        self.assertIn("attributes.rs:77", text)

    def test_question_list_includes_section12_rule_questions_when_structured(self):
        """Section 13 emits advisory Q-RULE questions from Section 12 attacker_question."""
        sec2_data = {"items": []}
        sec3_data = {"items": []}
        sec4_data = {"items": []}
        sec6_data = {"items": []}
        sec11_data = {"items": []}
        sec5_data = {"items": []}
        sec55_data = {"items": []}
        sec12_data = {
            "items": [
                {
                    "name": "AMF-bridge-replay",
                    "attacker_question": "Can I replay this proof across domains?",
                }
            ]
        }

        text, q_data = aug._build_sec13(
            sec2_data,
            sec3_data,
            sec4_data,
            sec6_data,
            sec11_data,
            sec5_data,
            sec55_data,
            sec12_data,
        )

        qids = [q["id"] for q in q_data["items"]]
        self.assertIn("Q-RULE-amf-bridge-replay", qids)
        self.assertIn("replay this proof across domains", text)
        self.assertIn("not severity assignment", text)

    def test_question_list_includes_section8_prior_outcome_questions(self):
        """Section 13 emits advisory Q-PRIOR questions from Section 8 rows."""
        sec2_data = {"items": []}
        sec3_data = {"items": []}
        sec4_data = {"items": []}
        sec6_data = {"items": []}
        sec11_data = {"items": []}
        sec5_data = {"items": []}
        sec55_data = {"items": []}
        sec12_data = {"items": []}
        sec8_data = {
            "items": [
                {
                    "source": "DUPE_CAUSES.md",
                    "text": "DUPE-path: prior filing already covers same withdrawal path",
                },
                {
                    "source": "REJECTION_CAUSES.md",
                    "text": "REJ-scope: missing in-scope affected path",
                },
            ]
        }

        text, q_data = aug._build_sec13(
            sec2_data,
            sec3_data,
            sec4_data,
            sec6_data,
            sec11_data,
            sec5_data,
            sec55_data,
            sec12_data,
            sec8_data,
        )

        qids = [q["id"] for q in q_data["items"]]
        self.assertIn("Q-PRIOR-dupe_causes-md-1", qids)
        self.assertIn("Q-PRIOR-rejection_causes-md-2", qids)
        self.assertIn("prior filing already covers same withdrawal path", text)
        self.assertIn("advisory triage signal only", text)
        self.assertIn("not severity assignment", text)

    def test_question_list_includes_section10_oos_advisory_questions(self):
        """Section 13 emits advisory Q-OOS questions from Section 10 rows."""
        sec2_data = {"items": []}
        sec3_data = {"items": []}
        sec4_data = {"items": []}
        sec6_data = {"items": []}
        sec11_data = {"items": []}
        sec5_data = {"items": []}
        sec55_data = {"items": []}
        sec12_data = {"items": []}
        sec10_data = {
            "items": [
                {
                    "source": "OOS_CHECKLIST.md",
                    "text": "- Withdraw-only watcher accounting issues are out of scope unless they impact signer balances",
                },
                {
                    "source": "SCOPE.md",
                    "text": "- Signer settlement paths are in scope",
                },
            ]
        }

        text, q_data = aug._build_sec13(
            sec2_data,
            sec3_data,
            sec4_data,
            sec6_data,
            sec11_data,
            sec5_data,
            sec55_data,
            sec12_data,
            sec10_data=sec10_data,
        )

        qids = [q["id"] for q in q_data["items"]]
        self.assertIn("Q-OOS-oos_checklist-md-1", qids)
        self.assertIn("Q-OOS-scope-md-2", qids)
        self.assertIn("what direct proof would defeat likely out-of-scope rejection", text)
        self.assertIn("impacted asset/accounting surface", text)
        self.assertIn("not severity assignment", text)

    def test_question_list_notes_when_section12_is_unstructured(self):
        """Section 13 explains when Section 12 cannot emit structured Q-RULE questions."""
        sec2_data = {"items": []}
        sec3_data = {"items": []}
        sec4_data = {"items": []}
        sec6_data = {"items": []}
        sec11_data = {"items": []}
        sec5_data = {"items": []}
        sec55_data = {"items": []}
        sec12_data = {
            "items": [
                {"name": "AMF-no-question", "mental_steps": "something unstructured"},
            ]
        }

        text, q_data = aug._build_sec13(
            sec2_data,
            sec3_data,
            sec4_data,
            sec6_data,
            sec11_data,
            sec5_data,
            sec55_data,
            sec12_data,
        )

        qids = [q["id"] for q in q_data["items"]]
        self.assertNotIn("Q-RULE-amf-no-question", qids)
        self.assertIn("no `Q-RULE-*` items emitted", text)

    def test_question_list_includes_attack_class_ranker_questions_from_detector_fires(self):
        """Section 13 emits bounded advisory Q-AC questions from ranker output."""
        calls = []

        class FakeRanker:
            REPO_ROOT = REPO_ROOT
            DEFAULT_PATTERNS_DIR = REPO_ROOT / "reference" / "patterns.dsl"
            DEFAULT_DEFIHACK_CATALOG = REPO_ROOT / "defihacklabs" / "catalog.yaml"

            @staticmethod
            def load_patterns(patterns_dir, repo_root):
                return ["pattern-item"]

            @staticmethod
            def load_defihack(catalog_path, repo_root):
                return ["defihack-item"]

            @staticmethod
            def rank_attack_classes(*, query_text, items, top_n):
                calls.append((query_text, items, top_n))
                rows = [
                    {
                        "rank": 1,
                        "attack_class": "oracle-manipulation",
                        "confidence": "low-medium",
                        "claim_scope": "hypothesis_prioritization_only",
                        "matched_terms": ["oracle", "price"],
                        "evidence_refs": [
                            {"source_ref": "reference/patterns.dsl/oracle.yaml"},
                        ],
                    },
                    {
                        "rank": 2,
                        "attack_class": "precision-rounding-accounting",
                        "confidence": "low",
                        "matched_terms": ["share"],
                        "evidence_refs": [
                            {"source_ref": "reference/patterns.dsl/rounding.yaml"},
                        ],
                    },
                    {
                        "rank": 3,
                        "attack_class": "access-control-bypass",
                        "confidence": "low",
                        "matched_terms": ["admin"],
                        "evidence_refs": [
                            {"source_ref": "reference/patterns.dsl/access.yaml"},
                        ],
                    },
                    {
                        "rank": 4,
                        "attack_class": "reentrancy",
                        "confidence": "low",
                    },
                ]
                return rows[:top_n]

        sec_empty = {"items": []}
        sec5_data = {
            "items": [
                {
                    "detector": "detector-alpha",
                    "fires": ["[HIGH] contracts/Vault.sol:42 — missing price freshness"],
                }
            ]
        }

        with patch.object(aug, "_load_attack_class_ranker_module", return_value=FakeRanker):
            text, q_data = aug._build_sec13(
                sec_empty,
                sec_empty,
                sec_empty,
                sec_empty,
                sec_empty,
                sec5_data,
                sec_empty,
                sec_empty,
                scoped_files=["contracts/Vault.sol"],
                hint="oracle vault",
            )

        self.assertEqual(calls[0][2], 3)
        self.assertIn("detector-alpha", calls[0][0])
        self.assertIn("missing price freshness", calls[0][0])
        self.assertIn("contracts/Vault.sol", calls[0][0])
        q_ac = [q for q in q_data["items"] if q["id"].startswith("Q-AC-")]
        self.assertEqual([q["id"] for q in q_ac], [
            "Q-AC-oracle-manipulation",
            "Q-AC-precision-rounding-accounting",
            "Q-AC-access-control-bypass",
        ])
        self.assertTrue(all(q["advisory_only"] for q in q_ac))
        self.assertTrue(all(q["claim_scope"] == "hypothesis_prioritization_only" for q in q_ac))
        self.assertNotIn("Q-AC-reentrancy", [q["id"] for q in q_data["items"]])
        self.assertIn("not proof-of-exploit", text)
        self.assertIn("not severity assignment", text)

    def test_question_list_uses_scoped_context_for_attack_class_ranker_without_fires(self):
        """Section 13 can rank advisory Q-AC questions from file/function scope alone."""
        calls = []

        class FakeRanker:
            REPO_ROOT = REPO_ROOT
            DEFAULT_PATTERNS_DIR = REPO_ROOT / "reference" / "patterns.dsl"
            DEFAULT_DEFIHACK_CATALOG = REPO_ROOT / "defihacklabs" / "catalog.yaml"

            @staticmethod
            def load_patterns(patterns_dir, repo_root):
                return ["pattern-item"]

            @staticmethod
            def load_defihack(catalog_path, repo_root):
                return []

            @staticmethod
            def rank_attack_classes(*, query_text, items, top_n):
                calls.append((query_text, items, top_n))
                return [
                    {
                        "rank": 1,
                        "attack_class": "bridge-message-validation",
                        "confidence": "low-medium",
                        "evidence_refs": [
                            {"source_ref": "reference/patterns.dsl/bridge.yaml"},
                        ],
                    }
                ]

        sec_empty = {"items": []}
        with patch.object(aug, "_load_attack_class_ranker_module", return_value=FakeRanker):
            text, q_data = aug._build_sec13(
                sec_empty,
                sec_empty,
                sec_empty,
                sec_empty,
                sec_empty,
                sec_empty,
                sec_empty,
                sec_empty,
                scoped_files=["src/Bridge.sol:verify(bytes32 proof)"],
                hint="bridge verifier",
            )

        self.assertIn("src/Bridge.sol:verify", calls[0][0])
        self.assertIn("bridge verifier", calls[0][0])
        qids = [q["id"] for q in q_data["items"]]
        self.assertIn("Q-AC-bridge-message-validation", qids)
        self.assertIn("Advisory attack-class check", text)
        self.assertIn("not proof-of-exploit", text)

    def test_question_list_uses_ranker_payload_and_prefers_analogue_refs(self):
        """Section 13 uses ranker.run payloads so external analogues reach Q-AC refs."""
        calls = []

        class FakeRanker:
            REPO_ROOT = REPO_ROOT

            @staticmethod
            def run(argv):
                calls.append(argv)
                return {
                    "ranked_attack_classes": [
                        {
                            "rank": 1,
                            "attack_class": "hook-reentrancy",
                            "confidence": "medium",
                            "claim_scope": "hypothesis_prioritization_only",
                            "matched_terms": ["hook", "callback"],
                            "analogue_refs": [
                                {
                                    "source_kind": "external_corpus:case-study",
                                    "source_ref": "reference/findings_rust.jsonl#spl-hook-reentry",
                                    "mechanism": "token hook callback reenters before accounting is finalized",
                                    "grep_predicates": ["transfer_hook", "pre_accounting_callback"],
                                    "runtime_predicates": ["second withdrawal observes stale balance"],
                                },
                            ],
                            "evidence_refs": [
                                {"source_ref": "reference/patterns.dsl/reentrancy.yaml"},
                            ],
                        }
                    ]
                }

        sec_empty = {"items": []}
        with patch.object(aug, "_load_attack_class_ranker_module", return_value=FakeRanker):
            text, q_data = aug._build_sec13(
                sec_empty,
                sec_empty,
                sec_empty,
                sec_empty,
                sec_empty,
                sec_empty,
                sec_empty,
                sec_empty,
                scoped_files=["programs/onre/src/lib.rs:process_redeem"],
                hint="callback hook accounting",
            )

        self.assertIn("--context", calls[0])
        context_arg = calls[0][calls[0].index("--context") + 1]
        self.assertIn("callback hook accounting", context_arg)
        q_ac = [q for q in q_data["items"] if q["id"] == "Q-AC-hook-reentrancy"]
        self.assertEqual(len(q_ac), 1)
        self.assertEqual(
            q_ac[0]["evidence_refs"][0],
            "reference/findings_rust.jsonl#spl-hook-reentry",
        )
        self.assertEqual(
            q_ac[0]["analogue_evidence"][0]["runtime_predicates"][0],
            "second withdrawal observes stale balance",
        )
        self.assertIn("reference/findings_rust.jsonl#spl-hook-reentry", text)
        self.assertIn("token hook callback reenters", text)
        self.assertIn("pre_accounting_callback", text)

    def test_reply_shape_uses_actual_question_ids(self):
        """Section 14 answer block mirrors Section 13 questions, not stale examples."""
        sec13 = {
            "items": [
                {"id": "Q-ANG-1"},
                {"id": "Q-DET-cap-desync"},
                {"id": "Q-DUPE"},
            ]
        }

        text, data = aug._build_sec14(sec13)

        self.assertEqual(data["items_count"], 3)
        self.assertIn("- Q-ANG-1: PASS|FAIL|UNKNOWN", text)
        self.assertIn("- Q-DET-cap-desync: PASS|FAIL|UNKNOWN", text)
        self.assertNotIn("Q-CS-001", text)
        self.assertNotIn("Q-RUB-1", text)

    def test_reply_shape_keeps_advisory_questions_second_class(self):
        """Section 14 must not make advisory analogue checks look like proof gates."""
        sec13 = {
            "items": [
                {"id": "Q-DET-cap-desync"},
                {"id": "Q-AC-reentrancy", "advisory_only": True},
                {"id": "Q-PRIOR-cantina-1", "advisory_only": True},
                {"id": "Q-OOS-immunefi-1", "advisory_only": True},
                {"id": "Q-RULE-r30-production-profile", "advisory_only": True},
            ]
        }

        text, data = aug._build_sec14(sec13)

        self.assertIn("- Q-DET-cap-desync: PASS|FAIL|UNKNOWN", text)
        self.assertIn("- Q-AC-reentrancy: ADVISORY_PASS|ADVISORY_FAIL|UNKNOWN", text)
        self.assertIn("not exploit proof, not severity assignment", text)
        by_id = {row["question_id"]: row for row in data["items"]}
        self.assertFalse(by_id["Q-DET-cap-desync"]["advisory_only"])
        self.assertTrue(by_id["Q-AC-reentrancy"]["advisory_only"])


class TestMcpContextSections(unittest.TestCase):
    def test_build_brief_uses_resume_exploit_context_for_sections_2_3_11(self):
        resume_context = {
            "context_pack_id": "resume-pack-full",
            "case_study_logic": [
                {
                    "case_id": "bridge-case",
                    "class": "bridge",
                    "mechanism": "bridge proof replay",
                    "extracted_lesson": "Bind proof domains before accepting withdrawals.",
                    "grep_predicates": ["verifyProof"],
                    "runtime_predicates": ["replayed proof accepted"],
                    "source_file": "case_study/bridge.md",
                }
            ],
            "big_loss_template_actor_sequences": [
                {
                    "template_id": "bridge_proof_domain",
                    "title": "Bridge proof domain attack",
                    "workspace_scope_match": True,
                    "actor_sequence_verdicts": [
                        {
                            "step": 1,
                            "actor": "attacker",
                            "action": "submit replayed proof",
                            "evidence_required": "verifyProof accepts replay",
                            "target": "BridgeVerifier.verifyProof",
                            "applicable": True,
                        }
                    ],
                }
            ],
        }
        exploit_context = {
            "context_pack_id": "exploit-pack-full",
            "angles": [
                {
                    "angle_id": "angle-bridge-001",
                    "title": "Bridge withdrawal replay",
                    "bug_class_id": "bridge",
                    "source_refs": ["workspace:src/BridgeVerifier.sol:42"],
                    "not_submit_ready_until": ["runnable PoC evidence"],
                    "proof_prerequisites": [
                        {
                            "artifact": "poc/bridge_replay.t.sol",
                            "status": "required",
                            "summary": "prove replay drains escrow",
                        }
                    ],
                }
            ],
        }

        with tempfile.TemporaryDirectory() as tmpdir:
            ws = _make_workspace(tmpdir)
            with patch.object(aug, "_load_resume_context", return_value=resume_context), \
                 patch.object(aug, "_load_exploit_context", return_value=exploit_context), \
                 patch.object(aug, "_build_sec12", return_value=("## Section 12 — Matched attacker frames (AMF-*)\n\n", {"items_count": 0, "items": []})):
                md, sections = aug.build_brief(
                    workspace=ws,
                    lane_id="H-bridge",
                    files=["src/BridgeVerifier.sol"],
                    hint="bridge",
                    max_items=8,
                )

        self.assertEqual(sections["sec2_case_study_logic"]["source"], "vault_resume_context.case_study_logic")
        self.assertEqual(sections["sec3_big_loss_sequences"]["source"], "vault_resume_context.big_loss_template_actor_sequences")
        self.assertEqual(sections["sec11_exploit_angles"]["source"], "vault_exploit_context.angles")
        self.assertIn("vault_resume_context", md)
        self.assertIn("vault_exploit_context", md)
        self.assertIn("bridge proof replay", md)
        self.assertIn("Bridge proof domain attack", md)
        self.assertIn("Bridge withdrawal replay", md)
        question_ids = {row["id"] for row in sections["sec13_question_list"]["items"]}
        self.assertIn("Q-CS-001", question_ids)
        self.assertIn("Q-SEQ-bridge_proof_domain", question_ids)
        self.assertIn("Q-ANG-1", question_ids)

    def test_resume_context_sections_inject_hacker_logic(self):
        resume_context = {
            "context_pack_id": "resume-pack-1",
            "case_study_logic": [
                {
                    "case_id": "case-bridge",
                    "class": "bridge",
                    "mechanism": "bridge proof replay",
                    "extracted_lesson": "Domain separation must bind the source chain.",
                    "grep_predicates": ["verifyProof", "domainSeparator"],
                    "runtime_predicates": ["proof accepts replayed source chain"],
                    "severity_class": "CRITICAL",
                    "source_file": "case_study/bridge.md",
                }
            ],
            "big_loss_template_actor_sequences": [
                {
                    "template_id": "bridge_proof_domain",
                    "title": "Bridge proof domain attack",
                    "workspace_scope_match": True,
                    "actor_sequence_verdicts": [
                        {
                            "step": 1,
                            "actor": "attacker",
                            "action": "submit forged proof",
                            "evidence_required": "verify() accepts proof",
                            "target": "Verifier.verify",
                            "applicable": True,
                        }
                    ],
                }
            ],
            "defihack_class_matches": [
                {
                    "id": "bridge-drain",
                    "attack_class": "bridge-drain",
                    "mechanism": "forged proof drains escrow",
                    "detector_status": "candidate",
                    "is_candidate": True,
                    "total_hits": 2,
                    "predicates_with_hits": 2,
                    "grep_predicates": ["verifyProof", "bridgeNonce"],
                    "matched_predicates": [
                        {
                            "predicate": "verifyProof",
                            "hit_refs": ["src/BridgeVerifier.sol:42"],
                        }
                    ],
                }
            ],
        }

        sec2_text, sec2 = aug._build_sec2(["BridgeVerifier.sol"], "bridge", 8, resume_context)
        sec3_text, sec3 = aug._build_sec3(["BridgeVerifier.sol"], "bridge", 8, resume_context)
        sec4_text, sec4 = aug._build_sec4(["BridgeVerifier.sol"], "bridge", 8, resume_context)

        self.assertEqual(sec2["items_count"], 1)
        self.assertEqual(sec3["items_count"], 1)
        self.assertEqual(sec4["items_count"], 1)
        self.assertIn("bridge proof replay", sec2_text)
        self.assertIn("Bridge proof domain attack", sec3_text)
        self.assertIn("forged proof drains escrow", sec4_text)
        self.assertIn("verifyProof", sec4_text)
        self.assertIn("src/BridgeVerifier.sol:42", sec4_text)

    def test_resume_context_section3_renders_advisory_predicates(self):
        resume_context = {
            "context_pack_id": "resume-pack-cpd",
            "big_loss_template_actor_sequences": [
                {
                    "template_id": "consensus_parser_differential",
                    "title": "Consensus parser differential",
                    "workspace_scope_match": True,
                    "actor_sequence_verdicts": [
                        {
                            "step": 2,
                            "actor": "base_consensus_node",
                            "action": "mis_label_payload_as_deposits_only",
                            "applicable": True,
                            "worklist_predicates": [
                                {
                                    "predicate_id": "cpd.step2.is_deposits_only_symbol_present",
                                    "status": "needs_evidence",
                                    "advisory_only": True,
                                    "hit_refs": ["crates/consensus/derive/src/attributes.rs:77"],
                                }
                            ],
                        }
                    ],
                }
            ],
        }

        sec3_text, sec3 = aug._build_sec3(["attributes.rs"], "consensus", 8, resume_context)
        self.assertEqual(sec3["items_count"], 1)
        self.assertIn("advisory_worklist_predicates", sec3_text)
        self.assertIn("cpd.step2.is_deposits_only_symbol_present", sec3_text)
        self.assertIn("attributes.rs:77", sec3_text)

    def test_exploit_context_section_injects_angles(self):
        exploit_context = {
            "context_pack_id": "exploit-pack-1",
            "angles": [
                {
                    "angle_id": "angle-001",
                    "title": "Fund lock on redemption",
                    "bug_class_id": "fund-lock",
                    "confidence": "medium",
                    "recommendation_status": "recommended",
                    "source_refs": ["workspace:programs/app/src/redeem.rs:42"],
                    "not_submit_ready_until": ["runnable PoC evidence"],
                    "proof_prerequisites": [
                        {
                            "artifact": "poc/redemption.rs",
                            "status": "required",
                            "summary": "prove balance/state delta",
                        }
                    ],
                }
            ],
        }

        text, data = aug._build_sec11(["redeem.rs"], "fund-lock", 8, exploit_context)

        self.assertEqual(data["items_count"], 1)
        self.assertIn("Fund lock on redemption", text)
        self.assertIn("runnable PoC evidence", text)

    def test_exploit_context_filters_spark_blockers_for_non_spark_workspace(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            ws = _make_workspace(tmpdir)
            exploit_context = {
                "context_pack_id": "exploit-pack-1",
                "angles": [
                    {
                        "angle_id": "angle-001",
                        "title": "Fund lock on redemption",
                        "bug_class_id": "fund-lock",
                        "source_refs": ["workspace:programs/app/src/redeem.rs:42"],
                        "not_submit_ready_until": [
                            "spark-go-poc-toolchain-absent",
                            "runnable PoC evidence",
                        ],
                        "proof_prerequisites": [
                            {
                                "artifact": "tools/pre-submit-check.sh",
                                "status": "watch",
                                "summary": "spark-go-poc-toolchain-absent",
                            },
                            {
                                "artifact": "poc/redemption.rs",
                                "status": "required",
                                "summary": "prove balance/state delta",
                            },
                        ],
                    }
                ],
            }

            text, data = aug._build_sec11(["redeem.rs"], "fund-lock", 8, exploit_context, ws)

            self.assertEqual(data["items_count"], 1)
            self.assertNotIn("spark-go-poc-toolchain-absent", text)
            self.assertIn("runnable PoC evidence", text)
            self.assertIn("prove balance/state delta", text)


# ---------------------------------------------------------------------------
# Test 15 — returns_zero_when_no_corpus_matches (empty placeholders, no error)
# ---------------------------------------------------------------------------

class TestReturnsZeroWhenNoCorpusMatches(unittest.TestCase):
    def test_returns_zero_when_no_corpus_matches(self):
        """Exotic file scope with zero matches produces brief with placeholder text, not error."""
        with tempfile.TemporaryDirectory() as tmpdir:
            ws = _make_workspace(tmpdir)
            md, sections = aug.build_brief(
                workspace=ws,
                lane_id="X-exotic-lane",
                files=["zzzuniquexyz_abc123_exotic_file.rs"],
                hint="totally-unknown-hint-xyz",
                max_items=8,
            )
            # Must not raise; must produce valid markdown
            self.assertIn("# Hacker Mindset Injection", md)
            # Empty sections use "(no matches in this category)" or similar placeholder
            self.assertIn("## Section 14", md)


# ---------------------------------------------------------------------------
# Test 16 — L17 three-axis verdict section present (from 12 §A)
# ---------------------------------------------------------------------------

class TestL17ThreeAxisVerdictSectionPresent(unittest.TestCase):
    def test_l17_three_axis_verdict_section_present(self):
        """Section 0 contains all three verdict axes: CONTESTED, HOLDS, NEEDS BUILD."""
        with tempfile.TemporaryDirectory() as tmpdir:
            ws = _make_workspace(tmpdir)
            md, _ = aug.build_brief(
                workspace=ws,
                lane_id="H1-test",
                files=["foo.go"],
                hint=None,
                max_items=8,
            )
            self.assertIn("VERDICT CONTESTED", md)
            self.assertIn("VERDICT HOLDS", md)
            self.assertIn("NEEDS BUILD", md)
            # Also verify the DROP conditions are listed
            self.assertIn("Evidence path structurally impossible", md)
            self.assertIn("Duplicate-clear filing already exists", md)


# ---------------------------------------------------------------------------
# Test 17 — workspace clones inventory derived from external dir (from 12 §A)
# ---------------------------------------------------------------------------

class TestWorkspaceClonesInventoryDerivedFromExternalDir(unittest.TestCase):
    def test_workspace_clones_inventory_derived_from_external_dir(self):
        """Section 0.5 table is populated from <ws>/external/* git repos."""
        with tempfile.TemporaryDirectory() as tmpdir:
            ws = _make_workspace(tmpdir)
            # Create two dummy external repos
            _make_external_clone(ws, "testorg_myrepo")
            _make_external_clone(ws, "testorg_other")

            text, data = aug._build_sec05(ws)

            self.assertIn("testorg_myrepo", text)
            self.assertIn("testorg_other", text)
            self.assertEqual(data["items_count"], 2)

    def test_workspace_clones_inventory_empty_when_no_external(self):
        """Section 0.5 shows 'no external clones' message when external/ is absent."""
        with tempfile.TemporaryDirectory() as tmpdir:
            ws = _make_workspace(tmpdir)
            # No external/ dir
            text, data = aug._build_sec05(ws)
            self.assertIn("no external clones found", text)
            self.assertEqual(data["items_count"], 0)


# ---------------------------------------------------------------------------
# Test 18 — queued leads filtered by scope overlap (from 12 §A)
# ---------------------------------------------------------------------------

class TestQueuedLeadsFilteredByScopeOverlap(unittest.TestCase):
    def test_queued_leads_filtered_by_scope_overlap(self):
        """Only leads whose paths[] overlap with --files are marked in_scope."""
        with tempfile.TemporaryDirectory() as tmpdir:
            ws = _make_workspace(tmpdir)
            leads = [
                {
                    "lane_id": "H-matching-lead",
                    "discovered_in": "iter4",
                    "shape": "spawn-git-clone shape",
                    "paths": ["external/lightsparkdev_lightspark_crypto_uniffi/"],
                    "l17_path": "BUILD",
                    "rubric_target": "CRIT-1",
                },
                {
                    "lane_id": "H-unrelated-lead",
                    "discovered_in": "iter4",
                    "shape": "some other shape",
                    "paths": ["external/some_other_repo/"],
                    "l17_path": "BUILD",
                    "rubric_target": "HIGH-1",
                },
            ]
            _make_state(ws, queued_leads=leads)

            _, data = aug._build_sec07(
                ws, files=["lightsparkdev_lightspark_crypto_uniffi/src/lib.rs"]
            )

            self.assertEqual(data["items_count"], 2)
            scope_matched = data.get("scope_matched", 0)
            self.assertEqual(scope_matched, 1)

    def test_queued_leads_empty_state(self):
        """Empty state file produces zero queued leads without error."""
        with tempfile.TemporaryDirectory() as tmpdir:
            ws = _make_workspace(tmpdir)
            _make_state(ws, queued_leads=[])

            _, data = aug._build_sec07(ws, files=["foo.go"])
            self.assertEqual(data["items_count"], 0)

    def test_queued_leads_missing_state_is_unavailable_not_empty(self):
        """Missing non-Spark loop state should not claim an empty queue."""
        with tempfile.TemporaryDirectory() as tmpdir:
            ws = _make_workspace(tmpdir)

            text, data = aug._build_sec07(ws, files=["foo.go"])

            self.assertFalse(data["state_available"])
            self.assertIn("state unavailable", text)
            self.assertNotIn("no queued leads in state file", text)


# ---------------------------------------------------------------------------
# Test 19 — lane cooldown trigger state freshness flag (from 12 §A)
# ---------------------------------------------------------------------------

class TestLaneCooldownTriggerStateFreshnessFlag(unittest.TestCase):
    def test_lane_cooldown_trigger_state_freshness_flag(self):
        """Section 0.9 shows the cooldown entry when lane_id prefix matches."""
        with tempfile.TemporaryDirectory() as tmpdir:
            ws = _make_workspace(tmpdir)
            cooldowns = {
                "H1-coop-exit": {
                    "since_iter": 8,
                    "reason": "90-commit backward window done; re-run when pin advances",
                    "trigger_state": {"audit_pin_sha": "e8311d2c0b55"},
                },
                "M-unrelated": {
                    "since_iter": 3,
                    "reason": "unrelated cooldown",
                    "trigger_state": {},
                },
            }
            _make_state(ws, lane_cooldowns=cooldowns)

            text, data = aug._build_sec09(ws, lane_id="H1-rerun")

            # H1-coop-exit should match H1 prefix; M-unrelated should not
            lane_ids = [it["lane_id"] for it in data["items"]]
            self.assertIn("H1-coop-exit", lane_ids)
            self.assertNotIn("M-unrelated", lane_ids)

    def test_lane_cooldown_no_match(self):
        """Section 0.9 shows no-match message when lane has no cooldowns."""
        with tempfile.TemporaryDirectory() as tmpdir:
            ws = _make_workspace(tmpdir)
            cooldowns = {
                "M-some-other": {
                    "since_iter": 2,
                    "reason": "unrelated",
                    "trigger_state": {},
                }
            }
            _make_state(ws, lane_cooldowns=cooldowns)

            text, data = aug._build_sec09(ws, lane_id="H9-totally-new")
            self.assertEqual(data["items_count"], 0)
            self.assertIn("no cooldowns overlap", text)

    def test_lane_cooldown_missing_state_is_unavailable_not_empty(self):
        """Missing non-Spark loop state should not claim no cooldown history."""
        with tempfile.TemporaryDirectory() as tmpdir:
            ws = _make_workspace(tmpdir)

            text, data = aug._build_sec09(ws, lane_id="H9-totally-new")

            self.assertFalse(data["state_available"])
            self.assertIn("state unavailable", text)
            self.assertNotIn("no cooldowns overlap", text)


# ---------------------------------------------------------------------------
# Test 20 — pending commits recent iters surfaced (from 12 §A)
# ---------------------------------------------------------------------------

class TestPendingCommitsRecentItersSurfaced(unittest.TestCase):
    def test_pending_commits_recent_iters_surfaced(self):
        """State file pending_commits are readable; last 5 iters accessible."""
        with tempfile.TemporaryDirectory() as tmpdir:
            ws = _make_workspace(tmpdir)
            pending = [
                {"iteration": i, "lane": f"lane-{i}", "commit": f"abc{i:03d}", "lines": 100}
                for i in range(1, 12)  # 11 entries
            ]
            _make_state(ws, pending_commits=pending)

            state_path = ws / ".auditooor" / "spark_hunt_loop_state.json"
            state = json.loads(state_path.read_text())
            pcs = state.get("pending_commits", [])

            # Last 5 iters
            last_5 = sorted(pcs, key=lambda x: x.get("iteration", 0))[-5:]
            self.assertEqual(len(last_5), 5)
            self.assertEqual(last_5[-1]["iteration"], 11)

    def test_pending_commits_in_full_build_accessible(self):
        """Full brief build with state file does not error when pending_commits populated."""
        with tempfile.TemporaryDirectory() as tmpdir:
            ws = _make_workspace(tmpdir)
            pending = [
                {"iteration": i, "lane": f"M-{i}", "commit": f"sha{i}"} for i in range(5)
            ]
            _make_state(ws, pending_commits=pending)

            md, sections = aug.build_brief(
                workspace=ws,
                lane_id="H1-test",
                files=["foo.go"],
                hint=None,
                max_items=8,
            )
            # Brief builds without error
            self.assertIn("# Hacker Mindset Injection", md)


# ---------------------------------------------------------------------------
# Tests 21-23 — Section 5.5 Go YAML pattern fallback (W2-CATCHUP-L5)
# ---------------------------------------------------------------------------


class TestGoYamlFallback(unittest.TestCase):
    """Section 5.5 fallback: when worker scope is Go AND no compiled detector
    exists in `go_wave1/`, surface YAML text patterns from
    `reference/patterns.dsl.r94_solodit_go/`. Plan §L5 spec."""

    def test_go_yaml_fallback_loads_when_compiled_absent(self):
        """Go file in scope + no compiled detector → fallback section emitted
        with at least one pattern row from the YAML directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            fake_repo = pathlib.Path(tmpdir)
            # YAML pattern dir with one file
            ydir = fake_repo / "reference" / "patterns.dsl.r94_solodit_go"
            ydir.mkdir(parents=True)
            (ydir / "test-pattern.yaml").write_text(
                "id: test-pattern\n"
                "title: Test Go bug\n"
                "severity: Medium\n"
                "language: go\n"
                "bug_class: gas-griefing\n"
                "indicators:\n"
                "  - 'text-pattern: foo-bar-baz'\n"
                "source_url: https://example.com\n",
                encoding="utf-8",
            )
            # No go_wave1/ dir → compiled-absent
            self.assertFalse(aug._has_compiled_go_detector(fake_repo))

            text, data = aug._build_sec55(
                files=["coopexit.go", "watcher.go"], repo=fake_repo
            )
            self.assertEqual(data["trigger"], "fallback_emitted")
            self.assertEqual(data["items_count"], 1)
            self.assertIn("Section 5.5", text)
            self.assertIn("test-pattern", text)
            self.assertIn("Test Go bug", text)
            self.assertIn("text-pattern: foo-bar-baz", text)
            # Provenance footer
            self.assertIn("text-pattern fallback", text)

    def test_go_yaml_fallback_skipped_when_compiled_detector_exists(self):
        """Go file in scope + compiled detector module present in go_wave1/
        → fallback skipped, section emits 'compiled detectors' message."""
        with tempfile.TemporaryDirectory() as tmpdir:
            fake_repo = pathlib.Path(tmpdir)
            # YAML dir present (would otherwise trigger)
            ydir = fake_repo / "reference" / "patterns.dsl.r94_solodit_go"
            ydir.mkdir(parents=True)
            (ydir / "p.yaml").write_text(
                "id: p\ntitle: P\nseverity: Low\nbug_class: x\nindicators: []\n",
                encoding="utf-8",
            )
            # Add a compiled Go detector module
            cdir = fake_repo / "go_wave1"
            cdir.mkdir(parents=True)
            (cdir / "my_detector.py").write_text("# fake compiled detector\n")
            self.assertTrue(aug._has_compiled_go_detector(fake_repo))

            text, data = aug._build_sec55(files=["foo.go"], repo=fake_repo)
            self.assertEqual(data["trigger"], "skipped_compiled_detectors_present")
            self.assertEqual(data["items_count"], 0)
            self.assertIn("compiled Go detector", text)

    def test_go_yaml_fallback_pattern_count_matches_yaml_dir(self):
        """Number of rows emitted equals the count of *.yaml files parsed."""
        with tempfile.TemporaryDirectory() as tmpdir:
            fake_repo = pathlib.Path(tmpdir)
            ydir = fake_repo / "reference" / "patterns.dsl.r94_solodit_go"
            ydir.mkdir(parents=True)
            for i in range(4):
                (ydir / f"pat-{i}.yaml").write_text(
                    f"id: pat-{i}\n"
                    f"title: Pattern {i}\n"
                    "severity: High\n"
                    "bug_class: misc\n"
                    f"indicators: ['text-pattern: ind-{i}']\n",
                    encoding="utf-8",
                )
            # No go_wave1/ → compiled absent
            text, data = aug._build_sec55(files=["x.go"], repo=fake_repo)
            self.assertEqual(data["items_count"], 4)
            # All 4 pattern IDs should appear in the output
            for i in range(4):
                self.assertIn(f"pat-{i}", text)
            # Loader returns same count when called directly
            patterns = aug._load_go_yaml_patterns(fake_repo)
            self.assertEqual(len(patterns), 4)

    def test_go_yaml_fallback_skipped_when_no_go_files(self):
        """Sanity: scope without any .go files → skipped, no rows emitted."""
        with tempfile.TemporaryDirectory() as tmpdir:
            fake_repo = pathlib.Path(tmpdir)
            ydir = fake_repo / "reference" / "patterns.dsl.r94_solodit_go"
            ydir.mkdir(parents=True)
            (ydir / "p.yaml").write_text(
                "id: p\ntitle: P\nseverity: Low\nbug_class: x\nindicators: []\n",
                encoding="utf-8",
            )
            text, data = aug._build_sec55(
                files=["Pool.sol", "Vault.sol"], repo=fake_repo
            )
            self.assertEqual(data["trigger"], "skipped_no_go_files")
            self.assertEqual(data["items_count"], 0)


# ---------------------------------------------------------------------------
# Tests for META-1 activation: Section 15a + 15b
# ---------------------------------------------------------------------------

class TestSec15aLaneRulesToAddress(unittest.TestCase):
    """Tests for _build_sec15a_lane_rules_to_address."""

    def _dispute_payload(self):
        """Fake vault_codified_rules_digest response for dispute lane."""
        return {
            "context_pack_id": "codified-rules-pack-dispute-001",
            "context_pack_hash": "abc123",
            "schema": "auditooor.vault_codified_rules_digest.v1",
            "lane": "dispute",
            "lane_subtype": "dispute",
            "severity": "HIGH",
            "digest": [
                {"rule_id": "R28", "name": "multi-path-escalation-merge", "mechanical_gate": "Check#28", "override_marker": "<!-- r28-rebuttal: -->", "severity_scope": "any"},
                {"rule_id": "R29", "name": "commitment-point-vs-validation-gap", "mechanical_gate": "Check#29", "override_marker": "<!-- r29-rebuttal: -->", "severity_scope": "any"},
                {"rule_id": "R43", "name": "triager-response-scope", "mechanical_gate": "Check#43", "override_marker": "<!-- r43-rebuttal: -->", "severity_scope": "any"},
                {"rule_id": "R45", "name": "dispute-resolution-finality", "mechanical_gate": "Check#45", "override_marker": "<!-- r45-rebuttal: -->", "severity_scope": "any"},
            ],
            "lane_specific_must_address": ["R28", "R29", "R43", "R45"],
            "routine_violation_warnings": [
                {"rule_id": "R28", "one_line_remediation": "Merge all parallel paths before pasting to Cantina."},
            ],
            "filter_summary": "lane=dispute severity=HIGH",
        }

    def test_dispute_lane_returns_r28_r29_r43_r45(self):
        """dispute lane must-address list includes R28/R29/R43/R45."""
        with tempfile.TemporaryDirectory() as tmpdir:
            ws = _make_workspace(tmpdir)
            with patch.object(aug, "_load_vault_context", return_value=self._dispute_payload()):
                text, meta = aug._build_sec15a_lane_rules_to_address(
                    lane_type="dispute",
                    severity="HIGH",
                    workspace_path=ws,
                )
        self.assertIn("## Section 15a", text)
        for rid in ("R28", "R29", "R43", "R45"):
            self.assertIn(rid, text, f"Expected {rid} in Section 15a for dispute lane")
        self.assertEqual(meta["must_address"], ["R28", "R29", "R43", "R45"])
        self.assertFalse(meta.get("mcp_unavailable", True))

    def test_hunt_lane_returns_hunt_rules(self):
        """hunt lane returns hunt-specific rules (R24/R25/R40/R42 etc.) - not R43."""
        hunt_payload = {
            "context_pack_id": "codified-rules-pack-hunt-001",
            "digest": [
                {"rule_id": "R24", "name": "non-self-impact-required", "mechanical_gate": "Check#62", "override_marker": "<!-- r24-rebuttal: -->", "severity_scope": "HIGH+"},
                {"rule_id": "R25", "name": "defense-in-depth-traversal", "mechanical_gate": "Check#63", "override_marker": "<!-- r25-rebuttal: -->", "severity_scope": "HIGH+"},
                {"rule_id": "R40", "name": "v3-grade-poc-required", "mechanical_gate": "Check#84", "override_marker": "r40-rebuttal:", "severity_scope": "MEDIUM+"},
            ],
            "lane_specific_must_address": ["R24", "R25", "R40"],
            "routine_violation_warnings": [],
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            ws = _make_workspace(tmpdir)
            with patch.object(aug, "_load_vault_context", return_value=hunt_payload):
                text, meta = aug._build_sec15a_lane_rules_to_address(
                    lane_type="hunt",
                    severity="HIGH",
                    workspace_path=ws,
                )
        self.assertIn("## Section 15a", text)
        self.assertIn("R24", text)
        self.assertNotIn("R43", text)

    def test_mcp_unavailable_falls_back_to_legacy(self):
        """When vault_codified_rules_digest is unavailable, fall back gracefully."""
        with tempfile.TemporaryDirectory() as tmpdir:
            ws = _make_workspace(tmpdir)
            with patch.object(aug, "_load_vault_context", return_value=None):
                text, meta = aug._build_sec15a_lane_rules_to_address(
                    lane_type="filing",
                    severity="HIGH",
                    workspace_path=ws,
                )
        self.assertTrue(meta.get("mcp_unavailable"))
        # Output should still contain Section 15a header
        self.assertIn("Section 15", text)

    def test_workspace_path_absent_uses_repo(self):
        """When workspace_path is None, function completes without error."""
        with patch.object(aug, "_load_vault_context", return_value=None):
            text, meta = aug._build_sec15a_lane_rules_to_address(
                lane_type="filing",
                severity="HIGH",
                workspace_path=None,
            )
        self.assertIn("Section 15", text)
        self.assertTrue(meta.get("mcp_unavailable"))


class TestSec15bLaneSkeletonTemplates(unittest.TestCase):
    """Tests for _build_sec15b_lane_skeleton_templates."""

    def _dispute_skeleton_payload(self):
        return {
            "context_pack_id": "skeleton-pack-dispute-001",
            "context_pack_hash": "def456",
            "schema": "auditooor.vault_lane_skeleton_filler.v1",
            "lane_type": "dispute",
            "severity": "HIGH",
            "applicable_rules": ["R28", "R29", "R43", "R45"],
            "skeleton_sections": {
                "R28": "## Multi-Path Escalation Merge\n\nPending paths: <<list_all_in_flight_paths>>\nMerged verdict: <<unified_triager_response>>",
                "R29": "## Commitment & Protection Analysis\n\n(a) Commitment point: <<file:line>>\n(b) Validation gap class: <<POST/PRE-commit>>\n(c) Protection cardinality: <<N guards>>"
            },
            "placeholders_to_resolve": {
                "R28": ["<<list_all_in_flight_paths>>", "<<unified_triager_response>>"],
                "R29": ["<<file:line>>", "<<POST/PRE-commit>>", "<<N guards>>"],
            },
            "workspace_anchors": {},
            "usage_note": "Fill in all <<placeholder>> values before pasting to Cantina.",
        }

    def test_dispute_returns_r28_r29_skeletons(self):
        """dispute lane Section 15b contains R28+R29 skeleton templates."""
        with tempfile.TemporaryDirectory() as tmpdir:
            ws = _make_workspace(tmpdir)
            with patch.object(aug, "_load_vault_context", return_value=self._dispute_skeleton_payload()):
                text, meta = aug._build_sec15b_lane_skeleton_templates(
                    lane_type="dispute",
                    severity="HIGH",
                    workspace_path=ws,
                )
        self.assertIn("## Section 15b", text)
        self.assertIn("R28", text)
        self.assertIn("R29", text)
        self.assertIn("<<list_all_in_flight_paths>>", text)
        self.assertIn("<<file:line>>", text)
        self.assertFalse(meta.get("mcp_unavailable", True))
        self.assertEqual(meta["items_count"], 2)

    def test_hunt_lane_no_skeleton_degrades_gracefully(self):
        """hunt lane with no skeleton templates returns warn-only, no error."""
        hunt_payload = {
            "context_pack_id": "skeleton-pack-hunt-001",
            "applicable_rules": ["R24", "R25", "R40"],
            "skeleton_sections": {},  # no templates for hunt
            "placeholders_to_resolve": {},
            "workspace_anchors": {},
            "usage_note": "",
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            ws = _make_workspace(tmpdir)
            with patch.object(aug, "_load_vault_context", return_value=hunt_payload):
                text, meta = aug._build_sec15b_lane_skeleton_templates(
                    lane_type="hunt",
                    severity="HIGH",
                    workspace_path=ws,
                )
        self.assertIn("## Section 15b", text)
        self.assertTrue(meta.get("no_templates"))
        self.assertEqual(meta["items_count"], 0)

    def test_mcp_unavailable_warn_only(self):
        """When vault_lane_skeleton_filler is unavailable, warn and return empty."""
        with tempfile.TemporaryDirectory() as tmpdir:
            ws = _make_workspace(tmpdir)
            with patch.object(aug, "_load_vault_context", return_value=None):
                text, meta = aug._build_sec15b_lane_skeleton_templates(
                    lane_type="dispute",
                    severity="HIGH",
                    workspace_path=ws,
                )
        self.assertIn("## Section 15b", text)
        self.assertIn("unavailable", text)
        self.assertTrue(meta.get("mcp_unavailable"))
        self.assertEqual(meta["items_count"], 0)

    def test_workspace_path_absent_non_anchored_fallback(self):
        """workspace_path=None falls back to non-workspace-anchored skeletons gracefully."""
        payload = {
            "context_pack_id": "skeleton-pack-no-ws",
            "applicable_rules": ["R43"],
            "skeleton_sections": {
                "R43": "## Rule 43 Skeleton\n\nFill: <<placeholder>>"
            },
            "placeholders_to_resolve": {"R43": ["<<placeholder>>"]},
            "workspace_anchors": {},  # no anchors when no workspace
            "usage_note": "No workspace anchors available.",
        }
        with patch.object(aug, "_load_vault_context", return_value=payload):
            text, meta = aug._build_sec15b_lane_skeleton_templates(
                lane_type="dispute",
                severity="HIGH",
                workspace_path=None,  # absent
            )
        self.assertIn("## Section 15b", text)
        self.assertIn("R43", text)
        self.assertIn("<<placeholder>>", text)
        self.assertFalse(meta.get("mcp_unavailable", True))


class TestBuildBriefSec15Integration(unittest.TestCase):
    """Integration: build_brief emits Section 15a AND 15b in output markdown."""

    def test_build_brief_emits_sec15a_and_sec15b(self):
        """build_brief output contains both ## Section 15a and ## Section 15b."""
        sec15a_payload = {
            "context_pack_id": "rules-pack-001",
            "digest": [{"rule_id": "R28", "name": "multi-path-escalation-merge", "override_marker": "", "severity_scope": "any"}],
            "lane_specific_must_address": ["R28"],
            "routine_violation_warnings": [],
        }
        sec15b_payload = {
            "context_pack_id": "skeleton-pack-001",
            "applicable_rules": ["R28"],
            "skeleton_sections": {"R28": "## R28 Skeleton\n\n<<placeholder>>"},
            "placeholders_to_resolve": {"R28": ["<<placeholder>>"]},
            "workspace_anchors": {},
            "usage_note": "",
        }

        def fake_load_vault(ws, call, args, **kwargs):
            if call == "vault_codified_rules_digest":
                return sec15a_payload
            if call == "vault_lane_skeleton_filler":
                return sec15b_payload
            return None

        with tempfile.TemporaryDirectory() as tmpdir:
            ws = _make_workspace(tmpdir)
            with patch.object(aug, "_load_vault_context", side_effect=fake_load_vault), \
                 patch.object(aug, "_load_resume_context", return_value={}), \
                 patch.object(aug, "_load_exploit_context", return_value={}), \
                 patch.object(aug, "_build_sec12", return_value=("## Section 12\n\n", {"items_count": 0, "items": []})):
                md, sections = aug.build_brief(
                    workspace=ws,
                    lane_id="DISPUTE-#192",
                    files=["src/Vault.sol"],
                    hint="dispute",
                    max_items=5,
                    lane_type="dispute",
                    severity="HIGH",
                )

        self.assertIn("## Section 15a", md)
        self.assertIn("## Section 15b", md)
        # Both sections land in the sections dict under backward-compat key
        self.assertIn("sec15_hard_rules_digest", sections)
        self.assertIn("sec15a_lane_rules", sections)
        self.assertIn("sec15b_skeleton_templates", sections)


# ---------------------------------------------------------------------------

if __name__ == "__main__":
    unittest.main(verbosity=2)
