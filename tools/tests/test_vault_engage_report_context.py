"""Tests for vault_engage_report_context MCP callable.

W2-B-3 — verifies the engage_report.md context surface exposed via
vault-mcp-server.py.  Four required test cases:
  1. Returns graceful empty envelope when workspace is missing.
  2. Returns context pack with detector clusters from a real engage_report.md.
  3. Honors the ``limit`` parameter (≥1, ≤20).
  4. Returns deterministic context_pack_hash for same input.
"""

import hashlib
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = REPO_ROOT / "tools" / "vault-mcp-server.py"

# ---------------------------------------------------------------------------
# Synthetic engage_report.md fixture with 2 clusters and 3 hits total.
# ---------------------------------------------------------------------------
FIXTURE_ENGAGE_REPORT = """\
# Engagement Report — test-workspace

- Workspace: `/tmp/test-workspace`
- Generated: 2026-05-10 12:00:00Z
- Total hits: **5**
- Severity: HIGH=2  MEDIUM=1  LOW=2
- Distinct detectors: **2**
- Analogical clusters: **2**

## Actionable Next Steps

- Triage (HIGH severity, LOW dupe risk): **2** hits
- Dupe-check (HIGH dupe risk): **1** hits
- Mine for novelty (no anchor + no cross-ws match): **2** hits

## Clusters

### Cluster: `reentrancy-no-guard` (2 hits)

- **[HIGH] `reentrancy-no-guard`** — `/tmp/test-workspace/src/Vault.sol:42`
  - snippet: `function withdraw(uint256 amount) external {`
  - dupe-risk: **LOW**
  - resembles: (none)
  - cross-ws: (none)
- **[HIGH] `reentrancy-no-guard`** — `/tmp/test-workspace/src/Vault.sol:88`
  - snippet: `externalCall.transfer(amount);`
  - dupe-risk: **LOW**
  - resembles: (none)
  - cross-ws: (none)

### Cluster: `missing-zero-address-check` (3 hits)

- **[MEDIUM] `missing-zero-address-check`** — `/tmp/test-workspace/src/Config.sol:15`
  - snippet: `owner = newOwner;`
  - dupe-risk: **HIGH**
  - resembles: audit_pdfs#ownership-transfer
  - cross-ws: (none)
- **[LOW] `missing-zero-address-check`** — `/tmp/test-workspace/src/Config.sol:30`
  - snippet: `treasury = addr;`
  - dupe-risk: **LOW**
  - resembles: (none)
  - cross-ws: (none)
- **[LOW] `missing-zero-address-check`** — `/tmp/test-workspace/src/Config.sol:45`
  - snippet: `receiver = account;`
  - dupe-risk: **LOW**
  - resembles: (none)
  - cross-ws: (none)
"""


def _load_module():
    spec = importlib.util.spec_from_file_location("vault_mcp_server_engage", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


vault_mcp = _load_module()


def _make_vault(tmp_root: Path) -> object:
    """Return a VaultQuery bound to a minimal vault under tmp_root."""
    vault_dir = tmp_root / "obsidian-vault"
    vault_dir.mkdir(parents=True, exist_ok=True)
    return vault_mcp.VaultQuery(vault_dir, REPO_ROOT)


def _make_workspace_with_report(tmp_root: Path, content: str = FIXTURE_ENGAGE_REPORT) -> Path:
    """Create a fake workspace directory with an engage_report.md and return it."""
    ws = tmp_root / "ws"
    ws.mkdir(parents=True, exist_ok=True)
    (ws / "engage_report.md").write_text(content, encoding="utf-8")
    return ws


def _serialized_context(result: object) -> str:
    return json.dumps(result, sort_keys=True)


def _assert_no_absolute_path_leak(testcase: unittest.TestCase, result: object, raw_workspace: Path | str):
    payload = _serialized_context(result)
    testcase.assertNotIn("/tmp/", payload)
    testcase.assertNotIn("/Users/", payload)
    testcase.assertNotIn(str(raw_workspace), payload)


# ---------------------------------------------------------------------------
# Test 1: Graceful empty envelope when workspace is missing
# ---------------------------------------------------------------------------
class TestEngageReportContextMissingWorkspace(unittest.TestCase):
    """Test 1 — callable returns graceful empty envelope for a missing workspace."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="auditooor-engage-t1-")
        self.vault = _make_vault(Path(self.tmp.name))

    def tearDown(self):
        self.tmp.cleanup()

    def test_missing_workspace_returns_report_found_false(self):
        result = self.vault.vault_engage_report_context(
            workspace_path="/nonexistent/path/does_not_exist_xyzzy"
        )
        self.assertFalse(result["report_found"])

    def test_missing_workspace_error_key_set(self):
        result = self.vault.vault_engage_report_context(
            workspace_path="/nonexistent/path/does_not_exist_xyzzy"
        )
        self.assertIn("error", result)
        self.assertIn("not_found", result["error"])

    def test_missing_workspace_has_context_pack_id(self):
        result = self.vault.vault_engage_report_context(
            workspace_path="/nonexistent/path/does_not_exist_xyzzy"
        )
        self.assertIn("context_pack_id", result)
        self.assertIn("context_pack_hash", result)

    def test_missing_workspace_clusters_empty(self):
        result = self.vault.vault_engage_report_context(
            workspace_path="/nonexistent/path/does_not_exist_xyzzy"
        )
        self.assertEqual(result["clusters"], [])
        self.assertEqual(result["total_hits"], 0)

    def test_missing_engage_report_file_returns_graceful_envelope(self):
        """Workspace dir exists but lacks engage_report.md."""
        ws = Path(self.tmp.name) / "ws_no_report"
        ws.mkdir(parents=True, exist_ok=True)
        result = self.vault.vault_engage_report_context(workspace_path=str(ws))
        self.assertFalse(result["report_found"])
        self.assertIn("error", result)
        self.assertEqual(result["clusters"], [])

    def test_schema_field_present_on_empty_envelope(self):
        result = self.vault.vault_engage_report_context(
            workspace_path="/nonexistent/path/does_not_exist_xyzzy"
        )
        self.assertEqual(result["schema"], vault_mcp.ENGAGE_REPORT_CONTEXT_SCHEMA)

    def test_kind_field_present_on_empty_envelope(self):
        result = self.vault.vault_engage_report_context(
            workspace_path="/nonexistent/path/does_not_exist_xyzzy"
        )
        self.assertEqual(result["kind"], "engage_report_context")

    def test_missing_workspace_does_not_echo_absolute_path(self):
        raw_workspace = "/tmp/does_not_exist_xyzzy"
        result = self.vault.vault_engage_report_context(workspace_path=raw_workspace)
        _assert_no_absolute_path_leak(self, result, raw_workspace)


# ---------------------------------------------------------------------------
# Test 2: Returns context pack with detector clusters from real engage_report.md
# ---------------------------------------------------------------------------
class TestEngageReportContextRealReport(unittest.TestCase):
    """Test 2 — callable parses a real-ish engage_report.md and returns clusters."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="auditooor-engage-t2-")
        self.vault = _make_vault(Path(self.tmp.name))
        self.ws = _make_workspace_with_report(Path(self.tmp.name))

    def tearDown(self):
        self.tmp.cleanup()

    def test_report_found_true(self):
        result = self.vault.vault_engage_report_context(workspace_path=str(self.ws))
        self.assertTrue(result["report_found"])

    def test_report_path_present(self):
        result = self.vault.vault_engage_report_context(workspace_path=str(self.ws))
        self.assertIsNotNone(result["report_path"])
        self.assertTrue(result["report_path"].endswith("engage_report.md"))
        self.assertEqual(result["report_path"], "workspace:engage_report.md")

    def test_total_hits_parsed(self):
        result = self.vault.vault_engage_report_context(workspace_path=str(self.ws))
        self.assertEqual(result["total_hits"], 5)

    def test_distinct_detectors_parsed(self):
        result = self.vault.vault_engage_report_context(workspace_path=str(self.ws))
        self.assertEqual(result["distinct_detectors"], 2)

    def test_parses_non_bold_distinct_and_cluster_counts(self):
        non_bold = (
            FIXTURE_ENGAGE_REPORT
            .replace("- Distinct detectors: **2**", "- Distinct detectors: 2")
            .replace("- Analogical clusters: **2**", "- Analogical clusters: 2")
        )
        (self.ws / "engage_report.md").write_text(non_bold, encoding="utf-8")
        result = self.vault.vault_engage_report_context(workspace_path=str(self.ws))
        self.assertEqual(result["distinct_detectors"], 2)
        self.assertEqual(result["analogical_clusters"], 2)

    def test_severity_summary_parsed(self):
        result = self.vault.vault_engage_report_context(workspace_path=str(self.ws))
        sev = result["severity_summary"]
        self.assertEqual(sev["HIGH"], 2)
        self.assertEqual(sev["MEDIUM"], 1)
        self.assertEqual(sev["LOW"], 2)

    def test_actionable_next_steps_parsed(self):
        result = self.vault.vault_engage_report_context(workspace_path=str(self.ws))
        ns = result["actionable_next_steps"]
        self.assertEqual(ns["triage"], 2)
        self.assertEqual(ns["dupe_check"], 1)
        self.assertEqual(ns["mine"], 2)

    def test_clusters_list_nonempty(self):
        result = self.vault.vault_engage_report_context(workspace_path=str(self.ws))
        self.assertGreater(len(result["clusters"]), 0)

    def test_cluster_has_required_keys(self):
        result = self.vault.vault_engage_report_context(workspace_path=str(self.ws))
        for cluster in result["clusters"]:
            for key in ("detector_slug", "hit_count", "hits"):
                self.assertIn(key, cluster, f"Cluster missing key: {key}")

    def test_first_cluster_slug(self):
        result = self.vault.vault_engage_report_context(workspace_path=str(self.ws))
        slugs = [c["detector_slug"] for c in result["clusters"]]
        self.assertIn("reentrancy-no-guard", slugs)

    def test_second_cluster_slug(self):
        result = self.vault.vault_engage_report_context(workspace_path=str(self.ws))
        slugs = [c["detector_slug"] for c in result["clusters"]]
        self.assertIn("missing-zero-address-check", slugs)

    def test_hit_has_severity_and_file_path(self):
        result = self.vault.vault_engage_report_context(workspace_path=str(self.ws))
        first_cluster = result["clusters"][0]
        if first_cluster["hits"]:
            hit = first_cluster["hits"][0]
            self.assertIn("severity", hit)
            self.assertIn("file_path", hit)
            self.assertIn("snippet", hit)
            self.assertEqual(hit["file_path"], "src/Vault.sol:42")

    def test_context_payload_does_not_leak_tmp_or_raw_workspace_paths(self):
        result = self.vault.vault_engage_report_context(workspace_path=str(self.ws))
        _assert_no_absolute_path_leak(self, result, self.ws)
        self.assertEqual(result["workspace_path"], self.ws.name)

    def test_context_payload_does_not_leak_users_paths_from_hits_or_snippets(self):
        report = FIXTURE_ENGAGE_REPORT.replace(
            "/tmp/test-workspace/src/Vault.sol:42",
            "/Users/wolf/audits/private-ws/contracts/Vault.sol:42",
        ).replace(
            "function withdraw(uint256 amount) external {",
            "touches /Users/wolf/audits/private-ws/contracts/Vault.sol before call",
        )
        (self.ws / "engage_report.md").write_text(report, encoding="utf-8")
        result = self.vault.vault_engage_report_context(workspace_path=str(self.ws))
        _assert_no_absolute_path_leak(self, result, self.ws)
        self.assertNotIn("/Users/", _serialized_context(result))

    def test_context_payload_does_not_leak_macos_private_var_paths_from_snippets(self):
        report = FIXTURE_ENGAGE_REPORT.replace(
            "function withdraw(uint256 amount) external {",
            "touches /private/var/folders/aa/bb/T/private-ws/contracts/Vault.sol before call",
        ).replace(
            "require(to != address(0));",
            "touches /var/folders/aa/bb/T/private-ws/contracts/Token.sol before call",
        )
        (self.ws / "engage_report.md").write_text(report, encoding="utf-8")
        result = self.vault.vault_engage_report_context(workspace_path=str(self.ws))
        payload = _serialized_context(result)
        self.assertNotIn("/private/var/", payload)
        self.assertNotIn("/var/folders/", payload)
        _assert_no_absolute_path_leak(self, result, self.ws)

    def test_prefers_json_sidecar_when_present(self):
        sidecar = {
            "schema": "auditooor.engage_report.sidecar.v1",
            "kind": "engage_report_sidecar",
            "total_hits": 7,
            "distinct_detectors": 3,
            "analogical_clusters": 1,
            "severity_summary": {"HIGH": 4, "MEDIUM": 2, "LOW": 1},
            "actionable_next_steps": {"triage": 3, "dupe_check": 1, "mine": 3},
            "clusters": [
                {
                    "detector_slug": "json-sidecar-cluster",
                    "hit_count": 2,
                    "hits": [
                        {
                            "severity": "HIGH",
                            "file_path": "/tmp/test-workspace/src/Sidecar.sol:99",
                            "snippet": "calls /Users/wolf/private/path before transfer",
                        }
                    ],
                }
            ],
        }
        (self.ws / "engage_report.json").write_text(json.dumps(sidecar), encoding="utf-8")
        result = self.vault.vault_engage_report_context(workspace_path=str(self.ws))
        self.assertEqual(result["report_path"], "workspace:engage_report.json")
        self.assertEqual(result["total_hits"], 7)
        self.assertEqual(result["clusters"][0]["detector_slug"], "json-sidecar-cluster")
        self.assertEqual(result["clusters"][0]["hits"][0]["file_path"], "src/Sidecar.sol:99")
        self.assertNotIn("/Users/", _serialized_context(result))

    def test_invalid_json_sidecar_falls_back_to_markdown(self):
        (self.ws / "engage_report.json").write_text("{not-json", encoding="utf-8")
        result = self.vault.vault_engage_report_context(workspace_path=str(self.ws))
        self.assertEqual(result["report_path"], "workspace:engage_report.md")
        self.assertEqual(result["total_hits"], 5)

    def test_json_sidecar_works_without_markdown_report(self):
        (self.ws / "engage_report.md").unlink()
        sidecar = {
            "total_hits": 1,
            "distinct_detectors": 1,
            "analogical_clusters": 1,
            "severity_summary": {"HIGH": 1, "MEDIUM": 0, "LOW": 0},
            "actionable_next_steps": {"triage": 1, "dupe_check": 0, "mine": 0},
            "clusters": [
                {
                    "detector_slug": "only-json",
                    "hit_count": 1,
                    "hits": [{"severity": "HIGH", "file_path": "src/A.sol:1", "snippet": "x"}],
                }
            ],
        }
        (self.ws / "engage_report.json").write_text(json.dumps(sidecar), encoding="utf-8")
        result = self.vault.vault_engage_report_context(workspace_path=str(self.ws))
        self.assertTrue(result["report_found"])
        self.assertEqual(result["report_path"], "workspace:engage_report.json")
        self.assertEqual(result["total_hits"], 1)

    def test_context_pack_id_has_schema_prefix(self):
        result = self.vault.vault_engage_report_context(workspace_path=str(self.ws))
        self.assertTrue(
            result["context_pack_id"].startswith(vault_mcp.ENGAGE_REPORT_CONTEXT_SCHEMA + ":"),
            f"pack_id={result['context_pack_id']!r} missing schema prefix",
        )

    def test_clusters_returned_count_consistent(self):
        result = self.vault.vault_engage_report_context(workspace_path=str(self.ws))
        self.assertEqual(result["clusters_returned"], len(result["clusters"]))

    def test_required_top_level_keys(self):
        result = self.vault.vault_engage_report_context(workspace_path=str(self.ws))
        required = (
            "schema", "kind", "workspace_path", "report_path", "report_found",
            "total_hits", "distinct_detectors", "analogical_clusters",
            "severity_summary", "actionable_next_steps", "clusters",
            "limit", "clusters_returned", "privacy_guards",
            "context_pack_id", "context_pack_hash",
        )
        for key in required:
            self.assertIn(key, result, f"Missing required key: {key}")


# ---------------------------------------------------------------------------
# Test 3: Honors limit parameter
# ---------------------------------------------------------------------------
class TestEngageReportContextLimit(unittest.TestCase):
    """Test 3 — callable respects the ``limit`` parameter."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="auditooor-engage-t3-")
        self.vault = _make_vault(Path(self.tmp.name))
        self.ws = _make_workspace_with_report(Path(self.tmp.name))

    def tearDown(self):
        self.tmp.cleanup()

    def test_limit_1_returns_at_most_1_cluster(self):
        result = self.vault.vault_engage_report_context(
            workspace_path=str(self.ws), limit=1
        )
        self.assertLessEqual(len(result["clusters"]), 1)

    def test_limit_echoed_in_output(self):
        result = self.vault.vault_engage_report_context(
            workspace_path=str(self.ws), limit=1
        )
        self.assertEqual(result["limit"], 1)

    def test_limit_20_returns_all_clusters_in_fixture(self):
        result = self.vault.vault_engage_report_context(
            workspace_path=str(self.ws), limit=20
        )
        # fixture has 2 clusters; both should come through
        self.assertEqual(len(result["clusters"]), 2)

    def test_limit_exceeds_max_clamped_to_20(self):
        """limit > 20 must be clamped to 20 (MAX_ENGAGE_REPORT_CLUSTERS)."""
        result = self.vault.vault_engage_report_context(
            workspace_path=str(self.ws), limit=999
        )
        self.assertLessEqual(result["limit"], 20)

    def test_limit_0_treated_as_1(self):
        """limit <= 0 must be clamped to 1 (via _clamp_limit)."""
        result = self.vault.vault_engage_report_context(
            workspace_path=str(self.ws), limit=0
        )
        self.assertGreaterEqual(result["limit"], 1)

    def test_default_limit_is_10(self):
        """When limit is omitted, default is 10."""
        result = self.vault.vault_engage_report_context(workspace_path=str(self.ws))
        self.assertEqual(result["limit"], 10)


# ---------------------------------------------------------------------------
# Test 4: Deterministic context_pack_hash for same input
# ---------------------------------------------------------------------------
class TestEngageReportContextDeterminism(unittest.TestCase):
    """Test 4 — context_pack_hash is deterministic for the same engage_report content."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="auditooor-engage-t4-")
        self.vault = _make_vault(Path(self.tmp.name))

    def tearDown(self):
        self.tmp.cleanup()

    def test_same_content_same_hash(self):
        ws = _make_workspace_with_report(Path(self.tmp.name))
        r1 = self.vault.vault_engage_report_context(workspace_path=str(ws))
        r2 = self.vault.vault_engage_report_context(workspace_path=str(ws))
        self.assertEqual(r1["context_pack_hash"], r2["context_pack_hash"])

    def test_different_content_different_hash(self):
        ws1 = _make_workspace_with_report(
            Path(self.tmp.name) / "ws1", FIXTURE_ENGAGE_REPORT
        )
        (Path(self.tmp.name) / "ws1").mkdir(parents=True, exist_ok=True)
        (Path(self.tmp.name) / "ws1" / "engage_report.md").write_text(
            FIXTURE_ENGAGE_REPORT, encoding="utf-8"
        )
        ws2_dir = Path(self.tmp.name) / "ws2"
        ws2_dir.mkdir(parents=True, exist_ok=True)
        alt_report = FIXTURE_ENGAGE_REPORT.replace("Total hits: **5**", "Total hits: **99**")
        (ws2_dir / "engage_report.md").write_text(alt_report, encoding="utf-8")
        r1 = self.vault.vault_engage_report_context(workspace_path=str(ws1))
        r2 = self.vault.vault_engage_report_context(workspace_path=str(ws2_dir))
        self.assertNotEqual(r1["context_pack_hash"], r2["context_pack_hash"])

    def test_pack_hash_is_64_hex_chars(self):
        ws = _make_workspace_with_report(Path(self.tmp.name) / "wshash")
        ws.mkdir(parents=True, exist_ok=True)
        (ws / "engage_report.md").write_text(FIXTURE_ENGAGE_REPORT, encoding="utf-8")
        result = self.vault.vault_engage_report_context(workspace_path=str(ws))
        self.assertEqual(len(result["context_pack_hash"]), 64)
        int(result["context_pack_hash"], 16)  # must be valid hex

    def test_empty_envelope_hash_deterministic(self):
        r1 = self.vault.vault_engage_report_context(
            workspace_path="/nonexistent/path/xyzzy_abc"
        )
        r2 = self.vault.vault_engage_report_context(
            workspace_path="/nonexistent/path/xyzzy_abc"
        )
        self.assertEqual(r1["context_pack_hash"], r2["context_pack_hash"])


# ---------------------------------------------------------------------------
# Test 5: Dispatcher and schema registration
# ---------------------------------------------------------------------------
class TestEngageReportContextDispatch(unittest.TestCase):
    """Test 5 — call() dispatcher and TOOL_SCHEMAS registration."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="auditooor-engage-t5-")
        self.vault = _make_vault(Path(self.tmp.name))

    def tearDown(self):
        self.tmp.cleanup()

    def test_dispatch_routes_correctly(self):
        result = self.vault.call(
            "vault_engage_report_context",
            {"workspace_path": "/nonexistent/path/xyzzy_dispatch"},
        )
        self.assertIn("context_pack_id", result)

    def test_tool_schema_registered(self):
        names = [t["name"] for t in vault_mcp.TOOL_SCHEMAS]
        self.assertIn("vault_engage_report_context", names)

    def test_schema_constant_defined(self):
        self.assertTrue(hasattr(vault_mcp, "ENGAGE_REPORT_CONTEXT_SCHEMA"))
        self.assertIn("engage_report_context", vault_mcp.ENGAGE_REPORT_CONTEXT_SCHEMA)

    def test_tool_schema_has_description(self):
        schema = next(
            t for t in vault_mcp.TOOL_SCHEMAS if t["name"] == "vault_engage_report_context"
        )
        self.assertIn("engage_report", schema["description"].lower())

    def test_tool_schema_has_workspace_path_property(self):
        schema = next(
            t for t in vault_mcp.TOOL_SCHEMAS if t["name"] == "vault_engage_report_context"
        )
        props = schema["inputSchema"]["properties"]
        self.assertIn("workspace_path", props)

    def test_tool_schema_has_limit_property(self):
        schema = next(
            t for t in vault_mcp.TOOL_SCHEMAS if t["name"] == "vault_engage_report_context"
        )
        props = schema["inputSchema"]["properties"]
        self.assertIn("limit", props)
        self.assertEqual(props["limit"]["maximum"], 20)


if __name__ == "__main__":
    unittest.main()
