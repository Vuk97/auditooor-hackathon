"""Tests for the 3 W2 plan 03 §12d MCP callables (SP-B, iter19).

Covers:
  * vault_bug_family_heatmap
  * vault_language_patterns
  * vault_dupe_rejection_context

Each callable has 3 tests:
  1. runs_without_input — empty args returns valid envelope (or degraded=true)
  2. filters_by_<key>   — filtered query returns expected subset
  3. caps_at_limit      — limit / top_n is honored
"""

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = REPO_ROOT / "tools" / "vault-mcp-server.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("vault_mcp_server", MODULE_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


vault_mcp_server = _load_module()


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

GRAPH_FIXTURE = {
    "generated_at": "2026-05-08T00:00:00Z",
    "audits_dir": "/tmp/audits",
    "workspaces_scanned": ["alpha-eng", "beta-eng", "gamma-eng"],
    "total_findings": 4,
    "total_edges": 0,
    "nodes": [
        {
            "workspace": "alpha-eng",
            "finding_id": "F1",
            "title": "Reentrancy in vault deposit path",
            "severity": "High",
            "matched_patterns": ["reentrancy"],
            "matched_detectors": [],
        },
        {
            "workspace": "alpha-eng",
            "finding_id": "F2",
            "title": "Oracle staleness in price feed",
            "severity": "Medium",
            "matched_patterns": ["oracle-staleness"],
            "matched_detectors": [],
        },
        {
            "workspace": "beta-eng",
            "finding_id": "F3",
            "title": "Signature replay in claim path",
            "severity": "Critical",
            "matched_patterns": ["signature-replay"],
            "matched_detectors": [],
        },
        {
            "workspace": "gamma-eng",
            "finding_id": "F4",
            "title": "Generic fix",
            "severity": "Low",
            "matched_patterns": [],
            "matched_detectors": [],
        },
    ],
}

FAMILIES_FIXTURE = """\
# Recurring bug families across engagements

## Bug-family heatmap

| Family | Total mentions | Seen in engagements |
|---|---:|---|
| `reentrancy` | 7 | alpha-eng, beta-eng |
| `oracle-staleness` | 4 | alpha-eng |
| `signature-replay` | 3 | beta-eng |
| `hook-bypass` | 1 | delta-eng |
"""


SOLIDITY_PATTERN = """\
pattern: foo-solidity-pattern
source: solodit/test
severity: HIGH
confidence: HIGH

# Test pattern for solidity (default language inference).
"""

RUST_PATTERN = """\
pattern: bar-rust-pattern
source: solodit/test
severity: MEDIUM
confidence: MEDIUM
language: rust

# Test pattern explicitly tagged as rust.
"""

GO_PATTERN = """\
pattern: baz-go-pattern
source: solodit/test
severity: CRITICAL
confidence: HIGH
language: go

# Test pattern explicitly tagged as go.
"""

GO_SIBLING_PATTERN = """\
pattern: r94-go-sibling-pattern
source: solodit/test-r94
severity: MEDIUM
confidence: MEDIUM
language: go

# Test pattern loaded from a patterns.dsl.* sibling dir.
"""

LOW_PATTERN = """\
pattern: low-priority-pattern
source: solodit/test
severity: LOW
confidence: LOW
language: solidity

# Low-score pattern — should rank below the others.
"""


OUTCOMES_FIXTURE = "\n".join(
    [
        json.dumps(
            {
                "date": "2026-04-18",
                "finding_id": "201",
                "outcome": "duplicate",
                "title": "Reentrancy in vault deposit path",
                "workspace": "alpha-eng",
                "bug_class": "reentrancy",
                "rejection_reason": "duplicate_of_internal_finding",
                "source": "submissions/SUBMISSIONS.md",
                "dupe_of": "INT-77",
            }
        ),
        json.dumps(
            {
                "date": "2026-04-19",
                "finding_id": "202",
                "outcome": "rejected",
                "title": "Oracle latency claim",
                "workspace": "alpha-eng",
                "bug_class": "oracle-staleness",
                "rejection_reason": "unknown",
                "source": "submissions/SUBMISSIONS.md",
            }
        ),
        json.dumps(
            {
                "date": "2026-04-20",
                "finding_id": "203",
                "outcome": "not_a_bug",
                "title": "Signature variant exploration",
                "workspace": "beta-eng",
                "bug_class": "signature-replay",
                "rejection_reason": "intended behavior",
                "source": "submissions/SUBMISSIONS.md",
            }
        ),
        json.dumps(
            {
                "date": "2026-04-21",
                "finding_id": "204",
                "outcome": "pending",
                "title": "Pending bug — should NOT appear",
                "workspace": "alpha-eng",
                "bug_class": "reentrancy",
                "source": "submissions/SUBMISSIONS.md",
            }
        ),
        json.dumps(
            {
                "date": "2026-04-22",
                "finding_id": "205",
                "outcome": "oos",
                "title": "Out-of-scope path",
                "workspace": "gamma-eng",
                "bug_class": "access-control",
                "rejection_reason": "OOS scope rule SC-3",
                "source": "submissions/SUBMISSIONS.md",
            }
        ),
    ]
)


def _make_repo(root: Path) -> None:
    (root / "reports").mkdir(parents=True, exist_ok=True)
    (root / "reference").mkdir(parents=True, exist_ok=True)
    (root / "reference" / "patterns.dsl").mkdir(parents=True, exist_ok=True)
    (root / "reference" / "patterns.dsl.r94_solodit_go").mkdir(
        parents=True, exist_ok=True
    )
    (root / "obsidian-vault").mkdir(parents=True, exist_ok=True)
    (root / "reports" / "cross_workspace_finding_graph.json").write_text(
        json.dumps(GRAPH_FIXTURE), encoding="utf-8"
    )
    (root / "reference" / "recurring_bug_families.md").write_text(
        FAMILIES_FIXTURE, encoding="utf-8"
    )
    (root / "reference" / "patterns.dsl" / "foo-sol.yaml").write_text(
        SOLIDITY_PATTERN, encoding="utf-8"
    )
    (root / "reference" / "patterns.dsl" / "bar-rust.yaml").write_text(
        RUST_PATTERN, encoding="utf-8"
    )
    (root / "reference" / "patterns.dsl" / "baz-go.yaml").write_text(
        GO_PATTERN, encoding="utf-8"
    )
    (root / "reference" / "patterns.dsl" / "low-priority.yaml").write_text(
        LOW_PATTERN, encoding="utf-8"
    )
    (root / "reference" / "patterns.dsl.r94_solodit_go" / "r94-go.yaml").write_text(
        GO_SIBLING_PATTERN, encoding="utf-8"
    )
    (root / "reference" / "outcomes.jsonl").write_text(
        OUTCOMES_FIXTURE, encoding="utf-8"
    )


def _make_vault(repo_root: Path):
    return vault_mcp_server.VaultQuery(repo_root / "obsidian-vault", repo_root)


# ---------------------------------------------------------------------------
# vault_bug_family_heatmap
# ---------------------------------------------------------------------------


class TestVaultBugFamilyHeatmap(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="vbfh-")
        self.root = Path(self.tmp.name)
        _make_repo(self.root)
        self.vault = _make_vault(self.root)

    def tearDown(self):
        self.tmp.cleanup()

    def test_bug_family_heatmap_runs_without_input(self):
        result = self.vault.vault_bug_family_heatmap()
        self.assertIn("context_pack_id", result)
        self.assertIn("context_pack_hash", result)
        self.assertEqual(result["schema"], vault_mcp_server.BUG_FAMILY_HEATMAP_SCHEMA)
        self.assertFalse(result["degraded"])
        self.assertGreater(len(result["heatmap"]), 0)
        # top_classes should be non-empty (we have multiple matches in fixture)
        self.assertIsInstance(result["top_classes"], list)

    def test_bug_family_heatmap_filters_by_engagement_list(self):
        result = self.vault.vault_bug_family_heatmap(
            engagement_list=["alpha-eng"]
        )
        self.assertEqual(result["engagements_returned"], ["alpha-eng"])
        for row in result["heatmap"]:
            self.assertEqual(row["engagement"], "alpha-eng")
        # alpha-eng has reentrancy + oracle-staleness in the graph
        families = {r["bug_family"] for r in result["heatmap"]}
        self.assertIn("reentrancy", families)
        self.assertIn("oracle-staleness", families)

    def test_bug_family_heatmap_caps_at_engagement_list_limit(self):
        # engagement_list itself is the cap (no separate limit param);
        # verify only the listed engagement appears.
        result = self.vault.vault_bug_family_heatmap(
            engagement_list=["beta-eng"]
        )
        self.assertEqual(len(result["engagements_returned"]), 1)
        for row in result["heatmap"]:
            self.assertEqual(row["engagement"], "beta-eng")


# ---------------------------------------------------------------------------
# vault_language_patterns
# ---------------------------------------------------------------------------


class TestVaultLanguagePatterns(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="vlp-")
        self.root = Path(self.tmp.name)
        _make_repo(self.root)
        self.vault = _make_vault(self.root)

    def tearDown(self):
        self.tmp.cleanup()

    def test_language_patterns_runs_without_input(self):
        result = self.vault.vault_language_patterns()
        self.assertIn("context_pack_id", result)
        self.assertEqual(result["schema"], vault_mcp_server.LANGUAGE_PATTERNS_SCHEMA)
        self.assertFalse(result["degraded"])
        self.assertEqual(result["language"], "all")
        self.assertEqual(result["total_scanned"], 5)
        # All 5 fixture patterns should be returned, including sibling DSL dirs.
        self.assertEqual(len(result["patterns"]), 5)
        self.assertIn("reference/patterns.dsl.r94_solodit_go/", result["source_refs"])
        # Highest-scoring pattern is the CRITICAL+HIGH go pattern (4*3 = 12)
        self.assertEqual(result["patterns"][0]["pattern_id"], "baz-go-pattern")

    def test_language_patterns_filters_by_language(self):
        result = self.vault.vault_language_patterns(language="rust")
        self.assertEqual(result["language"], "rust")
        # Only the rust pattern should be returned
        self.assertEqual(len(result["patterns"]), 1)
        self.assertEqual(result["patterns"][0]["pattern_id"], "bar-rust-pattern")
        self.assertEqual(result["patterns"][0]["language"], "rust")
        # language_summary still reports all-language counts
        self.assertEqual(
            sum(result["language_summary"].values()),
            result["total_scanned"],
        )

    def test_language_patterns_caps_at_top_n(self):
        result = self.vault.vault_language_patterns(top_n=2)
        self.assertEqual(result["top_n"], 2)
        self.assertEqual(len(result["patterns"]), 2)
        # Ordered by score desc — 1st = baz-go (12), 2nd = foo-sol (9)
        self.assertEqual(result["patterns"][0]["pattern_id"], "baz-go-pattern")
        self.assertEqual(result["patterns"][1]["pattern_id"], "foo-solidity-pattern")

    def test_language_patterns_includes_sibling_dsl_dirs(self):
        result = self.vault.vault_language_patterns(language="go")
        self.assertEqual(result["language"], "go")
        self.assertEqual(
            [row["pattern_id"] for row in result["patterns"]],
            ["baz-go-pattern", "r94-go-sibling-pattern"],
        )
        self.assertEqual(result["language_summary"]["go"], 2)


# ---------------------------------------------------------------------------
# vault_dupe_rejection_context
# ---------------------------------------------------------------------------


class TestVaultDupeRejectionContext(unittest.TestCase):

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="vdrc-")
        self.root = Path(self.tmp.name)
        _make_repo(self.root)
        self.vault = _make_vault(self.root)

    def tearDown(self):
        self.tmp.cleanup()

    def test_dupe_rejection_runs_without_input(self):
        result = self.vault.vault_dupe_rejection_context()
        self.assertIn("context_pack_id", result)
        self.assertEqual(
            result["schema"], vault_mcp_server.DUPE_REJECTION_CONTEXT_SCHEMA
        )
        self.assertFalse(result["degraded"])
        # 4 of 5 fixture rows have a dupe-rejection status (pending excluded)
        self.assertEqual(result["total_in_ledger"], 5)
        self.assertEqual(len(result["rejections"]), 4)
        statuses = {r["status"] for r in result["rejections"]}
        self.assertNotIn("pending", statuses)

    def test_dupe_rejection_filters_by_bug_class(self):
        result = self.vault.vault_dupe_rejection_context(bug_class="oracle")
        # Only the oracle-staleness rejected row matches
        self.assertEqual(len(result["rejections"]), 1)
        self.assertEqual(result["rejections"][0]["bug_class"], "oracle-staleness")
        self.assertEqual(result["filter"]["bug_class"], "oracle")
        # Summary reports per-bug-class totals across the FILTERED set
        self.assertEqual(result["summary"]["by_bug_class"], {"oracle-staleness": 1})

    def test_dupe_rejection_caps_at_limit(self):
        result = self.vault.vault_dupe_rejection_context(limit=2)
        self.assertEqual(result["filter"]["limit"], 2)
        self.assertEqual(len(result["rejections"]), 2)
        # total_filtered (pre-cap) still reflects all 4 matching rows
        self.assertEqual(result["summary"]["total_filtered"], 4)
        self.assertEqual(result["summary"]["total_returned"], 2)


# ---------------------------------------------------------------------------
# CLI dispatch + TOOL_SCHEMAS registration smoke
# ---------------------------------------------------------------------------


class TestCallablesRegistered(unittest.TestCase):

    def test_all_three_in_tool_schemas(self):
        names = {t["name"] for t in vault_mcp_server.TOOL_SCHEMAS}
        self.assertIn("vault_bug_family_heatmap", names)
        self.assertIn("vault_language_patterns", names)
        self.assertIn("vault_dupe_rejection_context", names)

    def test_dispatcher_routes_each_callable(self):
        with tempfile.TemporaryDirectory(prefix="vmcp-disp-") as tmp:
            root = Path(tmp)
            _make_repo(root)
            vault = _make_vault(root)
            for name in (
                "vault_bug_family_heatmap",
                "vault_language_patterns",
                "vault_dupe_rejection_context",
            ):
                out = vault.call(name, {})
                self.assertNotIn(
                    "error", out,
                    msg=f"{name} dispatcher missing: {out}",
                )
                self.assertIn("context_pack_id", out)


if __name__ == "__main__":
    unittest.main()
