#!/usr/bin/env python3
"""Wave-9 tests for tools/engage-report-parser.py.

Coverage (5+ assertions):
  T1  Parses morpho engage_report.md -> 50 hits, 24 clusters (exact header values)
  T2  Parses dydx engage_report.md -> 0 hits, 0 clusters (degenerate case)
  T3  Extracts file_path + line + snippet correctly (spot-check first cluster)
  T4  by_severity totals match sum of cluster hits
  T5  Missing file returns empty struct without crash (parse_ok=False)
  T6  Cluster-level expected_hits matches len(hits) for a spot-checked cluster
  T7  Synthetic multi-severity report parses severity breakdown correctly
"""
from __future__ import annotations

import importlib.util
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
MOD_PATH = REPO_ROOT / "tools" / "engage-report-parser.py"

MORPHO_REPORT = Path("/Users/wolf/audits/morpho/engage_report.md")
DYDX_REPORT = Path("/Users/wolf/audits/dydx/engage_report.md")


def _load() -> object:
    spec = importlib.util.spec_from_file_location("engage_report_parser_for_test", MOD_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load {MOD_PATH}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules["engage_report_parser_for_test"] = mod
    spec.loader.exec_module(mod)
    return mod


ER = _load()

# Synthetic engage_report with multiple severities for T7
SYNTHETIC_MULTI_SEV = textwrap.dedent("""\
# Engagement Report — synthetic-ws

- Workspace: `/Users/wolf/audits/synthetic-ws`
- Generated: 2026-05-11 00:00:00Z
- Total hits: **4**
- Severity: HIGH=1  MEDIUM=1  LOW=2
- Distinct detectors: 3
- Analogical clusters: 3

## Actionable Next Steps

- Triage (HIGH severity, LOW dupe risk): **1** hits
- Dupe-check (HIGH dupe risk): **0** hits
- Mine for novelty (no anchor + no cross-ws match): **3** hits

## Clusters

### Cluster: `reentrancy-no-guard` (1 hits)

- **[HIGH] `reentrancy-no-guard`** — `/Users/wolf/audits/synthetic-ws/src/Vault.sol:100`
  - snippet: `function withdraw(uint256 amount) external {`
  - dupe-risk: **LOW**
  - resembles: (reverse-correlator SKIPPED)
  - cross-ws: (lookup SKIPPED)

### Cluster: `unchecked-external-call` (1 hits)

- **[MEDIUM] `unchecked-external-call`** — `/Users/wolf/audits/synthetic-ws/src/Vault.sol:200`
  - snippet: `token.transfer(msg.sender, amount);`
  - dupe-risk: **SKIPPED**
  - resembles: (reverse-correlator SKIPPED)
  - cross-ws: (lookup SKIPPED)

### Cluster: `setters-with-no-access-control` (2 hits)

- **[LOW] `setters-with-no-access-control`** — `/Users/wolf/audits/synthetic-ws/src/Vault.sol:50`
  - snippet: `function setOwner(address newOwner) external {`
  - dupe-risk: **SKIPPED**
  - resembles: (reverse-correlator SKIPPED)
  - cross-ws: (lookup SKIPPED)
- **[LOW] `setters-with-no-access-control`** — `/Users/wolf/audits/synthetic-ws/src/Vault.sol:60`
  - snippet: `function setAdmin(address newAdmin) external {`
  - dupe-risk: **SKIPPED**
  - resembles: (reverse-correlator SKIPPED)
  - cross-ws: (lookup SKIPPED)

## No close historical match (best mining candidates)

- **[HIGH] `reentrancy-no-guard`** — `/Users/wolf/audits/synthetic-ws/src/Vault.sol:100`
  - function withdraw(uint256 amount) external {
""")


class TestEngageReportParser(unittest.TestCase):

    # T1: morpho 50 hits / 24 clusters
    @unittest.skipUnless(MORPHO_REPORT.exists(), "morpho engage_report.md not available")
    def test_t1_morpho_50_hits_24_clusters(self):
        result = ER.parse_engage_report(MORPHO_REPORT)
        self.assertTrue(result["parse_ok"], "parse_ok should be True for morpho")
        self.assertEqual(result["total_hits"], 50,
                         f"Expected 50 total_hits but got {result['total_hits']}")
        self.assertEqual(result["distinct_detectors"], 24,
                         f"Expected 24 distinct_detectors but got {result['distinct_detectors']}")
        self.assertEqual(len(result["clusters"]), 24,
                         f"Expected 24 clusters but got {len(result['clusters'])}")
        self.assertEqual(result["by_severity"]["HIGH"], 0)
        self.assertEqual(result["by_severity"]["MEDIUM"], 0)
        self.assertEqual(result["by_severity"]["LOW"], 50)

    # T2: dydx 0 hits / 0 clusters (degenerate)
    @unittest.skipUnless(DYDX_REPORT.exists(), "dydx engage_report.md not available")
    def test_t2_dydx_empty_degenerate(self):
        result = ER.parse_engage_report(DYDX_REPORT)
        self.assertTrue(result["parse_ok"], "parse_ok should be True even for empty report")
        self.assertEqual(result["total_hits"], 0)
        self.assertEqual(len(result["clusters"]), 0)

    # T3: file_path + line + snippet extraction (morpho first cluster)
    @unittest.skipUnless(MORPHO_REPORT.exists(), "morpho engage_report.md not available")
    def test_t3_extracts_file_path_line_snippet(self):
        result = ER.parse_engage_report(MORPHO_REPORT)
        # First cluster: setters-with-no-access-control, first hit VaultV2.sol:306
        first_cluster = result["clusters"][0]
        self.assertEqual(first_cluster["cluster_name"], "setters-with-no-access-control")
        first_hit = first_cluster["hits"][0]
        self.assertIn("VaultV2.sol", first_hit["file_path"],
                      "Expected VaultV2.sol in file_path")
        self.assertEqual(first_hit["line"], 306)
        self.assertIn("setOwner", first_hit["snippet"],
                      "Expected snippet to contain 'setOwner'")
        self.assertEqual(first_hit["detector_id"], "setters-with-no-access-control")

    # T4: by_severity totals match sum of cluster hits
    @unittest.skipUnless(MORPHO_REPORT.exists(), "morpho engage_report.md not available")
    def test_t4_by_severity_totals_match_cluster_sum(self):
        result = ER.parse_engage_report(MORPHO_REPORT)
        cluster_total = sum(len(cl["hits"]) for cl in result["clusters"])
        sev_total = sum(result["by_severity"].values())
        self.assertEqual(cluster_total, sev_total,
                         f"Cluster hit sum ({cluster_total}) != by_severity sum ({sev_total})")
        self.assertEqual(cluster_total, result["total_hits"],
                         f"Cluster hit sum ({cluster_total}) != header total_hits ({result['total_hits']})")

    # T5: missing file returns empty struct without crash
    def test_t5_missing_file_returns_empty_struct(self):
        result = ER.parse_engage_report(Path("/nonexistent/path/engage_report.md"))
        self.assertFalse(result["parse_ok"])
        self.assertEqual(result["total_hits"], 0)
        self.assertEqual(result["clusters"], [])
        self.assertIn("error", result)

    # T6: cluster expected_hits matches parsed len(hits)
    @unittest.skipUnless(MORPHO_REPORT.exists(), "morpho engage_report.md not available")
    def test_t6_cluster_expected_hits_match_parsed(self):
        result = ER.parse_engage_report(MORPHO_REPORT)
        mismatches = []
        for cl in result["clusters"]:
            if cl["expected_hits"] != len(cl["hits"]):
                mismatches.append(
                    f"{cl['cluster_name']}: expected={cl['expected_hits']} parsed={len(cl['hits'])}"
                )
        self.assertEqual(mismatches, [],
                         f"Cluster hit count mismatches: {mismatches}")

    # T7: synthetic multi-severity report parses severity breakdown correctly
    def test_t7_multi_severity_synthetic(self):
        with tempfile.NamedTemporaryFile(mode="w", suffix=".md",
                                         delete=False, encoding="utf-8") as f:
            f.write(SYNTHETIC_MULTI_SEV)
            tmp_path = Path(f.name)
        try:
            result = ER.parse_engage_report(tmp_path)
            self.assertTrue(result["parse_ok"])
            self.assertEqual(result["total_hits"], 4)
            self.assertEqual(len(result["clusters"]), 3)
            # Severity breakdown from parsed cluster hits
            self.assertEqual(result["by_severity"]["HIGH"], 1)
            self.assertEqual(result["by_severity"]["MEDIUM"], 1)
            self.assertEqual(result["by_severity"]["LOW"], 2)
            # Verify HIGH hit is reentrancy cluster
            high_cluster = next(
                cl for cl in result["clusters"] if cl["cluster_name"] == "reentrancy-no-guard"
            )
            self.assertEqual(len(high_cluster["hits"]), 1)
            self.assertEqual(high_cluster["hits"][0]["severity"], "HIGH")
            self.assertEqual(high_cluster["hits"][0]["line"], 100)
        finally:
            tmp_path.unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main()
