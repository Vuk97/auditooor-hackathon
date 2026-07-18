"""Tests for tools/wave3-cluster-to-hacker-brief.py.

Synthetic fixtures only.  Each fixture workspace is marked
``synthetic_fixture: true`` per operator emphasis.  No corpus material is
created.

Test matrix (8 cases):
  1. test_single_cluster_brief_emission       single --cluster invocation
  2. test_all_clusters_batch_mode             --all writes one brief per cluster
  3. test_cluster_matches_prior_concerns_block PRIOR_CONCERNS BLOCKS the brief
  4. test_severity_medium_rubric_mapping      MEDIUM hit -> Medium rubric hint
  5. test_severity_critical_rubric_mapping    CRITICAL hit -> Critical rubric hint
  6. test_affected_sites_parsed_correctly     file:line refs in markdown body
  7. test_cluster_not_found_returns_error     unknown cluster -> ok=False
  8. test_json_format_output                  --format json writes JSON body
"""
from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from typing import Any, Dict, List

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
TOOL_PATH = REPO_ROOT / "tools" / "wave3-cluster-to-hacker-brief.py"


def _load_module():
    spec = importlib.util.spec_from_file_location(
        "wave3_cluster_to_hacker_brief", str(TOOL_PATH)
    )
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


W3 = _load_module()


SYNTHETIC_MARKER = "synthetic_fixture: true"


def _make_engage_report(
    tmp: Path,
    clusters: List[Dict[str, Any]],
    *,
    workspace_label: str = "/tmp/fake/ws",
) -> Path:
    """Build a minimal engage_report.md the parser accepts.

    clusters: [{name: str, hits: [{severity, detector, file_path, line, snippet?}]}]
    """
    total_hits = sum(len(c["hits"]) for c in clusters)
    by_sev = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    distinct_detectors = set()
    for c in clusters:
        for h in c["hits"]:
            sev = h.get("severity", "LOW").upper()
            if sev == "CRITICAL":
                by_sev["HIGH"] += 1
            elif sev in by_sev:
                by_sev[sev] += 1
            else:
                by_sev["LOW"] += 1
            distinct_detectors.add(h.get("detector", c["name"]))

    lines: List[str] = []
    lines.append(f"<!-- {SYNTHETIC_MARKER} -->")
    lines.append("# engage report")
    lines.append("")
    lines.append(f"- Workspace: `{workspace_label}`")
    lines.append(f"- Total hits: **{total_hits}**")
    lines.append(f"- Severity: HIGH={by_sev['HIGH']}  MEDIUM={by_sev['MEDIUM']}  LOW={by_sev['LOW']}")
    lines.append(f"- Distinct detectors: {len(distinct_detectors)}")
    lines.append("")
    lines.append("## Clusters")
    lines.append("")
    for c in clusters:
        lines.append(f"### Cluster: `{c['name']}` ({len(c['hits'])} hits)")
        lines.append("")
        for h in c["hits"]:
            sev = h.get("severity", "LOW").upper()
            det = h.get("detector", c["name"])
            fp = h["file_path"]
            ln = h["line"]
            snip = h.get("snippet", "")
            lines.append(f"- **[{sev}] `{det}`** - `{fp}:{ln}`")
            if snip:
                lines.append(f"  - snippet: `{snip}`")
            lines.append("  - dupe-risk: **SKIPPED**")
            lines.append("  - cross-ws: (lookup SKIPPED)")
        lines.append("")
    report_path = tmp / "engage_report.md"
    report_path.write_text("\n".join(lines), encoding="utf-8")
    return report_path


def _make_prior_concerns(tmp: Path, body: str) -> Path:
    path = tmp / "PRIOR_CONCERNS.md"
    path.write_text(f"<!-- {SYNTHETIC_MARKER} -->\n# PRIOR_CONCERNS\n\n{body}\n", encoding="utf-8")
    return path


class WaveThreeClusterToHackerBriefTests(unittest.TestCase):

    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmpdir.name)

    def tearDown(self) -> None:
        self._tmpdir.cleanup()

    # ---- 1 ------------------------------------------------------------
    def test_single_cluster_brief_emission(self):
        ws = self.tmp
        _make_engage_report(
            ws,
            [
                {
                    "name": "wrapper-passes-zero-slippage-to-internal-call",
                    "hits": [
                        {
                            "severity": "MEDIUM",
                            "detector": "wrapper-passes-zero-slippage-to-internal-call",
                            "file_path": "/x/src/Wrapper.sol",
                            "line": 42,
                            "snippet": "internalSwap(amount, 0, deadline);",
                        }
                    ],
                }
            ],
        )
        out_dir = ws / "hacker_briefs"
        result = W3.process_workspace(
            workspace=ws,
            cluster_name="wrapper-passes-zero-slippage-to-internal-call",
            out_dir=out_dir,
            fmt="markdown",
            process_all=False,
            allow_blocked=False,
        )
        self.assertTrue(result["ok"])
        self.assertEqual(len(result["briefs"]), 1)
        brief = result["briefs"][0]
        self.assertFalse(brief["blocked"])
        self.assertTrue(brief["written_to"])
        body = Path(brief["written_to"]).read_text(encoding="utf-8")
        self.assertIn("# Hacker Brief: wrapper-passes-zero-slippage-to-internal-call", body)
        self.assertIn("## Precondition", body)
        self.assertIn("## Action", body)
        self.assertIn("## Impact", body)
        self.assertIn("## Severity rubric candidate", body)
        self.assertIn("## PoC shape", body)
        self.assertIn("## Originality angle", body)
        self.assertIn("## Rule 30 scaffold notes", body)

    # ---- 2 ------------------------------------------------------------
    def test_all_clusters_batch_mode(self):
        ws = self.tmp
        _make_engage_report(
            ws,
            [
                {
                    "name": "unprotected-initialize",
                    "hits": [
                        {"severity": "HIGH", "detector": "unprotected-initialize",
                         "file_path": "/x/A.sol", "line": 10}
                    ],
                },
                {
                    "name": "setters-no-access-control",
                    "hits": [
                        {"severity": "LOW", "detector": "setters-no-access-control",
                         "file_path": "/x/B.sol", "line": 20}
                    ],
                },
                {
                    "name": "reentrancy-no-eth",
                    "hits": [
                        {"severity": "MEDIUM", "detector": "reentrancy-no-eth",
                         "file_path": "/x/C.sol", "line": 30}
                    ],
                },
            ],
        )
        out_dir = ws / "hacker_briefs"
        result = W3.process_workspace(
            workspace=ws,
            cluster_name=None,
            out_dir=out_dir,
            fmt="markdown",
            process_all=True,
            allow_blocked=False,
        )
        self.assertTrue(result["ok"])
        self.assertEqual(len(result["briefs"]), 3)
        for b in result["briefs"]:
            self.assertFalse(b["blocked"])
            self.assertTrue(Path(b["written_to"]).exists())

    # ---- 3 ------------------------------------------------------------
    def test_cluster_matches_prior_concerns_block(self):
        ws = self.tmp
        _make_engage_report(
            ws,
            [
                {
                    "name": "owner-can-set-fee",
                    "hits": [
                        {"severity": "LOW", "detector": "owner-can-set-fee",
                         "file_path": "/x/Fee.sol", "line": 5}
                    ],
                }
            ],
        )
        _make_prior_concerns(
            ws,
            "- `owner-can-set-fee`: acknowledged-by-design (owner is trusted multisig).",
        )
        out_dir = ws / "hacker_briefs"
        result = W3.process_workspace(
            workspace=ws,
            cluster_name="owner-can-set-fee",
            out_dir=out_dir,
            fmt="markdown",
            process_all=False,
            allow_blocked=False,
        )
        self.assertTrue(result["ok"])
        self.assertEqual(len(result["briefs"]), 1)
        brief = result["briefs"][0]
        self.assertTrue(brief["blocked"])
        self.assertIn("PRIOR_CONCERNS", brief["block_reason"])
        self.assertIsNone(brief["written_to"])

    # ---- 4 ------------------------------------------------------------
    def test_severity_medium_rubric_mapping(self):
        hint = W3.severity_rubric_candidate("MEDIUM")
        self.assertIn("Medium", hint)
        self.assertIn("SEVERITY.md", hint)

    # ---- 5 ------------------------------------------------------------
    def test_severity_critical_rubric_mapping(self):
        hint = W3.severity_rubric_candidate("CRITICAL")
        self.assertIn("Critical", hint)
        self.assertIn("Direct loss of funds", hint)
        self.assertIn("SEVERITY.md", hint)

    # ---- 6 ------------------------------------------------------------
    def test_affected_sites_parsed_correctly(self):
        ws = self.tmp
        _make_engage_report(
            ws,
            [
                {
                    "name": "missing-zero-check",
                    "hits": [
                        {"severity": "LOW", "detector": "missing-zero-check",
                         "file_path": "/x/Token.sol", "line": 101},
                        {"severity": "LOW", "detector": "missing-zero-check",
                         "file_path": "/x/Vault.sol", "line": 202},
                    ],
                }
            ],
        )
        out_dir = ws / "hacker_briefs"
        result = W3.process_workspace(
            workspace=ws,
            cluster_name="missing-zero-check",
            out_dir=out_dir,
            fmt="markdown",
            process_all=False,
            allow_blocked=False,
        )
        self.assertTrue(result["ok"])
        body = Path(result["briefs"][0]["written_to"]).read_text(encoding="utf-8")
        self.assertIn("/x/Token.sol:101", body)
        self.assertIn("/x/Vault.sol:202", body)
        self.assertIn("## Affected sites", body)

    # ---- 7 ------------------------------------------------------------
    def test_cluster_not_found_returns_error(self):
        ws = self.tmp
        _make_engage_report(
            ws,
            [
                {
                    "name": "real-cluster",
                    "hits": [
                        {"severity": "LOW", "detector": "real-cluster",
                         "file_path": "/x/A.sol", "line": 1}
                    ],
                }
            ],
        )
        out_dir = ws / "hacker_briefs"
        result = W3.process_workspace(
            workspace=ws,
            cluster_name="nonexistent-cluster",
            out_dir=out_dir,
            fmt="markdown",
            process_all=False,
            allow_blocked=False,
        )
        self.assertFalse(result["ok"])
        self.assertIn("not found", result["error"])
        self.assertIn("real-cluster", result.get("available_clusters", []))

    # ---- 8 ------------------------------------------------------------
    def test_json_format_output(self):
        ws = self.tmp
        _make_engage_report(
            ws,
            [
                {
                    "name": "json-format-cluster",
                    "hits": [
                        {"severity": "HIGH", "detector": "json-format-cluster",
                         "file_path": "/x/J.sol", "line": 7}
                    ],
                }
            ],
        )
        out_dir = ws / "hacker_briefs"
        result = W3.process_workspace(
            workspace=ws,
            cluster_name="json-format-cluster",
            out_dir=out_dir,
            fmt="json",
            process_all=False,
            allow_blocked=False,
        )
        self.assertTrue(result["ok"])
        body_path = Path(result["briefs"][0]["written_to"])
        self.assertTrue(str(body_path).endswith(".json"))
        record = json.loads(body_path.read_text(encoding="utf-8"))
        self.assertEqual(record["schema"], W3.SCHEMA)
        self.assertEqual(record["cluster_name"], "json-format-cluster")
        self.assertEqual(record["dominant_severity"], "HIGH")
        self.assertEqual(record["hit_count"], 1)
        self.assertIn("precondition", record)
        self.assertIn("severity_rubric_candidate", record)


def _make_priority_envelope(tmp: Path, ranked_classes: List[str]) -> Path:
    """Write a minimal auditooor.bug_class_priority.v1 envelope.

    ranked_classes is best-first; rank 1 = highest dispatch priority.
    """
    env = {
        "schema": "auditooor.bug_class_priority.v1",
        "kind": "bug_class_priority",
        "workspace": "/tmp/fake/ws",
        "ranked_attack_classes": [
            {
                "attack_class": cls,
                "rank": i,
                "priority": round(1.0 - (i - 1) * 0.1, 4),
            }
            for i, cls in enumerate(ranked_classes, start=1)
        ],
    }
    path = tmp / "bug_class_priority.json"
    path.write_text(json.dumps(env, indent=2), encoding="utf-8")
    return path


class WaveThreePriorityDispatchTests(unittest.TestCase):
    """LANE W5-H2: prove the W4.13 prioritizer drives dispatch ordering."""

    def setUp(self) -> None:
        self._tmpdir = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmpdir.name)

    def tearDown(self) -> None:
        self._tmpdir.cleanup()

    def _three_cluster_report(self) -> None:
        # parser-native order: A, B, C.
        _make_engage_report(
            self.tmp,
            [
                {"name": "low-priority-class", "hits": [
                    {"severity": "LOW", "detector": "low-priority-class",
                     "file_path": "/x/A.sol", "line": 10}]},
                {"name": "mid-priority-class", "hits": [
                    {"severity": "MEDIUM", "detector": "mid-priority-class",
                     "file_path": "/x/B.sol", "line": 20}]},
                {"name": "top-priority-class", "hits": [
                    {"severity": "HIGH", "detector": "top-priority-class",
                     "file_path": "/x/C.sol", "line": 30}]},
            ],
        )

    # ---- 9: priority file reorders dispatch -------------------------------
    def test_priority_json_reorders_dispatch(self):
        self._three_cluster_report()
        # prioritizer says: top, mid, low - INVERSE of parser-native order.
        prio = _make_priority_envelope(
            self.tmp,
            ["top-priority-class", "mid-priority-class", "low-priority-class"],
        )
        result = W3.process_workspace(
            workspace=self.tmp, cluster_name=None,
            out_dir=self.tmp / "hacker_briefs", fmt="markdown",
            process_all=True, allow_blocked=False, priority_json=prio,
        )
        self.assertTrue(result["ok"])
        self.assertTrue(result["priority_applied"])
        order = [b["cluster_name"] for b in result["briefs"]]
        # dispatch order must be prioritizer order, NOT parser-native order.
        self.assertEqual(
            order,
            ["top-priority-class", "mid-priority-class", "low-priority-class"],
        )
        # dispatch_order index runs 1..N and priority_rank is resolved.
        self.assertEqual([b["dispatch_order"] for b in result["briefs"]], [1, 2, 3])
        self.assertEqual([b["priority_rank"] for b in result["briefs"]], [1, 2, 3])

    # ---- 10: no priority file -> parser-native order preserved ------------
    def test_no_priority_json_preserves_parser_order(self):
        self._three_cluster_report()
        result = W3.process_workspace(
            workspace=self.tmp, cluster_name=None,
            out_dir=self.tmp / "hacker_briefs", fmt="markdown",
            process_all=True, allow_blocked=False, priority_json=None,
        )
        self.assertTrue(result["ok"])
        self.assertFalse(result["priority_applied"])
        order = [b["cluster_name"] for b in result["briefs"]]
        self.assertEqual(
            order,
            ["low-priority-class", "mid-priority-class", "top-priority-class"],
        )
        self.assertTrue(all(b["priority_rank"] is None for b in result["briefs"]))

    # ---- 11: auto-detect <ws>/bug_class_priority.json ---------------------
    def test_default_priority_file_auto_detected(self):
        self._three_cluster_report()
        # write the default-named file; do NOT pass priority_json explicitly.
        _make_priority_envelope(
            self.tmp,
            ["top-priority-class", "mid-priority-class", "low-priority-class"],
        )
        result = W3.process_workspace(
            workspace=self.tmp, cluster_name=None,
            out_dir=self.tmp / "hacker_briefs", fmt="markdown",
            process_all=True, allow_blocked=False, priority_json=None,
        )
        self.assertTrue(result["priority_applied"])
        order = [b["cluster_name"] for b in result["briefs"]]
        self.assertEqual(order[0], "top-priority-class")

    # ---- 12: unmatched clusters sort after ranked ones, stably -----------
    def test_unmatched_clusters_sort_last_stably(self):
        self._three_cluster_report()
        # prioritizer only ranks one class; the other two are unmatched.
        prio = _make_priority_envelope(self.tmp, ["top-priority-class"])
        result = W3.process_workspace(
            workspace=self.tmp, cluster_name=None,
            out_dir=self.tmp / "hacker_briefs", fmt="markdown",
            process_all=True, allow_blocked=False, priority_json=prio,
        )
        order = [b["cluster_name"] for b in result["briefs"]]
        # ranked cluster first; unmatched two keep parser-native relative order.
        self.assertEqual(order[0], "top-priority-class")
        self.assertEqual(order[1:], ["low-priority-class", "mid-priority-class"])

    # ---- 13: malformed priority file degrades gracefully ------------------
    def test_malformed_priority_json_falls_back(self):
        self._three_cluster_report()
        bad = self.tmp / "bad_priority.json"
        bad.write_text("{ not valid json", encoding="utf-8")
        result = W3.process_workspace(
            workspace=self.tmp, cluster_name=None,
            out_dir=self.tmp / "hacker_briefs", fmt="markdown",
            process_all=True, allow_blocked=False, priority_json=bad,
        )
        self.assertTrue(result["ok"])
        self.assertFalse(result["priority_applied"])
        order = [b["cluster_name"] for b in result["briefs"]]
        self.assertEqual(
            order,
            ["low-priority-class", "mid-priority-class", "top-priority-class"],
        )

    # ---- 14: cluster matches via detector_id when name differs -----------
    def test_priority_match_via_detector_id(self):
        # cluster name and detector id differ; prioritizer ranks the detector.
        _make_engage_report(
            self.tmp,
            [
                {"name": "cluster-alpha", "hits": [
                    {"severity": "LOW", "detector": "boring-class",
                     "file_path": "/x/A.sol", "line": 1}]},
                {"name": "cluster-beta", "hits": [
                    {"severity": "HIGH", "detector": "reentrancy",
                     "file_path": "/x/B.sol", "line": 2}]},
            ],
        )
        prio = _make_priority_envelope(self.tmp, ["reentrancy", "boring-class"])
        result = W3.process_workspace(
            workspace=self.tmp, cluster_name=None,
            out_dir=self.tmp / "hacker_briefs", fmt="markdown",
            process_all=True, allow_blocked=False, priority_json=prio,
        )
        order = [b["cluster_name"] for b in result["briefs"]]
        # cluster-beta ranks first because its detector_id `reentrancy` is rank 1.
        self.assertEqual(order, ["cluster-beta", "cluster-alpha"])

    # ---- 15: helper unit tests -------------------------------------------
    def test_load_priority_ranking_helper(self):
        prio = _make_priority_envelope(self.tmp, ["c-one", "c-two"])
        ranking = W3.load_priority_ranking(prio)
        self.assertEqual(ranking, {"c-one": 1, "c-two": 2})
        # missing file -> empty map.
        self.assertEqual(
            W3.load_priority_ranking(self.tmp / "nope.json"), {}
        )

    def test_order_clusters_by_priority_is_stable_when_empty(self):
        clusters = [{"cluster_name": "x"}, {"cluster_name": "y"}]
        self.assertEqual(
            W3.order_clusters_by_priority(clusters, {}), clusters
        )


if __name__ == "__main__":
    unittest.main()
