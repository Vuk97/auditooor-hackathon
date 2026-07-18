"""test_agent_brief_prefetch.py - unit tests for the META-1 prefetch CLI.

Covers:
  1. Lane-type validation (positive + negative cases for the six valid types).
  2. Severity-filter routing into MCP arg shape.
  3. Workspace-anchor injection forwarded to vault_lane_skeleton_filler.
  4. Missing-workspace fallback (workspace path that does not exist).
  5. MCP-callable unavailable -> graceful fallback message (no crash).
  6. Anchors scan (Section 15c) - empty when reports/ is empty.
  7. Anchors scan finds and ranks lane reports by mtime.
  8. Busywork defaults always render unless --no-busywork.
  9. Busywork extra file appended after defaults.
 10. End-to-end CLI smoke (dispatch / HIGH) emits BEGIN+END markers.
"""

from __future__ import annotations

import importlib.util
import json
import pathlib
import subprocess
import sys
import tempfile
import time
import unittest
from typing import Any, Dict, List, Optional, Tuple
from unittest.mock import patch

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
TOOL_PATH = REPO_ROOT / "tools" / "agent-brief-prefetch.py"


def _load_module():
    spec = importlib.util.spec_from_file_location(
        "agent_brief_prefetch", TOOL_PATH
    )
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Cannot load module at {TOOL_PATH}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules["agent_brief_prefetch"] = mod
    spec.loader.exec_module(mod)  # type: ignore[attr-defined]
    return mod


prefetch = _load_module()


# ---------------------------------------------------------------------------
# Fixture MCP payloads (so tests do not need a live vault).
# ---------------------------------------------------------------------------

def _fake_digest_payload(must_address: List[str]) -> Dict[str, Any]:
    return {
        "context_pack_id": "fake:digest:abc123",
        "digest": [
            {
                "rule_id": rid,
                "name": f"{rid} test rule",
                "override_marker": f"<!-- {rid.lower()}-rebuttal: ... -->",
            }
            for rid in must_address
        ],
        "lane_specific_must_address": must_address,
        "routine_violation_warnings": [
            {"rule_id": "R42", "one_line_remediation": "trace it"},
            {"rule_id": "R29", "one_line_remediation": "tabulate it"},
        ],
    }


def _fake_skeleton_payload(
    applicable: List[str],
    skeletons: Dict[str, str],
) -> Dict[str, Any]:
    return {
        "context_pack_id": "fake:skeleton:def456",
        "applicable_rules": applicable,
        "skeleton_sections": skeletons,
        "placeholders_to_resolve": {
            rid: ["placeholder_a", "placeholder_b"] for rid in skeletons
        },
        "workspace_anchors": {},
        "usage_note": "fill the placeholders in",
    }


def _patch_call_mcp(routes: Dict[str, Optional[Dict[str, Any]]]):
    """Patch prefetch._call_mcp to return routes[call_name]."""

    def _stub(call: str, args: Dict[str, Any], **kwargs):
        return routes.get(call, None)

    return patch.object(prefetch, "_call_mcp", side_effect=_stub)


# ---------------------------------------------------------------------------
# Test cases
# ---------------------------------------------------------------------------

class LaneTypeValidationTests(unittest.TestCase):

    def test_valid_lane_types_all_six(self):
        """All six lane types from _lane_rule_map.json must validate."""
        routes = {
            "vault_codified_rules_digest": _fake_digest_payload(["R28"]),
            "vault_lane_skeleton_filler": _fake_skeleton_payload([], {}),
        }
        with _patch_call_mcp(routes):
            for lane in prefetch.VALID_LANE_TYPES:
                text, meta = prefetch.build_prefetch_block(
                    lane_type=lane,
                    severity="HIGH",
                    workspace=None,
                    include_anchors=False,
                    include_busywork=False,
                )
                self.assertIn("BEGIN agent-brief-prefetch", text)
                self.assertEqual(meta["lane_type"], lane)

    def test_invalid_lane_type_raises(self):
        """Unknown lane types must ValueError before any MCP call."""
        with self.assertRaises(ValueError) as cm:
            prefetch.build_prefetch_block(
                lane_type="bogus",
                severity="HIGH",
                workspace=None,
            )
        self.assertIn("invalid lane_type", str(cm.exception))


class SeverityRoutingTests(unittest.TestCase):

    def test_severity_propagates_into_mcp_args(self):
        """Severity must reach both MCP callables in their args dict."""
        seen_args: List[Tuple[str, Dict[str, Any]]] = []

        def _stub(call: str, args: Dict[str, Any], **kwargs):
            seen_args.append((call, dict(args)))
            if call == "vault_codified_rules_digest":
                return _fake_digest_payload(["R28"])
            return _fake_skeleton_payload([], {})

        with patch.object(prefetch, "_call_mcp", side_effect=_stub):
            prefetch.build_prefetch_block(
                lane_type="dispute",
                severity="CRITICAL",
                workspace=None,
                include_anchors=False,
                include_busywork=False,
            )
        # Both callables saw severity=CRITICAL
        sev_seen = {call: a.get("severity") for call, a in seen_args}
        self.assertEqual(sev_seen["vault_codified_rules_digest"], "CRITICAL")
        self.assertEqual(sev_seen["vault_lane_skeleton_filler"], "CRITICAL")


class WorkspaceAnchorTests(unittest.TestCase):

    def test_target_finding_class_forwarded_to_skeleton_filler(self):
        """--target-finding-class must reach vault_lane_skeleton_filler."""
        seen: Dict[str, Any] = {}

        def _stub(call: str, args: Dict[str, Any], **kwargs):
            if call == "vault_lane_skeleton_filler":
                seen.update(args)
                return _fake_skeleton_payload([], {})
            return _fake_digest_payload(["R28"])

        with patch.object(prefetch, "_call_mcp", side_effect=_stub):
            prefetch.build_prefetch_block(
                lane_type="filing",
                severity="HIGH",
                workspace=None,
                target_finding_class="bridge_proof_consume_once",
                include_anchors=False,
                include_busywork=False,
            )
        self.assertEqual(
            seen.get("target_finding_class"), "bridge_proof_consume_once"
        )


class MissingWorkspaceFallbackTests(unittest.TestCase):

    def test_workspace_nonexistent_path_falls_back_to_repo(self):
        """A CLI workspace path that doesn't exist falls back to REPO root."""
        with _patch_call_mcp(
            {
                "vault_codified_rules_digest": _fake_digest_payload(["R28"]),
                "vault_lane_skeleton_filler": _fake_skeleton_payload([], {}),
            }
        ):
            rc = prefetch.main(
                [
                    "--lane-type",
                    "dispute",
                    "--severity",
                    "HIGH",
                    "--workspace",
                    "/definitely/does/not/exist/abc123",
                    "--no-anchors",
                    "--no-busywork",
                    "--quiet",
                ]
            )
        self.assertEqual(rc, 0)


class MCPUnavailableFallbackTests(unittest.TestCase):

    def test_both_callables_unavailable_no_crash(self):
        """If both MCP callables return None, the block still renders."""
        with _patch_call_mcp(
            {
                "vault_codified_rules_digest": None,
                "vault_lane_skeleton_filler": None,
            }
        ):
            text, meta = prefetch.build_prefetch_block(
                lane_type="dispute",
                severity="HIGH",
                workspace=None,
                include_anchors=False,
                include_busywork=False,
            )
        self.assertIn("BEGIN agent-brief-prefetch", text)
        self.assertIn("vault_codified_rules_digest unavailable", text)
        self.assertIn("vault_lane_skeleton_filler unavailable", text)
        self.assertTrue(meta["sec15a"]["mcp_unavailable"])
        self.assertTrue(meta["sec15b"]["mcp_unavailable"])


class AnchorsScanTests(unittest.TestCase):

    def test_anchors_empty_when_reports_dir_missing(self):
        """No reports/ dir -> friendly empty message."""
        with tempfile.TemporaryDirectory() as td:
            fake_repo = pathlib.Path(td)
            with patch.object(prefetch, "REPO", fake_repo):
                text, meta = prefetch._build_sec15c_empirical_anchors(
                    fake_repo, limit=5
                )
        self.assertIn("no recent lane reports", text)
        self.assertEqual(meta["items_count"], 0)

    def test_anchors_finds_lane_reports_by_mtime(self):
        """Anchors section ranks reports by mtime descending."""
        with tempfile.TemporaryDirectory() as td:
            fake_repo = pathlib.Path(td)
            iter_dir = fake_repo / "reports" / "v3_iter_2026-05-23_iter99"
            (iter_dir / "lane_AAA").mkdir(parents=True, exist_ok=True)
            (iter_dir / "lane_BBB").mkdir(parents=True, exist_ok=True)
            older = iter_dir / "lane_AAA" / "results.md"
            newer = iter_dir / "lane_BBB" / "results.md"
            older.write_text(
                "# Lane AAA - older\n\n## Bottom-line verdict\nfoo\n",
                encoding="utf-8",
            )
            time.sleep(0.05)
            newer.write_text(
                "# Lane BBB - newer\n\n## Bottom-line verdict\nbar\n",
                encoding="utf-8",
            )
            with patch.object(prefetch, "REPO", fake_repo):
                text, meta = prefetch._build_sec15c_empirical_anchors(
                    fake_repo, limit=5
                )
        self.assertEqual(meta["items_count"], 2)
        # newer first
        self.assertEqual(meta["items"][0]["title"], "Lane BBB - newer")
        self.assertEqual(meta["items"][1]["title"], "Lane AAA - older")
        self.assertIn("Lane BBB", text)


class BusyworkTests(unittest.TestCase):

    def test_defaults_always_rendered(self):
        """Every default busywork row must appear in the rendered block."""
        text, meta = prefetch._build_sec15d_busywork()
        self.assertEqual(meta["default_count"], len(prefetch.BUSYWORK_DEFAULTS))
        self.assertEqual(meta["extra_count"], 0)
        for pattern, _reason in prefetch.BUSYWORK_DEFAULTS:
            self.assertIn(pattern, text)

    def test_extra_file_appended(self):
        """--busywork-file rows append AFTER defaults."""
        with tempfile.TemporaryDirectory() as td:
            extra = pathlib.Path(td) / "extra.tsv"
            extra.write_text(
                "# comment\n"
                "Re-derive Sei block-import path\tcovered by Hyperbridge anchor\n"
                "Rerun forge fuzz iter9\tflakey-on-iter9-pinned-toolchain\n",
                encoding="utf-8",
            )
            extra_rows = prefetch._load_busywork_from_file(extra)
        self.assertEqual(len(extra_rows), 2)
        text, meta = prefetch._build_sec15d_busywork(extra_rows)
        self.assertEqual(meta["extra_count"], 2)
        self.assertIn("Re-derive Sei block-import path", text)
        self.assertIn("flakey-on-iter9-pinned-toolchain", text)

    def test_no_busywork_flag_omits_section(self):
        """--no-busywork must omit Section 15d entirely."""
        with _patch_call_mcp(
            {
                "vault_codified_rules_digest": _fake_digest_payload(["R28"]),
                "vault_lane_skeleton_filler": _fake_skeleton_payload([], {}),
            }
        ):
            text, _meta = prefetch.build_prefetch_block(
                lane_type="dispute",
                severity="HIGH",
                workspace=None,
                include_anchors=False,
                include_busywork=False,
            )
        self.assertNotIn("Section 15d", text)


class EndToEndCLISmokeTests(unittest.TestCase):

    def test_cli_dispute_high_emits_begin_end_markers(self):
        """Real subprocess invocation against live MCP must emit a valid block."""
        proc = subprocess.run(
            [
                sys.executable,
                str(TOOL_PATH),
                "--lane-type",
                "dispute",
                "--severity",
                "HIGH",
                "--workspace",
                str(REPO_ROOT),
                "--no-anchors",
                "--no-busywork",
                "--quiet",
            ],
            capture_output=True,
            text=True,
            timeout=60,
            cwd=str(REPO_ROOT),
        )
        self.assertEqual(proc.returncode, 0, msg=proc.stderr)
        self.assertIn("BEGIN agent-brief-prefetch", proc.stdout)
        self.assertIn("END agent-brief-prefetch", proc.stdout)
        # Either Section 15a renders rules OR an unavailability warning.
        self.assertIn("Section 15a", proc.stdout)
        self.assertIn("Section 15b", proc.stdout)


if __name__ == "__main__":
    unittest.main()
