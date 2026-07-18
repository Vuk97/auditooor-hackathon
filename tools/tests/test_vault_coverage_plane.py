#!/usr/bin/env python3
"""Regression coverage for vault_coverage_plane.

Purely additive callable that exposes a workspace's coverage substrate (the
(unit x frame) / completeness plane) from the EXISTING .auditooor/ artifacts,
mirroring how vault_capability_inventory exposes the capability inventory.
"""

from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "tools" / "vault-mcp-server.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("vault_mcp_server_coverage_plane", MODULE_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


vault_mcp_server = _load_module()


def _write_fixture_ws(root: Path) -> Path:
    """Create a workspace with a minimal but realistic .auditooor/ coverage set."""
    ws = root / "fixture_ws"
    aud = ws / ".auditooor"
    aud.mkdir(parents=True, exist_ok=True)

    completeness = {
        "schema": "auditooor.completeness_matrix.v1",
        "ws": str(ws),
        "verdict": "complete",
        "mechanism_axis": {
            "present": True,
            "cells": [
                {
                    "impact": "direct-theft",
                    "mechanism": "recipient-not-bound-to-debited-owner",
                    "detector": "recipient-binding-check",
                    "status": "enumerated-agent-cleared",
                    "open_findings": 0,
                },
                {
                    "impact": "griefing",
                    "mechanism": "unbounded-loop",
                    "detector": "loop-bound-check",
                    "status": "open",
                    "open_findings": 1,
                },
            ],
        },
        "assets": [
            {
                "asset_id": "src/contracts",
                "invariant_enumeration": {
                    "conservation": {"status": "enumerated", "source": "comprehension"},
                    "authorization": {"status": "not-enumerated"},
                },
                "functions": [
                    {
                        "function": "deposit",
                        "file": "src/contracts/Vault.sol",
                        "coverage_status": "covered",
                    },
                    {
                        "function": "adminOnly",
                        "file": "src/contracts/Vault.sol",
                        "coverage_status": "out-of-scope-fcc-filtered",
                    },
                ],
            }
        ],
    }
    (aud / "completeness_matrix.json").write_text(
        json.dumps(completeness), encoding="utf-8"
    )

    coverage_report = {
        "schema": "auditooor.workspace_coverage_report.v1",
        "coverage_basis": "source-unit",
        "function_denominator_status": "complete",
        "denominator_disclosure": {
            "total_units": 10,
            "covered_units": 9,
            "uncovered_units": 1,
        },
    }
    (aud / "coverage_report.json").write_text(
        json.dumps(coverage_report), encoding="utf-8"
    )

    amv = aud / "agent_mechanism_verdicts"
    amv.mkdir(parents=True, exist_ok=True)
    (amv / "perfn_batch_0000.json").write_text(
        json.dumps(
            [
                {
                    "schema": "auditooor.agent_mechanism_verdict.v1",
                    "impact": "arithmetic-precision-corruption",
                    "mechanism": "unchecked-subtraction-underflow",
                    "verdict": "cleared",
                    "source_refs": ["src/contracts/Vault.sol:202"],
                }
            ]
        ),
        encoding="utf-8",
    )

    (aud / "mechanism_dispositions.jsonl").write_text(
        json.dumps(
            {
                "schema": "auditooor.mechanism_disposition.v1",
                "mechanism": "reentrancy",
                "file": "Vault.sol",
                "line": "235",
                "verdict": "refuted: guarded value-moving sink",
            }
        )
        + "\n",
        encoding="utf-8",
    )
    return ws


class VaultCoveragePlaneTests(unittest.TestCase):
    def test_schema_registered_and_well_formed(self) -> None:
        names = {tool["name"] for tool in vault_mcp_server.TOOL_SCHEMAS}
        self.assertIn("vault_coverage_plane", names)
        schema = next(
            tool
            for tool in vault_mcp_server.TOOL_SCHEMAS
            if tool["name"] == "vault_coverage_plane"
        )
        self.assertEqual(
            vault_mcp_server.COVERAGE_PLANE_SCHEMA,
            "auditooor.vault_coverage_plane.v1",
        )
        self.assertIn(vault_mcp_server.COVERAGE_PLANE_SCHEMA, schema["description"])
        props = schema["inputSchema"]["properties"]
        self.assertIn("workspace_path", props)
        self.assertIn("filter", props)
        self.assertIn("status", props["filter"]["properties"])
        self.assertIn("frame", props["filter"]["properties"])
        self.assertIn("query", props["filter"]["properties"])
        self.assertIn("limit", props)
        self.assertEqual(schema["inputSchema"]["required"], ["workspace_path"])

    def test_returns_valid_v1_json_for_fixture_ws(self) -> None:
        with tempfile.TemporaryDirectory(prefix="vault-coverage-plane-") as td:
            root = Path(td)
            ws = _write_fixture_ws(root)
            query = vault_mcp_server.VaultQuery(root, repo_root=root)
            result = query.vault_coverage_plane(workspace_path=str(ws), limit=100)

        self.assertEqual(result["schema"], "auditooor.vault_coverage_plane.v1")
        self.assertEqual(result["kind"], "coverage_plane")
        self.assertTrue(result["advisory_only"])
        self.assertTrue(result["present"])
        # cells from all four artifacts are present.
        sources = {c["source_of_truth"] for c in result["cells"]}
        self.assertIn(".auditooor/completeness_matrix.json", sources)
        self.assertIn(".auditooor/mechanism_dispositions.jsonl", sources)
        self.assertTrue(
            any(s.startswith(".auditooor/agent_mechanism_verdicts/") for s in sources)
        )
        # normalized statuses only.
        allowed = {"covered", "open", "not-enumerated", "agent-cleared"}
        self.assertTrue(all(c["status"] in allowed for c in result["cells"]))
        # every cell carries a source_of_truth and a frame.
        for cell in result["cells"]:
            self.assertTrue(cell["source_of_truth"])
            self.assertTrue(cell["frame"])
        # coverage_report summary is surfaced.
        self.assertTrue(result["coverage_report"]["present"])
        self.assertEqual(result["coverage_report"]["total_units"], 10)
        self.assertEqual(result["coverage_report"]["covered_units"], 9)
        # summary by_status counts present.
        self.assertIn("by_status", result["summary"])
        self.assertGreater(result["summary"]["total_cells_available"], 0)

    def test_filters_status_frame_and_limit(self) -> None:
        with tempfile.TemporaryDirectory(prefix="vault-coverage-plane-f-") as td:
            root = Path(td)
            ws = _write_fixture_ws(root)
            query = vault_mcp_server.VaultQuery(root, repo_root=root)

            # status filter
            open_only = query.vault_coverage_plane(
                workspace_path=str(ws), status="open", limit=100
            )
            self.assertTrue(open_only["cells"])
            self.assertTrue(all(c["status"] == "open" for c in open_only["cells"]))

            # frame filter (function-coverage frame)
            fn_only = query.vault_coverage_plane(
                workspace_path=str(ws), frame="function-coverage", limit=100
            )
            self.assertTrue(fn_only["cells"])
            self.assertTrue(
                all("function-coverage" in c["frame"] for c in fn_only["cells"])
            )

            # free-text query filter
            reentrancy = query.vault_coverage_plane(
                workspace_path=str(ws), query="reentrancy", limit=100
            )
            self.assertTrue(reentrancy["cells"])
            self.assertTrue(
                all("reentrancy" in json.dumps(c).lower() for c in reentrancy["cells"])
            )

            # limit is enforced and capped.
            capped = query.vault_coverage_plane(workspace_path=str(ws), limit=1)
            self.assertEqual(len(capped["cells"]), 1)
            over = query.vault_coverage_plane(workspace_path=str(ws), limit=999999)
            self.assertEqual(over["inputs"]["limit"], 1500)

    def test_call_dispatch(self) -> None:
        with tempfile.TemporaryDirectory(prefix="vault-coverage-plane-d-") as td:
            root = Path(td)
            ws = _write_fixture_ws(root)
            query = vault_mcp_server.VaultQuery(root, repo_root=root)
            result = query.call(
                "vault_coverage_plane",
                {"workspace_path": str(ws), "filter": {"status": "covered"}, "limit": 5},
            )
        self.assertEqual(result["kind"], "coverage_plane")
        self.assertTrue(all(c["status"] == "covered" for c in result["cells"]))

    def test_empty_ws_degrades_gracefully(self) -> None:
        with tempfile.TemporaryDirectory(prefix="vault-coverage-plane-e-") as td:
            root = Path(td)
            query = vault_mcp_server.VaultQuery(root, repo_root=root)

            # non-existent workspace path: present=False, empty cells, no crash.
            missing = query.vault_coverage_plane(
                workspace_path=str(root / "does-not-exist")
            )
            self.assertFalse(missing["present"])
            self.assertEqual(missing["cells"], [])
            self.assertTrue(missing["degraded"])

            # workspace with no .auditooor/ dir: present=False, empty cells.
            empty_ws = root / "empty_ws"
            empty_ws.mkdir(parents=True, exist_ok=True)
            res = query.vault_coverage_plane(workspace_path=str(empty_ws))
            self.assertFalse(res["present"])
            self.assertEqual(res["cells"], [])
            self.assertTrue(res["degraded"])


if __name__ == "__main__":
    unittest.main()
