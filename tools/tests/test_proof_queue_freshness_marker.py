#!/usr/bin/env python3
"""Tests for tools/proof-queue-freshness-marker.py.

The marker is a control-plane freshness hint for make audit. It must be
hermetic, workspace-bounded, and advisory-only.
"""
from __future__ import annotations

import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]
TOOL_PATH = REPO / "tools" / "proof-queue-freshness-marker.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("proof_queue_freshness_marker", TOOL_PATH)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules["proof_queue_freshness_marker"] = mod
    spec.loader.exec_module(mod)
    return mod


MOD = _load_module()


def _workspace(root: Path) -> Path:
    ws = root / "ws"
    (ws / ".auditooor").mkdir(parents=True)
    return ws


def _write_queue(ws: Path, payload: dict[str, object] | str) -> Path:
    queue_path = ws / ".auditooor" / "proof_obligation_queue.json"
    if isinstance(payload, str):
        queue_path.write_text(payload, encoding="utf-8")
    else:
        queue_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return queue_path


def _write_source(ws: Path, rel: str = "src/Vault.sol") -> Path:
    path = ws / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("contract Vault {}\n", encoding="utf-8")
    return path


def _write_graph(ws: Path) -> Path:
    path = ws / ".auditooor" / "detector_action_graphs" / "hit_001.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("{}\n", encoding="utf-8")
    return path


def _fresh_queue_payload(
    *,
    advisory_only: bool = False,
    blocker: str = "",
    blockers: list[str] | None = None,
    source_refs: list[str] | None = None,
    workspace: str = "<workspace>",
    harness_evidence: dict[str, object] | None = None,
) -> dict[str, object]:
    refs = source_refs if source_refs is not None else [
        "<workspace>/src/Vault.sol",
        "<workspace>/.auditooor/detector_action_graphs/hit_001.json",
    ]
    task: dict[str, object] = {
        "task_id": "POQ-001",
        "proof_needed": "Run target harness and capture execution evidence",
        "source_refs": refs,
        "source_ref": refs[-1] if refs else "",
        "advisory_only": advisory_only,
        "harness_evidence": harness_evidence
        if harness_evidence is not None
        else {"command": "forge test --match-test testVaultProof", "status": "pass", "exit_code": 0},
    }
    if blocker:
        task["blocker"] = blocker
    if blockers is not None:
        task["blockers"] = blockers
    return {
        "schema": "auditooor.proof_obligation_queue.v1",
        "workspace": workspace,
        "advisory_only": True,
        "status": "ready",
        "blocked": False,
        "degraded": False,
        "summary": {"task_count": 1},
        "tasks": [task],
    }


class ProofQueueFreshnessMarkerTest(unittest.TestCase):
    def test_mark_stale_existing_queue_writes_json_and_markdown(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pq-freshness-") as tmp:
            ws = _workspace(Path(tmp))
            _write_queue(
                ws,
                {
                    "schema": "auditooor.proof_obligation_queue.v1",
                    "status": "ok",
                    "context_pack_id": "proof-queue:test",
                    "generated_at_utc": "2026-05-13T00:00:00Z",
                    "summary": {"task_count": 7},
                },
            )

            marker = MOD.run(
                [
                    "--workspace",
                    str(ws),
                    "--mode",
                    "mark-stale",
                    "--bridge-rc",
                    "2",
                    "--reason",
                    "bridge failed",
                    "--generated-at",
                    "2026-05-13T01:00:00Z",
                ]
            )

            self.assertEqual(marker["schema"], MOD.SCHEMA)
            self.assertEqual(marker["workspace"], "<workspace>")
            self.assertTrue(marker["advisory_only"])
            self.assertEqual(marker["status"], "stale_existing_proof_queue")
            self.assertFalse(marker["fresh"])
            self.assertTrue(marker["stale"])
            self.assertEqual(marker["bridge_rc"], 2)
            self.assertEqual(marker["reason"], "bridge failed")
            self.assertEqual(marker["proof_queue"]["path"], "<workspace>/.auditooor/proof_obligation_queue.json")
            self.assertTrue(marker["proof_queue"]["exists"])
            self.assertTrue(marker["proof_queue"]["json_valid"])
            self.assertEqual(marker["proof_queue"]["task_count"], 7)
            self.assertEqual(marker["proof_queue"]["context_pack_id"], "proof-queue:test")
            self.assertNotIn(str(ws), json.dumps(marker, sort_keys=True))

            json_path = ws / ".auditooor" / "proof_obligation_queue.freshness.json"
            md_path = ws / ".auditooor" / "proof_obligation_queue.freshness.md"
            self.assertTrue(json_path.is_file())
            self.assertTrue(md_path.is_file())
            self.assertEqual(json.loads(json_path.read_text(encoding="utf-8"))["status"], "stale_existing_proof_queue")
            self.assertIn("stale_existing_proof_queue", md_path.read_text(encoding="utf-8"))

    def test_mark_stale_without_queue_is_non_fresh_absence_marker(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pq-freshness-") as tmp:
            ws = _workspace(Path(tmp))
            marker = MOD.run(
                [
                    "--workspace",
                    str(ws),
                    "--mode",
                    "mark-stale",
                    "--reason",
                    "bridge failed before queue",
                ]
            )

            self.assertEqual(marker["status"], "no_existing_proof_queue")
            self.assertFalse(marker["fresh"])
            self.assertTrue(marker["stale"])
            self.assertIn("queue_missing", marker["non_fresh_reasons"])
            self.assertFalse(marker["proof_queue"]["exists"])
            self.assertFalse(marker["proof_queue"]["json_valid"])

    def test_invalid_existing_queue_is_still_marked_stale(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pq-freshness-") as tmp:
            ws = _workspace(Path(tmp))
            _write_queue(ws, "{not json")
            marker = MOD.run(["--workspace", str(ws), "--mode", "mark-stale"])

            self.assertEqual(marker["status"], "stale_existing_proof_queue")
            self.assertFalse(marker["fresh"])
            self.assertTrue(marker["stale"])
            self.assertIn("queue_json_invalid", marker["non_fresh_reasons"])
            self.assertTrue(marker["proof_queue"]["exists"])
            self.assertFalse(marker["proof_queue"]["json_valid"])

    def test_mark_fresh_overwrites_marker_after_success(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pq-freshness-") as tmp:
            ws = _workspace(Path(tmp))
            _write_source(ws)
            _write_graph(ws)
            _write_queue(ws, _fresh_queue_payload())
            MOD.run(["--workspace", str(ws), "--mode", "mark-stale", "--reason", "first"])

            marker = MOD.run(
                [
                    "--workspace",
                    str(ws),
                    "--mode",
                    "mark-fresh",
                    "--reason",
                    "bridge completed",
                    "--bridge-rc",
                    "0",
                ]
            )

            self.assertEqual(marker["status"], "fresh_bridge_completed")
            self.assertTrue(marker["fresh"])
            self.assertFalse(marker["stale"])
            self.assertEqual(marker["non_fresh_reasons"], [])
            self.assertTrue(marker["freshness"]["task_results"][0]["fresh"])
            self.assertEqual(marker["reason"], "bridge completed")
            stored = json.loads((ws / ".auditooor" / "proof_obligation_queue.freshness.json").read_text())
            self.assertEqual(stored["status"], "fresh_bridge_completed")
            self.assertTrue(stored["fresh"])
            self.assertFalse(stored["stale"])

    def test_mark_fresh_rejects_stale_workspace_source_ref(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pq-freshness-") as tmp:
            ws = _workspace(Path(tmp))
            source = _write_source(ws)
            _write_graph(ws)
            queue_path = _write_queue(ws, _fresh_queue_payload())
            newer = queue_path.stat().st_mtime + 10
            os.utime(source, (newer, newer))

            marker = MOD.run(["--workspace", str(ws), "--mode", "mark-fresh"])

            self.assertEqual(marker["status"], "non_fresh_proof_queue")
            self.assertFalse(marker["fresh"])
            self.assertTrue(marker["stale"])
            self.assertIn("source_ref_newer_than_queue", marker["non_fresh_reasons"])

    def test_mark_fresh_rejects_missing_source_refs(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pq-freshness-") as tmp:
            ws = _workspace(Path(tmp))
            _write_queue(ws, _fresh_queue_payload(source_refs=[]))

            marker = MOD.run(["--workspace", str(ws), "--mode", "mark-fresh"])

            self.assertEqual(marker["status"], "non_fresh_proof_queue")
            self.assertIn("task_missing_source_refs", marker["non_fresh_reasons"])
            self.assertFalse(marker["freshness"]["task_results"][0]["fresh"])

    def test_mark_fresh_rejects_advisory_only_entry(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pq-freshness-") as tmp:
            ws = _workspace(Path(tmp))
            _write_source(ws)
            _write_graph(ws)
            _write_queue(ws, _fresh_queue_payload(advisory_only=True))

            marker = MOD.run(["--workspace", str(ws), "--mode", "mark-fresh"])

            self.assertEqual(marker["status"], "non_fresh_proof_queue")
            self.assertIn("task_advisory_only", marker["non_fresh_reasons"])

    def test_mark_fresh_requires_concrete_proof_or_harness_evidence(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pq-freshness-") as tmp:
            ws = _workspace(Path(tmp))
            _write_source(ws)
            _write_graph(ws)
            _write_queue(ws, _fresh_queue_payload(harness_evidence={}))

            marker = MOD.run(["--workspace", str(ws), "--mode", "mark-fresh"])

            self.assertEqual(marker["status"], "non_fresh_proof_queue")
            self.assertIn(
                "task_missing_concrete_proof_or_harness_evidence",
                marker["non_fresh_reasons"],
            )

    def test_mark_fresh_rejects_workspace_mismatched_queue(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pq-freshness-") as tmp:
            ws = _workspace(Path(tmp))
            _write_source(ws)
            _write_graph(ws)
            _write_queue(ws, _fresh_queue_payload(workspace=str(Path(tmp) / "other-ws")))

            marker = MOD.run(["--workspace", str(ws), "--mode", "mark-fresh"])

            self.assertEqual(marker["status"], "non_fresh_proof_queue")
            self.assertIn("queue_workspace_mismatch", marker["non_fresh_reasons"])

    def test_mark_fresh_propagates_blockers(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pq-freshness-") as tmp:
            ws = _workspace(Path(tmp))
            _write_source(ws)
            _write_graph(ws)
            _write_queue(
                ws,
                _fresh_queue_payload(
                    blocker="missing execution manifest",
                    blockers=["manual replay still pending"],
                ),
            )

            marker = MOD.run(["--workspace", str(ws), "--mode", "mark-fresh"])

            self.assertEqual(marker["status"], "non_fresh_proof_queue")
            self.assertIn("task_has_blockers", marker["non_fresh_reasons"])
            result = marker["freshness"]["task_results"][0]
            self.assertIn("missing execution manifest", result["blockers"])
            self.assertIn("manual replay still pending", result["blockers"])

    def test_path_escape_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory(prefix="pq-freshness-") as tmp:
            root = Path(tmp)
            ws = _workspace(root)
            outside = root / "outside.json"

            with self.assertRaises(ValueError):
                MOD.run(
                    [
                        "--workspace",
                        str(ws),
                        "--mode",
                        "mark-stale",
                        "--proof-queue",
                        str(outside),
                    ]
                )


if __name__ == "__main__":
    unittest.main()
