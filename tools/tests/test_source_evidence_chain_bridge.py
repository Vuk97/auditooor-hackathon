"""HACKERMAN_V3 Lane D1 - source-evidence chain bridge tests."""
from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
BRIDGE_TOOL = ROOT / "tools" / "source-evidence-chain-bridge.py"
PLANNER_TOOL = ROOT / "tools" / "chained-attack-planner.py"


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _anchored_artifact(
    ws: Path,
    lead_id: str,
    *,
    rel_file: str,
    line: int,
    produces: list[str],
    requires: list[str],
) -> dict:
    """A source-mined artifact with an exact source anchor (path+line+excerpt)."""
    return {
        "schema": "auditooor.exploit_queue_source_artifact.v1",
        "lead_id": lead_id,
        "row_title": f"{lead_id} state",
        "source_refs": [
            {
                "path": str(ws / rel_file),
                "line_start": line,
                "line_end": line + 4,
                "excerpt": f"// {lead_id} source-cited code at {rel_file}:{line}",
            }
        ],
        "state_evidence": {
            "lead_id": lead_id,
            "role": "producer" if produces and not requires else "consumer",
            "produces_state": produces,
            "requires_state": requires,
            "bridge_claims": [],
        },
    }


class SourceEvidenceChainBridgeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.bridge = _load(BRIDGE_TOOL, "_source_evidence_chain_bridge")
        self.planner = _load(PLANNER_TOOL, "_chained_attack_planner")
        self.tmp = tempfile.TemporaryDirectory(prefix="source-evidence-chain-bridge-")
        self.ws = Path(self.tmp.name)
        self.artifact_dir = self.ws / ".auditooor" / "source_artifacts"
        self.artifact_dir.mkdir(parents=True)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_matching_produces_requires_state_mints_live_bridge(self) -> None:
        # D1: hit A confirms produces state X, hit B confirms requires state X.
        producer = _anchored_artifact(
            self.ws,
            "EQ-A",
            rel_file="src/Vault.sol",
            line=10,
            produces=["vault_locked_balance"],
            requires=[],
        )
        consumer = _anchored_artifact(
            self.ws,
            "EQ-B",
            rel_file="src/Router.sol",
            line=44,
            produces=[],
            requires=["vault_locked_balance"],
        )
        _write_json(self.artifact_dir / "EQ-A.source_artifact.json", producer)
        _write_json(self.artifact_dir / "EQ-B.source_artifact.json", consumer)

        summary = self.bridge.run(["--workspace", str(self.ws)])

        self.assertEqual(summary["bridge_rows_emitted"], 1)
        self.assertTrue(summary["metadata_overlap_only_unproven_promoted"])
        bridge = summary["bridges"][0]
        self.assertEqual(bridge["token"], "vault_locked_balance")
        self.assertEqual(bridge["producer_lead_id"], "EQ-A")
        self.assertEqual(bridge["consumer_lead_id"], "EQ-B")
        self.assertTrue(bridge["bridge_id"].startswith("LIVE-"))

        # Identical LIVE-<id> claim is written into BOTH artifacts on disk.
        a = json.loads((self.artifact_dir / "EQ-A.source_artifact.json").read_text())
        b = json.loads((self.artifact_dir / "EQ-B.source_artifact.json").read_text())
        a_claims = a["state_evidence"]["bridge_claims"]
        b_claims = b["state_evidence"]["bridge_claims"]
        self.assertEqual(len(a_claims), 1)
        self.assertEqual(len(b_claims), 1)
        self.assertEqual(a_claims[0]["bridge_id"], b_claims[0]["bridge_id"])
        self.assertEqual(a_claims[0]["bridge_id"], bridge["bridge_id"])

    def test_bridged_artifacts_leave_metadata_overlap_only_unproven(self) -> None:
        # D1 end-to-end: after the bridge runs, the planner promotes the chain
        # past metadata_overlap_only_unproven via the shared LIVE-<id> row.
        producer = _anchored_artifact(
            self.ws,
            "EQ-A",
            rel_file="src/Vault.sol",
            line=10,
            produces=["vault_locked_balance"],
            requires=[],
        )
        consumer = _anchored_artifact(
            self.ws,
            "EQ-B",
            rel_file="src/Router.sol",
            line=44,
            produces=[],
            requires=["vault_locked_balance"],
        )
        _write_json(self.artifact_dir / "EQ-A.source_artifact.json", producer)
        _write_json(self.artifact_dir / "EQ-B.source_artifact.json", consumer)

        # Before the bridge: artifacts carry empty bridge_claims, so they share
        # no chain-forming overlap and the planner emits no chain plan at all.
        before = self.planner.run(["--workspace", str(self.ws)])
        self.assertEqual(before["summary"]["plan_count"], 0)

        # Run the D1 bridge, then re-plan.
        self.bridge.run(["--workspace", str(self.ws)])
        after = self.planner.run(["--workspace", str(self.ws)])

        self.assertEqual(after["summary"]["plan_count"], 1)
        plan = after["plans"][0]
        self.assertFalse(plan["metadata_overlap_only"])
        self.assertEqual(plan["causal_evidence_level"], "distinct_bridge_signal_present")
        self.assertTrue(plan["causal_bridge_signals"])
        self.assertTrue(plan["paired_live_row_ids"])

    def test_metadata_only_artifacts_stay_unproven(self) -> None:
        # D1 negative case: artifacts with NO exact source anchor carry only
        # metadata - no bridge is minted, the chain stays unproven.
        producer = {
            "schema": "auditooor.exploit_queue_source_artifact.v1",
            "lead_id": "EQ-A",
            "row_title": "EQ-A metadata only",
            "source_refs": [{"path": str(self.ws / "src/Vault.sol")}],  # no line/excerpt
            "state_evidence": {
                "lead_id": "EQ-A",
                "role": "producer",
                "produces_state": ["vault_locked_balance"],
                "requires_state": [],
                "bridge_claims": [],
            },
        }
        consumer = {
            "schema": "auditooor.exploit_queue_source_artifact.v1",
            "lead_id": "EQ-B",
            "row_title": "EQ-B metadata only",
            "source_refs": [{"path": str(self.ws / "src/Router.sol")}],
            "state_evidence": {
                "lead_id": "EQ-B",
                "role": "consumer",
                "produces_state": [],
                "requires_state": ["vault_locked_balance"],
                "bridge_claims": [],
            },
        }
        _write_json(self.artifact_dir / "EQ-A.source_artifact.json", producer)
        _write_json(self.artifact_dir / "EQ-B.source_artifact.json", consumer)

        summary = self.bridge.run(["--workspace", str(self.ws)])

        self.assertEqual(summary["bridge_rows_emitted"], 0)
        self.assertFalse(summary["metadata_overlap_only_unproven_promoted"])
        # No bridge claim was written into either artifact.
        a = json.loads((self.artifact_dir / "EQ-A.source_artifact.json").read_text())
        self.assertEqual(a["state_evidence"]["bridge_claims"], [])

    def test_no_shared_state_token_emits_no_bridge(self) -> None:
        # D1: matching the right token matters - disjoint produces/requires
        # state must not co-occurrence-match into a bridge.
        producer = _anchored_artifact(
            self.ws,
            "EQ-A",
            rel_file="src/Vault.sol",
            line=10,
            produces=["vault_locked_balance"],
            requires=[],
        )
        consumer = _anchored_artifact(
            self.ws,
            "EQ-B",
            rel_file="src/Router.sol",
            line=44,
            produces=[],
            requires=["oracle_price_staleness"],
        )
        _write_json(self.artifact_dir / "EQ-A.source_artifact.json", producer)
        _write_json(self.artifact_dir / "EQ-B.source_artifact.json", consumer)

        summary = self.bridge.run(["--workspace", str(self.ws)])
        self.assertEqual(summary["bridge_rows_emitted"], 0)

    def test_dry_run_does_not_write_back(self) -> None:
        producer = _anchored_artifact(
            self.ws, "EQ-A", rel_file="src/Vault.sol", line=10,
            produces=["vault_locked_balance"], requires=[],
        )
        consumer = _anchored_artifact(
            self.ws, "EQ-B", rel_file="src/Router.sol", line=44,
            produces=[], requires=["vault_locked_balance"],
        )
        _write_json(self.artifact_dir / "EQ-A.source_artifact.json", producer)
        _write_json(self.artifact_dir / "EQ-B.source_artifact.json", consumer)

        summary = self.bridge.run(["--workspace", str(self.ws), "--dry-run"])
        self.assertEqual(summary["bridge_rows_emitted"], 1)
        # Disk artifacts are untouched in dry-run mode.
        a = json.loads((self.artifact_dir / "EQ-A.source_artifact.json").read_text())
        self.assertEqual(a["state_evidence"]["bridge_claims"], [])


if __name__ == "__main__":
    unittest.main()
