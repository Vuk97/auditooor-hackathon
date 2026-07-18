from __future__ import annotations

import argparse
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "audit-hacker-logic-bridge.py"
PROOF_QUEUE_TOOL = ROOT / "tools" / "proof-obligation-queue.py"


def _load_tool():
    spec = importlib.util.spec_from_file_location("audit_hacker_logic_bridge", TOOL)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _load_proof_queue_tool():
    spec = importlib.util.spec_from_file_location("proof_obligation_queue", PROOF_QUEUE_TOOL)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _write_json(path: Path, payload: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


class AuditHackerLogicBridgeTests(unittest.TestCase):
    def test_dydx_priority_selector_ranks_production_paths_above_generic_panic_hits(self) -> None:
        tool = _load_tool()
        hits = [
            {
                "detector_slug": "go.generic.panic",
                "hit": {
                    "severity": "HIGH",
                    "file_path": "protocol/app/app.go:44",
                    "snippet": "panic on generic app wiring helper",
                },
            },
            {
                "detector_slug": "go.clob.accounting",
                "hit": {
                    "severity": "HIGH",
                    "file_path": "protocol/x/clob/keeper/match.go:88",
                    "snippet": "insurance fund module account transfer before liquidation failure",
                },
            },
            {
                "detector_slug": "go.subaccounts.permission",
                "hit": {
                    "severity": "MEDIUM",
                    "file_path": "protocol/x/subaccounts/keeper/msg_server.go:75",
                    "snippet": "withdraw permission bypass on subaccount module account",
                },
            },
            {
                "detector_slug": "go.perpetuals.oracle",
                "hit": {
                    "severity": "MEDIUM",
                    "file_path": "protocol/x/perpetuals/keeper/funding.go:91",
                    "snippet": "oracle price update controls funding payment",
                },
            },
            {
                "detector_slug": "go.vault.accounting",
                "hit": {
                    "severity": "MEDIUM",
                    "file_path": "protocol/x/vault/keeper/withdraw.go:19",
                    "snippet": "vault withdraw updates module account balances",
                },
            },
            {
                "detector_slug": "go.affiliates.rewards",
                "hit": {
                    "severity": "LOW",
                    "file_path": "protocol/x/affiliates/keeper/rewards.go:22",
                    "snippet": "permissioned reward accounting path",
                },
            },
            {
                "detector_slug": "go.slinky.vote-extension",
                "hit": {
                    "severity": "LOW",
                    "file_path": "protocol/daemons/slinky/abci/ve/handler.go:42",
                    "snippet": "ExtendVote price oracle path",
                },
            },
            {
                "detector_slug": "go.iavl.apphash",
                "hit": {
                    "severity": "LOW",
                    "file_path": "external/iavl/nodedb.go:625",
                    "snippet": "IAVL AppHash persistence path",
                },
            },
            {
                "detector_slug": "go.abci.prepareproposal",
                "hit": {
                    "severity": "LOW",
                    "file_path": "protocol/app/abci.go:120",
                    "snippet": "PrepareProposal consensus path",
                },
            },
            {
                "detector_slug": "go.cli.support",
                "hit": {
                    "severity": "HIGH",
                    "file_path": "protocol/cmd/dydxprotocold/root.go:12",
                    "snippet": "panic in CLI support path",
                },
            },
        ]
        args = argparse.Namespace(
            hit_index=None,
            max_hits=8,
            priority_mode="dydx",
            target_repo="dydxprotocol/v4-chain",
            engage_report="",
        )

        selected, mode, rows = tool._select_hit_indexes(hits, args=args, workspace=Path("/tmp/dydx"))

        self.assertEqual(mode, "dydx")
        self.assertEqual(selected, [1, 2, 3, 4, 6, 7, 5, 8])
        self.assertNotIn(0, selected)
        self.assertNotIn(9, selected)
        scores = {int(row["hit_index"]): int(row["priority_score"]) for row in rows}
        app_score = tool._dydx_priority(hits[0])["score"]
        cli_score = tool._dydx_priority(hits[9])["score"]
        self.assertTrue(all(score > app_score for score in scores.values()))
        self.assertTrue(all(score > cli_score for score in scores.values()))

    def test_two_engage_hits_emit_two_graphs_and_one_proof_queue(self) -> None:
        tool = _load_tool()
        with tempfile.TemporaryDirectory(prefix="audit-hacker-bridge-") as tmp:
            ws = Path(tmp) / "ws"
            ws.mkdir()
            _write_json(
                ws / "engage_report.json",
                {
                    "schema": "auditooor.engage_report.sidecar.v1",
                    "clusters": [
                        {
                            "detector_slug": "reentrancy-no-guard",
                            "hit_count": 2,
                            "hits": [
                                {
                                    "severity": "HIGH",
                                    "file_path": "src/Vault.sol:42",
                                    "snippet": "first hit sends value before lock",
                                },
                                {
                                    "severity": "HIGH",
                                    "file_path": "src/Vault.sol:88",
                                    "snippet": "second hit calls hook before accounting",
                                },
                            ],
                        }
                    ],
                },
            )

            summary = tool.run(
                [
                    "--workspace",
                    str(ws),
                    "--repo-root",
                    str(ROOT),
                    "--max-hits",
                    "2",
                    "--max-tasks",
                    "20",
                    "--top-n",
                    "1",
                ]
            )

            self.assertEqual(summary["schema"], "auditooor.audit_hacker_logic_bridge.v1")
            self.assertEqual(summary["engage_hit_count"], 2)
            self.assertEqual(summary["graph_count"], 2)
            self.assertEqual(len(summary["graphs"]), 2)
            self.assertTrue((ws / ".auditooor" / "detector_action_graph.json").is_file())
            self.assertTrue((ws / ".auditooor" / "audit_hacker_logic_bridge.json").is_file())
            self.assertTrue((ws / ".auditooor" / "proof_obligation_queue.json").is_file())

            queue_payload = json.loads((ws / ".auditooor" / "proof_obligation_queue.json").read_text())
            self.assertEqual(queue_payload["summary"]["detector_action_graph_tasks"], 8)
            self.assertEqual(queue_payload["summary"]["task_count"], 8)
            self.assertEqual(summary["proof_queue_task_count"], 8)
            self.assertEqual(
                sorted(path.name for path in (ws / ".auditooor" / "detector_action_graphs").glob("*.json")),
                [
                    "hit_000_reentrancy-no-guard.json",
                    "hit_001_reentrancy-no-guard.json",
                ],
            )
            rendered = json.dumps(queue_payload, sort_keys=True)
            self.assertIn("src/Vault.sol:42", rendered)
            self.assertIn("src/Vault.sol:88", rendered)

            proof_queue = _load_proof_queue_tool()
            standalone_queue = proof_queue.run(
                ["--workspace", str(ws), "--generated-at", "2026-05-13T00:00:00Z"]
            )
            self.assertEqual(standalone_queue["summary"]["detector_action_graph_tasks"], 8)
            self.assertEqual(standalone_queue["summary"]["task_count"], 8)

    def test_single_hit_index_selects_second_hit(self) -> None:
        tool = _load_tool()
        with tempfile.TemporaryDirectory(prefix="audit-hacker-bridge-index-") as tmp:
            ws = Path(tmp) / "ws"
            ws.mkdir()
            _write_json(
                ws / "engage_report.json",
                {
                    "clusters": [
                        {
                            "detector_slug": "reentrancy-no-guard",
                            "hits": [
                                {"severity": "HIGH", "file_path": "src/Vault.sol:42", "snippet": "first hit"},
                                {"severity": "HIGH", "file_path": "src/Vault.sol:88", "snippet": "second hit"},
                            ],
                        }
                    ]
                },
            )

            summary = tool.run(
                [
                    "--workspace",
                    str(ws),
                    "--repo-root",
                    str(ROOT),
                    "--hit-index",
                    "1",
                    "--top-n",
                    "1",
                ]
            )

            self.assertEqual(summary["hit_indexes"], [1])
            self.assertEqual(summary["graph_count"], 1)
            graph = json.loads((ws / ".auditooor" / "detector_action_graph.json").read_text())
            self.assertEqual(graph["detector_hit"]["file_path"], "src/Vault.sol:88")

    def test_dydx_priority_mode_ranks_protocol_hits_before_generic_app_panic(self) -> None:
        tool = _load_tool()
        with tempfile.TemporaryDirectory(prefix="audit-hacker-bridge-dydx-") as tmp:
            ws = Path(tmp) / "dydx"
            ws.mkdir()
            _write_json(
                ws / "engage_report.json",
                {
                    "clusters": [
                        {
                            "detector_slug": "go.generic.panic",
                            "hits": [
                                {
                                    "severity": "HIGH",
                                    "file_path": "protocol/app/app.go:101",
                                    "snippet": "panic on generic app wiring helper",
                                },
                            ],
                        },
                        {
                            "detector_slug": "go.accounting.ordering",
                            "hits": [
                                {
                                    "severity": "MEDIUM",
                                    "file_path": "protocol/x/clob/keeper/match.go:88",
                                    "snippet": "insurance fund module account transfer before liquidation fill failure",
                                },
                            ],
                        },
                        {
                            "detector_slug": "go.oracle.vote_extension",
                            "hits": [
                                {
                                    "severity": "LOW",
                                    "file_path": "protocol/daemons/slinky/abci/ve/handler.go:42",
                                    "snippet": "ExtendVote price update path can skip oracle freshness handling",
                                },
                            ],
                        },
                    ]
                },
            )

            summary = tool.run(
                [
                    "--workspace",
                    str(ws),
                    "--repo-root",
                    str(ROOT),
                    "--max-hits",
                    "2",
                    "--max-tasks",
                    "20",
                    "--top-n",
                    "1",
                    "--target-repo",
                    "dydxprotocol/v4-chain",
                ]
            )

            self.assertEqual(summary["priority_mode"], "dydx")
            self.assertEqual(summary["language"], "go")
            self.assertEqual(summary["hit_indexes"], [1, 2])
            self.assertEqual(
                [row["file_path"] for row in summary["graphs"]],
                [
                    "protocol/x/clob/keeper/match.go:88",
                    "protocol/daemons/slinky/abci/ve/handler.go:42",
                ],
            )
            self.assertGreater(summary["graphs"][0]["priority_score"], summary["graphs"][1]["priority_score"])
            self.assertTrue(
                any("CLOB" in reason or "accounting" in reason for reason in summary["graphs"][0]["priority_reasons"])
            )
            graph = json.loads((ws / ".auditooor" / "detector_action_graph.json").read_text())
            self.assertEqual(graph["detector_hit"]["file_path"], "protocol/x/clob/keeper/match.go:88")
            self.assertEqual(
                sorted(path.name for path in (ws / ".auditooor" / "detector_action_graphs").glob("*.json")),
                [
                    "hit_001_go-accounting-ordering.json",
                    "hit_002_go-oracle-vote-extension.json",
                ],
            )

    def test_missing_engage_report_does_not_consume_stale_default_graph(self) -> None:
        tool = _load_tool()
        with tempfile.TemporaryDirectory(prefix="audit-hacker-bridge-empty-") as tmp:
            ws = Path(tmp) / "ws"
            ws.mkdir()
            _write_json(
                ws / ".auditooor" / "detector_action_graph.json",
                {
                    "schema": "auditooor.detector_hit_action_graph.v1",
                    "proof_obligations": [
                        {
                            "id": "STALE",
                            "kind": "source_confirmation",
                            "proof_needed": "stale proof should not be consumed",
                        }
                    ],
                },
            )

            summary = tool.run(["--workspace", str(ws), "--repo-root", str(ROOT), "--max-hits", "2"])

            self.assertEqual(summary["engage_hit_count"], 0)
            self.assertEqual(summary["graph_count"], 0)
            queue_payload = json.loads((ws / ".auditooor" / "proof_obligation_queue.json").read_text())
            self.assertEqual(queue_payload["summary"]["detector_action_graph_tasks"], 0)
            self.assertNotIn("STALE", json.dumps(queue_payload))

    def test_strict_mode_fails_when_no_proof_queue_tasks_are_created(self) -> None:
        with tempfile.TemporaryDirectory(prefix="audit-hacker-bridge-strict-empty-") as tmp:
            ws = Path(tmp) / "ws"
            ws.mkdir()
            proc = subprocess.run(
                [
                    sys.executable,
                    str(TOOL),
                    "--workspace",
                    str(ws),
                    "--repo-root",
                    str(ROOT),
                    "--max-hits",
                    "2",
                    "--strict",
                ],
                cwd=ROOT,
                capture_output=True,
                text=True,
                timeout=45,
                check=False,
            )

            self.assertNotEqual(proc.returncode, 0)
            self.assertIn("STRICT FAIL", proc.stderr)
            summary_path = ws / ".auditooor" / "audit_hacker_logic_bridge.json"
            self.assertTrue(summary_path.is_file())
            summary = json.loads(summary_path.read_text(encoding="utf-8"))
            self.assertTrue(summary["strict"])
            self.assertIn("proof queue contains no tasks", summary["strict_failures"])

    def test_strict_mode_passes_when_selected_hits_create_proof_tasks(self) -> None:
        tool = _load_tool()
        with tempfile.TemporaryDirectory(prefix="audit-hacker-bridge-strict-ready-") as tmp:
            ws = Path(tmp) / "ws"
            ws.mkdir()
            _write_json(
                ws / "engage_report.json",
                {
                    "clusters": [
                        {
                            "detector_slug": "reentrancy-no-guard",
                            "hits": [
                                {
                                    "severity": "HIGH",
                                    "file_path": "src/Vault.sol:42",
                                    "snippet": "sends value before accounting update",
                                }
                            ],
                        }
                    ]
                },
            )

            summary = tool.run(
                [
                    "--workspace",
                    str(ws),
                    "--repo-root",
                    str(ROOT),
                    "--max-hits",
                    "1",
                    "--top-n",
                    "1",
                    "--strict",
                ]
            )

            self.assertTrue(summary["strict"])
            self.assertEqual(summary["strict_failures"], [])
            self.assertEqual(summary["graph_count"], 1)
            self.assertGreater(summary["proof_queue_task_count"], 0)


if __name__ == "__main__":
    unittest.main()
