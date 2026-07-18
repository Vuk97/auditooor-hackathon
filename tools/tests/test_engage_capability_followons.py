from __future__ import annotations

import importlib.util
import json
import stat
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
ENGAGE = ROOT / "tools" / "engage.py"


def _load_engage():
    import sys

    tools_dir = str(ROOT / "tools")
    if tools_dir not in sys.path:
        sys.path.insert(0, tools_dir)
    spec = importlib.util.spec_from_file_location("engage_capability_followons", ENGAGE)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _write_executable(path: Path, text: str) -> None:
    path.write_text(text, encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


class EngageCapabilityFollowOnTests(unittest.TestCase):
    def setUp(self) -> None:
        self.mod = _load_engage()
        self.args = types.SimpleNamespace(quiet=True)

    def test_scan_rust_runs_runtime_blockers_and_base_preflight_follow_ons(self) -> None:
        with tempfile.TemporaryDirectory(prefix="engage_followon_scan_rust_") as tmp:
            ws = Path(tmp)
            (ws / "Cargo.toml").write_text("[package]\nname='fixture'\nversion='0.1.0'\n", encoding="utf-8")
            (ws / "INTAKE_BASELINE.json").write_text(
                json.dumps(
                    {
                        "assets_in_scope": ["Smart Contract", "Blockchain/DLT"],
                        "rust_roots": ["."],
                        "summary": {"rust_scan_artifact_present": False},
                    }
                ),
                encoding="utf-8",
            )
            runner = ws / "fake-rust-scan-runner.sh"
            blockers = ws / "fake-rust-runtime-semantic-blockers.py"
            preflight = ws / "fake-base-scan-preflight.py"
            _write_executable(
                runner,
                "#!/usr/bin/env bash\n"
                "set -euo pipefail\n"
                "mkdir -p \"$1/scanners/rust\"\n"
                "printf '# summary\\n' > \"$1/scanners/rust/SCAN_RUST_SUMMARY.md\"\n"
                "printf '{\"roots\":[\".\"]}\\n' > \"$1/scanners/rust/SCAN_RUST_SUMMARY.json\"\n",
            )
            _write_executable(
                blockers,
                "#!/usr/bin/env python3\n"
                "import json, os, sys\n"
                "out = sys.argv[sys.argv.index('--out-json') + 1]\n"
                "os.makedirs(os.path.dirname(out), exist_ok=True)\n"
                "payload = {\n"
                "  'status': 'READY_WITH_P1',\n"
                "  'runtime_semantic_blocker_queue': [{'id': 'row-1'}],\n"
                "  'safe_detectorization_handoff': [{'id': 'handoff-1'}]\n"
                "}\n"
                "open(out, 'w', encoding='utf-8').write(json.dumps(payload))\n",
            )
            _write_executable(
                preflight,
                "#!/usr/bin/env python3\n"
                "import json, os, sys\n"
                "out = sys.argv[sys.argv.index('--out-json') + 1]\n"
                "os.makedirs(os.path.dirname(out), exist_ok=True)\n"
                "payload = {'status': 'PASS', 'can_start_base_scan': True}\n"
                "open(out, 'w', encoding='utf-8').write(json.dumps(payload))\n",
            )

            with mock.patch.object(self.mod, "RUST_SCAN_RUNNER", runner), \
                 mock.patch.object(self.mod, "RUST_RUNTIME_SEMANTIC_BLOCKERS", blockers), \
                 mock.patch.object(self.mod, "BASE_SCAN_PREFLIGHT", preflight):
                status = self.mod.stage_scan_rust(ws, self.args)

            self.assertEqual(status, "SUCCESS")
            self.assertTrue((ws / ".auditooor" / "rust_runtime_semantic_blockers.json").is_file())
            self.assertTrue((ws / ".auditooor" / "base_scan_preflight.json").is_file())

    def test_engage_report_sidecar_uses_public_workspace_label(self) -> None:
        with tempfile.TemporaryDirectory(prefix="engage_sidecar_") as tmp:
            ws = Path(tmp)
            hits = [
                {
                    "severity": "HIGH",
                    "detector": "detector-alpha",
                    "file": "src/Target.sol",
                    "line": 42,
                    "snippet": "issue in target",
                }
            ]
            enriched = [{"reverse": {}, "cross_ws": {}, "dupe": {"risk": "LOW"}}]
            sidecar = self.mod.build_report_sidecar(ws, hits, enriched, {"detector-alpha": [0]})

            self.assertEqual(sidecar["workspace"], ws.name)
            payload = json.dumps(sidecar, sort_keys=True)
            self.assertNotIn(str(ws), payload)
            self.assertEqual(sidecar["clusters"][0]["hits"][0]["file_path"], "src/Target.sol:42")

    def test_collect_hits_ingests_go_detector_findings(self) -> None:
        with tempfile.TemporaryDirectory(prefix="engage_go_findings_") as tmp:
            ws = Path(tmp)
            auditooor_dir = ws / ".auditooor"
            auditooor_dir.mkdir()
            (auditooor_dir / "go_findings.json").write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "patterns": {
                            "go.crypto.parse.negative_or_zero_int_unchecked": {
                                "id": "go.crypto.parse.negative_or_zero_int_unchecked",
                                "hits": [
                                    {
                                        "file": "external/v4-chain/protocol/x/vault/types/vault_id.go",
                                        "line": 46,
                                        "snippet": "number, err := strconv.ParseUint(split[1], 10, 32)",
                                        "extra": {"function": "GetVaultIdFromStateKey"},
                                    }
                                ],
                                "hit_count": 1,
                            }
                        },
                    }
                ),
                encoding="utf-8",
            )

            hits, dropped = self.mod.collect_hits(ws)

            self.assertEqual(dropped, 0)
            self.assertEqual(len(hits), 1)
            self.assertEqual(hits[0]["detector"], "go.crypto.parse.negative_or_zero_int_unchecked")
            self.assertEqual(hits[0]["severity"], "LOW")
            self.assertEqual(hits[0]["file"], "external/v4-chain/protocol/x/vault/types/vault_id.go")
            self.assertEqual(hits[0]["line"], "46")
            self.assertEqual(hits[0]["function"], "GetVaultIdFromStateKey")
            self.assertEqual(hits[0]["source"], "go")

    def test_collect_hits_ingests_workspace_go_findings_when_out_dir_differs(self) -> None:
        with tempfile.TemporaryDirectory(prefix="engage_go_findings_out_") as tmp:
            root = Path(tmp)
            ws = root / "ws"
            out_dir = root / "out"
            (ws / ".auditooor").mkdir(parents=True)
            out_dir.mkdir()
            (ws / ".auditooor" / "go_findings.json").write_text(
                json.dumps(
                    {
                        "patterns": {
                            "go.dydx.permissioned.subaccount_filter_gap": {
                                "id": "go.dydx.permissioned.subaccount_filter_gap",
                                "severity": "Critical",
                                "hits": [
                                    {
                                        "file": "protocol/x/accountplus/keeper/msg_server.go",
                                        "line": 142,
                                        "snippet": "check only validates sender account",
                                        "extra": {"function": "SendFromModuleToAccount"},
                                    }
                                ],
                            }
                        },
                    }
                ),
                encoding="utf-8",
            )

            hits, dropped = self.mod.collect_hits(out_dir, workspace=ws)

            self.assertEqual(dropped, 0)
            self.assertEqual(len(hits), 1)
            self.assertEqual(hits[0]["detector"], "go.dydx.permissioned.subaccount_filter_gap")
            self.assertEqual(hits[0]["severity"], "CRITICAL")
            self.assertEqual(hits[0]["function"], "SendFromModuleToAccount")
            self.assertEqual(hits[0]["source"], "go")

    def test_collect_hits_ingests_regex_detector_manifest(self) -> None:
        with tempfile.TemporaryDirectory(prefix="engage_regex_manifest_") as tmp:
            out_dir = Path(tmp)
            (out_dir / "regex_detectors_manifest.json").write_text(
                json.dumps(
                    {
                        "schema": "auditooor.regex_detectors_manifest.v1",
                        "findings": [
                            {
                                "detector": "v4-hook-take-before-pricing-state-mutation",
                                "severity": "High",
                                "file": "src/Hook.sol",
                                "line": 77,
                                "function": "beforeSwap",
                                "message": "hook mutates reserves before pricing",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )

            hits, dropped = self.mod.collect_hits(out_dir)

            self.assertEqual(dropped, 0)
            self.assertEqual(len(hits), 1)
            self.assertEqual(hits[0]["detector"], "v4-hook-take-before-pricing-state-mutation")
            self.assertEqual(hits[0]["severity"], "HIGH")
            self.assertEqual(hits[0]["file"], "src/Hook.sol")
            self.assertEqual(hits[0]["line"], "77")
            self.assertEqual(hits[0]["function"], "beforeSwap")
            self.assertEqual(hits[0]["source"], "regex")

    def test_engage_report_sidecar_sanitizes_absolute_hit_paths_and_snippets(self) -> None:
        with tempfile.TemporaryDirectory(prefix="engage_sidecar_privacy_") as tmp:
            ws = Path(tmp)
            hits = [
                {
                    "severity": "HIGH",
                    "detector": "detector-alpha",
                    "file": str(ws / "src" / "Vault.sol"),
                    "line": 42,
                    "snippet": f"touches {ws / 'src' / 'Vault.sol'} before transfer",
                },
                {
                    "severity": "MEDIUM",
                    "detector": "detector-alpha",
                    "file": "/Users/wolf/private-ws/contracts/Secret.sol",
                    "line": 7,
                    "snippet": "uses /Users/wolf/private-ws/contracts/Secret.sol before call",
                },
                {
                    "severity": "LOW",
                    "detector": "detector-alpha",
                    "file": "/private/var/folders/aa/bb/T/private-ws/contracts/Token.sol",
                    "line": 9,
                    "snippet": "loads /private/var/folders/aa/bb/T/private-ws/contracts/Token.sol and /tmp/secret.txt",
                },
                {
                    "severity": "LOW",
                    "detector": "detector-alpha",
                    "file": "/tmp/random/Outside.sol",
                    "line": 11,
                    "snippet": "hits /tmp/random/Outside.sol and /arbitrary/abs/path/Leak.sol",
                },
            ]
            enriched = [
                {"reverse": {}, "cross_ws": {}, "dupe": {"risk": "LOW"}}
                for _ in hits
            ]

            sidecar = self.mod.build_report_sidecar(ws, hits, enriched, {"detector-alpha": [0, 1, 2, 3]})
            cluster_hits = sidecar["clusters"][0]["hits"]
            payload = json.dumps(sidecar, sort_keys=True)

            self.assertEqual(cluster_hits[0]["file_path"], "src/Vault.sol:42")
            self.assertEqual(
                cluster_hits[0]["snippet"],
                f"touches workspace:{ws.name}/src/Vault.sol before transfer",
            )
            self.assertEqual(cluster_hits[1]["file_path"], "contracts/Secret.sol:7")
            self.assertEqual(cluster_hits[1]["snippet"], "uses [redacted-local-path] before call")
            self.assertEqual(cluster_hits[2]["file_path"], "contracts/Token.sol:9")
            self.assertEqual(
                cluster_hits[2]["snippet"],
                "loads [redacted-local-path] and [redacted-local-path]",
            )
            self.assertEqual(cluster_hits[3]["file_path"], "random/Outside.sol:11")
            self.assertEqual(
                cluster_hits[3]["snippet"],
                "hits [redacted-local-path] and [redacted-local-path]",
            )
            self.assertNotIn("/Users", payload)
            self.assertNotIn("/private/var", payload)
            self.assertNotIn("/tmp/", payload)
            self.assertNotIn("/arbitrary/abs/path", payload)
            self.assertNotIn(str(ws), payload)

    def test_agent_synthesize_materializes_recall_detector_queue(self) -> None:
        with tempfile.TemporaryDirectory(prefix="engage_followon_agent_") as tmp:
            ws = Path(tmp)
            agent_dir = ws / "agent_outputs"
            agent_dir.mkdir()
            (agent_dir / "dispatch_fixture.md").write_text("VERDICT: TP severity-HIGH\n", encoding="utf-8")
            synth = ws / "fake-agent-output-synthesizer.py"
            queue_tool = ws / "fake-agent-recall-detector-queue.py"
            _write_executable(
                synth,
                "#!/usr/bin/env python3\n"
                "import json, sys\n"
                "out = sys.argv[sys.argv.index('--out') + 1]\n"
                "if '--brief-candidates' in sys.argv:\n"
                "  payload = {'summary': {'candidate_count': 1, 'candidate_findings': 1, 'poc_plans': 0}}\n"
                "else:\n"
                "  payload = {'summary': {'verdict_count': 1}}\n"
                "open(out, 'w', encoding='utf-8').write(json.dumps(payload))\n",
            )
            _write_executable(
                queue_tool,
                "#!/usr/bin/env python3\n"
                "import json, os, sys\n"
                "ws = sys.argv[sys.argv.index('--workspace') + 1]\n"
                "out = sys.argv[sys.argv.index('--out-json') + 1]\n"
                "os.makedirs(os.path.dirname(out), exist_ok=True)\n"
                "payload = {'status': 'ok', 'summary': {'row_count': 2}}\n"
                "open(out, 'w', encoding='utf-8').write(json.dumps(payload))\n"
                "print(json.dumps(payload))\n",
            )

            with mock.patch.object(self.mod, "AGENT_OUTPUT_SYNTHESIZER", synth), \
                 mock.patch.object(self.mod, "AGENT_RECALL_DETECTOR_QUEUE", queue_tool):
                status = self.mod.stage_agent_synthesize(ws, self.args)

            self.assertEqual(status, "SUCCESS")
            queue = json.loads((ws / ".auditooor" / "agent_recall_detector_queue.json").read_text(encoding="utf-8"))
            self.assertEqual(queue["summary"]["row_count"], 2)

    def test_post_audit_review_runs_high_impact_execution_bridge_follow_on(self) -> None:
        with tempfile.TemporaryDirectory(prefix="engage_followon_closeout_") as tmp:
            ws = Path(tmp)
            (ws / "submissions").mkdir()
            (ws / "submissions" / "SUBMISSIONS.md").write_text("# Ledger\n", encoding="utf-8")
            (ws / "STATUS.md").write_text("# Status\n", encoding="utf-8")
            (ws / ".auditooor").mkdir()
            (ws / ".auditooor" / "invariant_ledger.json").write_text(json.dumps({"rows": []}), encoding="utf-8")
            review = ws / "fake-post-audit-review.sh"
            sync = ws / "fake-submission-sync.sh"
            bridge = ws / "fake-high-impact-execution-bridge.py"
            _write_executable(
                review,
                "#!/usr/bin/env bash\n"
                "set -euo pipefail\n"
                "printf 'Potential staging-vs-final contradictions: 0\\n'\n"
                "printf 'No live-proof contradictions detected\\n'\n",
            )
            _write_executable(
                sync,
                "#!/usr/bin/env bash\n"
                "set -euo pipefail\n"
                "printf 'status sync ok\\n'\n",
            )
            _write_executable(
                bridge,
                "#!/usr/bin/env python3\n"
                "import json, sys\n"
                "out = sys.argv[sys.argv.index('--out-json') + 1]\n"
                "payload = {'summary': {'runnable_harness_rows': 1, 'blocked_missing_impact_contract': 0}}\n"
                "open(out, 'w', encoding='utf-8').write(json.dumps(payload))\n",
            )

            with mock.patch.object(self.mod, "POST_AUDIT_REVIEW", review), \
                 mock.patch.object(self.mod, "SUBMISSION_SYNC", sync), \
                 mock.patch.object(self.mod, "HIGH_IMPACT_EXECUTION_BRIDGE", bridge):
                status = self.mod.stage_post_audit_review(ws, self.args)

            self.assertEqual(status, "SUCCESS")
            self.assertTrue((ws / ".auditooor" / "high_impact_execution_bridge.json").is_file())


if __name__ == "__main__":
    unittest.main()
