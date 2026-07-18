#!/usr/bin/env python3
"""Tests for tools/semantic-predicate-gate.py."""

from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "semantic-predicate-gate.py"


def _load_tool():
    spec = importlib.util.spec_from_file_location("semantic_predicate_gate", TOOL)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


GATE = _load_tool()


class SemanticPredicateGateTests(unittest.TestCase):
    def _report(self, entries: list[dict]) -> dict:
        return {
            "schema": "auditooor.live_target_intelligence.v3",
            "entry_points": entries,
        }

    def _topical_fixture(self, root: Path) -> tuple[Path, Path, Path]:
        ws = root / "ws"
        (ws / "src").mkdir(parents=True)
        (ws / "src" / "Gate.sol").write_text(
            "\n".join(
                [
                    "contract Gate {",
                    "  function ping() external {}",
                    "}",
                ]
            ),
            encoding="utf-8",
        )
        report_path = root / "report.json"
        report_path.write_text(
            json.dumps(
                self._report(
                    [
                        {
                            "file_line": "src/Gate.sol:1",
                            "cluster_id": "gate-topical",
                            "snippet": "contract Gate { function ping() external {} }",
                            "p1_match_tier": "TOPICAL-MATCH",
                            "topical_p1_invariants": ["INV-AUTH-001"],
                        }
                    ]
                )
            ),
            encoding="utf-8",
        )
        return root, ws, report_path

    def test_llm_verdict_is_cached_by_code_and_predicate_hash(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            ws = root / "ws"
            (ws / "src").mkdir(parents=True)
            (ws / "src" / "Bridge.sol").write_text(
                "\n".join(
                    [
                        "contract Bridge {",
                        "  mapping(bytes32 => address) private _requestReceipts;",
                        "  function relay(bytes32 commitment, address target) external {",
                        "    require(_requestReceipts[commitment] == address(0));",
                        "    _requestReceipts[commitment] = msg.sender;",
                        "    target.call(\"\");",
                        "  }",
                        "}",
                    ]
                ),
                encoding="utf-8",
            )
            report_path = root / "report.json"
            report_path.write_text(
                json.dumps(
                    self._report(
                        [
                            {
                                "file_line": "src/Bridge.sol:4",
                                "cluster_id": "bridge-commitment-replay",
                                "snippet": "_requestReceipts[commitment] = msg.sender;",
                                "p1_match_tier": "TOPICAL-MATCH",
                                "topical_p1_invariants": ["INV-BRIDGE-003"],
                            }
                        ]
                    )
                ),
                encoding="utf-8",
            )
            cache = root / "cache.json"
            output = root / "out.json"

            calls: list[list[str]] = []

            def fake_run(cmd, **kwargs):
                calls.append(cmd)
                prompt_path = Path(cmd[cmd.index("--prompt-file") + 1])
                prompt = prompt_path.read_text(encoding="utf-8")
                self.assertIn("INV-BRIDGE-003", prompt)
                self.assertIn("_requestReceipts", prompt)
                return subprocess.CompletedProcess(
                    cmd,
                    0,
                    stdout=json.dumps(
                        {
                            "verdict": "SEMANTIC",
                            "reason": "mapping write consumes the commitment before the call",
                            "evidence": "_requestReceipts[commitment] = msg.sender",
                        }
                    ),
                    stderr="",
                )

            with mock.patch.object(GATE.subprocess, "run", side_effect=fake_run):
                rc = GATE.main(
                    [
                        "--input",
                        str(report_path),
                        "--workspace",
                        str(ws),
                        "--cache",
                        str(cache),
                        "--output",
                        str(output),
                    ]
                )
            self.assertEqual(rc, 0)
            self.assertEqual(len(calls), 1)
            emitted = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(emitted["summary"]["effective_call_cap"], 50)
            self.assertEqual(emitted["summary"]["verdict_counts"]["SEMANTIC"], 1)
            cached = json.loads(cache.read_text(encoding="utf-8"))
            self.assertEqual(len(cached["records"]), 1)

            def fail_run(*_args, **_kwargs):
                raise AssertionError("second run should use cache")

            with mock.patch.object(GATE.subprocess, "run", side_effect=fail_run):
                report = GATE.load_json(report_path)
                candidates = GATE.build_candidates(
                    report,
                    workspace=ws,
                    invariant_index=GATE.load_invariant_index(),
                    context_lines=20,
                )
                verdicts, summary = GATE.evaluate_candidates(
                    candidates,
                    cache_path=cache,
                    dispatcher=TOOL,
                    provider="auto",
                    max_tokens=200,
                    timeout=5,
                    audit_dir=None,
                    max_calls=50,
                    max_report_cost_usd=1,
                    cost_per_call_usd=0.02,
                    operator_live_network_consent=False,
                    dry_run=False,
                )
            self.assertEqual(summary["cache_hits"], 1)
            self.assertEqual(verdicts[0]["verdict"], "SEMANTIC")
            self.assertEqual(verdicts[0]["source"], "cache")

    def test_dry_run_does_not_create_default_cache(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _, ws, report_path = self._topical_fixture(root)
            default_cache = GATE.default_cache_path(ws)
            self.assertFalse(default_cache.exists())

            with mock.patch.object(GATE.subprocess, "run") as run:
                rc = GATE.main(
                    [
                        "--input",
                        str(report_path),
                        "--workspace",
                        str(ws),
                        "--dry-run",
                    ]
                )

            self.assertEqual(rc, 0)
            run.assert_not_called()
            self.assertFalse(
                default_cache.exists(),
                "dry-run must not create the default semantic predicate cache",
            )

    def test_ambient_consent_is_scrubbed_without_operator_opt_in(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _, ws, report_path = self._topical_fixture(root)
            cache_path = root / "cache.json"
            captured: list[dict[str, str]] = []

            def fake_run(cmd, **kwargs):
                captured.append(dict(kwargs["env"]))
                return subprocess.CompletedProcess(cmd, 0, stdout="{}", stderr="")

            with mock.patch.dict(
                os.environ,
                {
                    "AUDITOOOR_LLM_NETWORK_CONSENT": "1",
                    "ADVERSARIAL_LIVE_CONSENT": "1",
                },
                clear=False,
            ), mock.patch.object(GATE.subprocess, "run", side_effect=fake_run):
                verdicts, summary = GATE.evaluate_candidates(
                    GATE.build_candidates(
                        GATE.load_json(report_path),
                        workspace=ws,
                        invariant_index={"INV-AUTH-001": {"statement": "Sensitive actions require authorization."}},
                        context_lines=5,
                    ),
                    cache_path=cache_path,
                    dispatcher=TOOL,
                    provider="auto",
                    max_tokens=200,
                    timeout=5,
                    audit_dir=None,
                    max_calls=50,
                    max_report_cost_usd=1,
                    cost_per_call_usd=0.02,
                    operator_live_network_consent=False,
                    dry_run=False,
                )

            self.assertEqual(summary["llm_calls_attempted"], 1)
            self.assertEqual(verdicts[0]["source"], "llm")
            self.assertEqual(len(captured), 1)
            self.assertNotIn("AUDITOOOR_LLM_NETWORK_CONSENT", captured[0])
            self.assertNotIn("ADVERSARIAL_LIVE_CONSENT", captured[0])

    def test_operator_live_consent_is_forwarded_when_explicitly_enabled(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            _, ws, report_path = self._topical_fixture(root)
            cache_path = root / "cache.json"
            captured: list[dict[str, str]] = []

            def fake_run(cmd, **kwargs):
                captured.append(dict(kwargs["env"]))
                return subprocess.CompletedProcess(cmd, 0, stdout="{}", stderr="")

            with mock.patch.dict(
                os.environ,
                {
                    "AUDITOOOR_LLM_NETWORK_CONSENT": "1",
                    "ADVERSARIAL_LIVE_CONSENT": "1",
                },
                clear=False,
            ), mock.patch.object(GATE.subprocess, "run", side_effect=fake_run):
                verdicts, summary = GATE.evaluate_candidates(
                    GATE.build_candidates(
                        GATE.load_json(report_path),
                        workspace=ws,
                        invariant_index={"INV-AUTH-001": {"statement": "Sensitive actions require authorization."}},
                        context_lines=5,
                    ),
                    cache_path=cache_path,
                    dispatcher=TOOL,
                    provider="auto",
                    max_tokens=200,
                    timeout=5,
                    audit_dir=None,
                    max_calls=50,
                    max_report_cost_usd=1,
                    cost_per_call_usd=0.02,
                    operator_live_network_consent=True,
                    dry_run=False,
                )

            self.assertEqual(summary["llm_calls_attempted"], 1)
            self.assertEqual(verdicts[0]["source"], "llm")
            self.assertEqual(len(captured), 1)
            self.assertEqual(captured[0]["AUDITOOOR_LLM_NETWORK_CONSENT"], "1")
            self.assertEqual(captured[0]["ADVERSARIAL_LIVE_CONSENT"], "1")

    def test_default_cost_cap_budget_skips_after_effective_call_limit(self) -> None:
        report = self._report(
            [
                {
                    "file_line": f"src/T.sol:{idx}",
                    "cluster_id": "auth-topical",
                    "snippet": f"function f{idx}() external {{}}",
                    "p1_match_tier": "TOPICAL-MATCH",
                    "topical_p1_invariants": ["INV-AUTH-001"],
                }
                for idx in range(1, 4)
            ]
        )
        candidates = GATE.build_candidates(
            report,
            workspace=None,
            invariant_index={"INV-AUTH-001": {"statement": "Sensitive actions require authorization."}},
            context_lines=5,
        )

        def fake_run(cmd, **_kwargs):
            return subprocess.CompletedProcess(
                cmd,
                0,
                stdout='{"verdict":"FALSE-POSITIVE","reason":"unrelated","evidence":"none"}',
                stderr="",
            )

        with tempfile.TemporaryDirectory() as td, mock.patch.object(
            GATE.subprocess, "run", side_effect=fake_run
        ):
            verdicts, summary = GATE.evaluate_candidates(
                candidates,
                cache_path=Path(td) / "cache.json",
                dispatcher=TOOL,
                provider="auto",
                max_tokens=200,
                timeout=5,
                audit_dir=None,
                max_calls=50,
                max_report_cost_usd=0.04,
                cost_per_call_usd=0.02,
                operator_live_network_consent=False,
                dry_run=False,
            )
        self.assertEqual(summary["effective_call_cap"], 2)
        self.assertEqual(summary["llm_calls_attempted"], 2)
        self.assertEqual(summary["budget_skipped"], 1)
        self.assertEqual([row["verdict"] for row in verdicts], ["FALSE-POSITIVE", "FALSE-POSITIVE", "TOPICAL"])
        self.assertEqual(verdicts[-1]["source"], "budget")

    def test_parse_llm_response_normalizes_fenced_json(self) -> None:
        parsed = GATE.parse_llm_response(
            "analysis\n```json\n"
            '{"verdict":"SEMANTIC-MATCH","reason":"same state machine","evidence":"height check"}'
            "\n```\n"
        )
        self.assertEqual(parsed["verdict"], "SEMANTIC")
        self.assertEqual(parsed["reason"], "same state machine")

    def test_non_topical_rows_are_not_sent_to_stage_two(self) -> None:
        report = self._report(
            [
                {
                    "file_line": "src/Safe.sol:1",
                    "cluster_id": "already-semantic",
                    "snippet": "safe",
                    "p1_match_tier": "SEMANTIC-MATCH",
                    "matched_p1_invariants": ["INV-UNI-002"],
                    "semantic_p1_invariants": ["INV-UNI-002"],
                },
                {
                    "file_line": "src/None.sol:1",
                    "cluster_id": "none",
                    "snippet": "none",
                    "p1_match_tier": "NO-MATCH",
                },
            ]
        )
        self.assertEqual(
            GATE.build_candidates(
                report,
                workspace=None,
                invariant_index={},
                context_lines=5,
            ),
            [],
        )

    def test_apply_semantic_verdict_promotes_report_row(self) -> None:
        report = self._report(
            [
                {
                    "file_line": "src/Bridge.sol:4",
                    "cluster_id": "bridge-commitment-replay",
                    "snippet": "_requestReceipts[commitment] = msg.sender;",
                    "engage_severity_score": 50.0,
                    "hunt_priority": "MEDIUM-PRIORITY",
                    "hunt_priority_base": "MEDIUM-PRIORITY",
                    "matched_anti_patterns": ["P3-BRIDGE-REPLAY"],
                    "matched_p1_invariants": ["INV-BRIDGE-003"],
                    "p1_invariant_hits": ["INV-BRIDGE-003"],
                    "semantic_p1_invariants": [],
                    "topical_p1_invariants": ["INV-BRIDGE-003"],
                    "p1_match_tier": "TOPICAL-MATCH",
                    "p1_semantic_invariant_gaps": [{"status": "topical-only"}],
                    "composability_score": 1,
                }
            ]
        )
        report["summary_card"] = {"composability": {}}
        payload = {
            "verdicts": [
                {
                    "entry_index": 0,
                    "candidate_id": "src/Bridge.sol:4|bridge-commitment-replay|INV-BRIDGE-003",
                    "file_line": "src/Bridge.sol:4",
                    "cluster_id": "bridge-commitment-replay",
                    "predicate_id": "INV-BRIDGE-003",
                    "verdict": "SEMANTIC",
                    "reason": "prewrite consumes request before external call",
                    "evidence": "_requestReceipts[commitment]",
                    "source": "llm",
                    "cache_key": "abc",
                }
            ]
        }

        summary = GATE.apply_verdicts_to_report(report, payload)
        row = report["entry_points"][0]
        self.assertEqual(summary["semantic_promotions"], 1)
        self.assertEqual(row["p1_match_tier"], "SEMANTIC-MATCH")
        self.assertEqual(row["semantic_p1_invariants"], ["INV-BRIDGE-003"])
        self.assertEqual(row["topical_p1_invariants"], [])
        self.assertEqual(row["p1_semantic_invariant_gaps"], [])
        self.assertEqual(row["semantic_gate_verdicts"][0]["action"], "promoted-to-semantic-p1-invariant")
        self.assertEqual(report["summary_card"]["composability"]["p1_match_tier_counts"]["SEMANTIC-MATCH"], 1)

    def test_apply_false_positive_records_without_suppressing_row(self) -> None:
        report = self._report(
            [
                {
                    "file_line": "src/Safe.sol:1",
                    "cluster_id": "bridge-proof-safe",
                    "engage_severity_score": 45,
                    "hunt_priority": "MEDIUM-PRIORITY",
                    "matched_p1_invariants": ["INV-BRIDGE-004"],
                    "p1_invariant_hits": ["INV-BRIDGE-004"],
                    "semantic_p1_invariants": [],
                    "topical_p1_invariants": ["INV-BRIDGE-004"],
                    "p1_match_tier": "TOPICAL-MATCH",
                    "p1_semantic_invariant_gaps": [{"status": "topical-only"}],
                }
            ]
        )
        payload = {
            "verdicts": [
                {
                    "entry_index": 0,
                    "file_line": "src/Safe.sol:1",
                    "cluster_id": "bridge-proof-safe",
                    "predicate_id": "INV-BRIDGE-004",
                    "verdict": "FALSE-POSITIVE",
                    "reason": "nonce check present",
                    "evidence": "require(nonce == expected)",
                    "source": "llm",
                    "cache_key": "fp",
                }
            ]
        }

        summary = GATE.apply_verdicts_to_report(report, payload)
        row = report["entry_points"][0]
        self.assertEqual(summary["false_positive_records"], 1)
        self.assertEqual(row["p1_match_tier"], "TOPICAL-MATCH")
        self.assertEqual(row["topical_p1_invariants"], ["INV-BRIDGE-004"])
        self.assertEqual(row["semantic_gate_verdicts"][0]["action"], "recorded-only-no-auto-suppression")

    def test_apply_skips_dry_run_placeholders_by_default(self) -> None:
        report = self._report(
            [
                {
                    "file_line": "src/Bridge.sol:4",
                    "cluster_id": "bridge-commitment-replay",
                    "matched_p1_invariants": ["INV-BRIDGE-003"],
                    "topical_p1_invariants": ["INV-BRIDGE-003"],
                    "p1_match_tier": "TOPICAL-MATCH",
                }
            ]
        )
        payload = {
            "verdicts": [
                {
                    "entry_index": 0,
                    "file_line": "src/Bridge.sol:4",
                    "cluster_id": "bridge-commitment-replay",
                    "predicate_id": "INV-BRIDGE-003",
                    "verdict": "TOPICAL",
                    "source": "dry-run",
                }
            ]
        }

        summary = GATE.apply_verdicts_to_report(report, payload)
        self.assertEqual(summary["dry_run_verdicts_skipped"], 1)
        self.assertNotIn("semantic_gate_verdicts", report["entry_points"][0])


if __name__ == "__main__":
    unittest.main()
