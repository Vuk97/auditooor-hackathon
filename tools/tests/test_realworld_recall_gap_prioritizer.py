#!/usr/bin/env python3
"""Tests for tools/audit/realworld-recall-gap-prioritizer.py."""

from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL = REPO_ROOT / "tools" / "audit" / "realworld-recall-gap-prioritizer.py"


def _load_module():
    spec = importlib.util.spec_from_file_location(
        "realworld_recall_gap_prioritizer", TOOL
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


M = _load_module()


def _sample(
    attack_class: str,
    slug: str,
    *,
    sample_origin: str = "internal_fixture",
    source: str = "fixture:test",
    target_language: str = "solidity",
    own: bool = True,
    indep_any: bool = False,
    indep_same: bool = False,
    dets: list[str] | None = None,
    compile_error: str | None = None,
) -> dict:
    return {
        "slug": slug,
        "attack_class": attack_class,
        "severity": "HIGH",
        "source": source,
        "sample_origin": sample_origin,
        "target_language": target_language,
        "compile_error": compile_error,
        "own_detector_fired": own,
        "independent_any_fired": indep_any,
        "independent_same_class_fired": indep_same,
        "independent_firing_detectors": dets or [],
    }


def _scoreboard(*, generated_at: str, per_sample: list[dict], external_manifest: str = "") -> dict:
    return {
        "schema": "auditooor.realworld_recall_scoreboard.v1",
        "generated_at": generated_at,
        "external_manifest": external_manifest,
        "per_sample": per_sample,
    }


class TestSchemaAndRanking(unittest.TestCase):
    def test_schema_constant(self):
        self.assertEqual(M.SCHEMA, "auditooor.realworld_recall_gap_priorities.v1")

    def test_sidecar_external_evidence_and_latest_sample_win(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            reports = root / "reports"
            reports.mkdir()

            manifest = reports / "external_recall_samples_phase_f.json"
            manifest.write_text(
                json.dumps(
                    {
                        "schema": "auditooor.external_recall_samples.v1",
                        "samples": [
                            {
                                "id": "arith-ext-a",
                                "path": "arith-a.sol",
                                "attack_class": "fund-loss-via-arithmetic",
                                "source": "external_repo:morpho:src/A.sol",
                            },
                            {
                                "id": "arith-ext-b",
                                "path": "arith-b.sol",
                                "attack_class": "fund-loss-via-arithmetic",
                                "source": "external_repo:reserve:src/B.sol",
                            },
                            {
                                "id": "arith-ext-c",
                                "path": "arith-c.sol",
                                "attack_class": "fund-loss-via-arithmetic",
                                "source": "external_repo:centrifuge:src/C.sol",
                            },
                        ],
                    }
                ),
                encoding="utf-8",
            )

            (reports / "realworld_recall_scoreboard.json").write_text(
                json.dumps(
                    _scoreboard(
                        generated_at="2026-05-17T10:00:00Z",
                        per_sample=[
                            _sample(
                                "fund-loss-via-arithmetic",
                                "arith-int-1",
                                indep_any=True,
                                dets=["wrong-detector-a"],
                            ),
                            _sample(
                                "fund-loss-via-arithmetic",
                                "arith-int-2",
                                indep_any=True,
                                dets=["wrong-detector-a", "wrong-detector-b"],
                            ),
                            _sample(
                                "fund-loss-via-arithmetic",
                                "arith-int-3",
                                indep_any=False,
                            ),
                            _sample(
                                "fund-loss-via-arithmetic",
                                "arith-int-4",
                                indep_any=True,
                                indep_same=True,
                            ),
                            _sample(
                                "access-control",
                                "access-int-1",
                                indep_any=True,
                                indep_same=False,
                                dets=["guard-detector"],
                            ),
                            _sample(
                                "access-control",
                                "access-int-2",
                                indep_any=True,
                                indep_same=True,
                            ),
                            _sample(
                                "access-control",
                                "access-int-3",
                                indep_any=True,
                                indep_same=True,
                            ),
                        ],
                    )
                ),
                encoding="utf-8",
            )

            (reports / "realworld_recall_scoreboard_external_phase_f.json").write_text(
                json.dumps(
                    _scoreboard(
                        generated_at="2026-05-17T11:00:00Z",
                        external_manifest=str(manifest),
                        per_sample=[
                            _sample(
                                "fund-loss-via-arithmetic",
                                "arith-ext-a",
                                sample_origin="external_repo",
                                source="external_repo:morpho:src/A.sol",
                                own=False,
                                indep_any=True,
                                indep_same=False,
                                dets=["wrong-detector-a"],
                            ),
                            _sample(
                                "fund-loss-via-arithmetic",
                                "arith-ext-b",
                                sample_origin="external_repo",
                                source="external_repo:reserve:src/B.sol",
                                own=False,
                                indep_any=True,
                                indep_same=False,
                                dets=["wrong-detector-c"],
                            ),
                        ],
                    )
                ),
                encoding="utf-8",
            )

            (reports / "realworld_recall_scoreboard_external_phase_f_after_w68.json").write_text(
                json.dumps(
                    _scoreboard(
                        generated_at="2026-05-17T12:00:00Z",
                        external_manifest=str(manifest),
                        per_sample=[
                            _sample(
                                "fund-loss-via-arithmetic",
                                "arith-ext-a",
                                sample_origin="external_repo",
                                source="external_repo:morpho:src/A.sol",
                                own=False,
                                indep_any=True,
                                indep_same=True,
                                dets=["wrong-detector-a"],
                            ),
                            _sample(
                                "fund-loss-via-arithmetic",
                                "arith-ext-b",
                                sample_origin="external_repo",
                                source="external_repo:reserve:src/B.sol",
                                own=False,
                                indep_any=True,
                                indep_same=False,
                                dets=["wrong-detector-c"],
                            ),
                        ],
                    )
                ),
                encoding="utf-8",
            )

            payload = M.run(
                scoreboard_path=reports / "realworld_recall_scoreboard.json",
                reports_dir=reports,
                include_uncategorized=False,
                top_n=10,
            )

            self.assertEqual(payload["summary"]["ranked_attack_classes"], 2)
            top = payload["priorities"][0]
            self.assertEqual(top["attack_class"], "fund-loss-via-arithmetic")
            self.assertEqual(top["external_evidence"]["measured_external_samples"], 2)
            self.assertEqual(top["external_evidence"]["manifest_external_unmeasured"], 1)
            self.assertAlmostEqual(top["external_evidence"]["external_same_class_recall"], 0.5)
            detectors = [row["detector"] for row in top["top_cross_class_detectors_on_misses"]]
            self.assertEqual(detectors[0], "wrong-detector-a")
            task_text = " ".join(task["summary"] for task in top["next_tasks"])
            self.assertIn("wrong-detector-a", task_text)
            self.assertIn("external", task_text)

    def test_historical_same_class_flag_reconciles_against_current_map(self):
        measured = [
            _sample(
                "bridge-proof-domain-bypass",
                "stale-external-row",
                sample_origin="external_repo",
                source="external_repo:snowbridge:src/Verification.sol",
                own=False,
                indep_any=True,
                indep_same=False,
                dets=["bridge-versioned-digest-tag-not-bound-to-version-flag"],
            )
        ]

        reconciled = [M._reconcile_recall_flags(dict(row)) for row in measured]
        priorities, taxonomy_debt, totals = M.aggregate_priorities(
            measured_samples=reconciled,
            manifest_samples=[],
            include_uncategorized=False,
        )

        self.assertEqual(taxonomy_debt, [])
        self.assertEqual(totals["measured_scorable_samples"], 1)
        self.assertEqual(priorities[0]["same_class_misses"], 0)
        self.assertEqual(priorities[0]["same_class_recall"], 1.0)
        self.assertTrue(reconciled[0]["independent_same_class_fired"])
        self.assertTrue(reconciled[0]["_same_class_reconciled_from_current_map"])
        self.assertEqual(
            reconciled[0]["_same_class_reconciled_detectors"],
            ["bridge-versioned-digest-tag-not-bound-to-version-flag"],
        )

    def test_quality_index_is_language_scoped(self):
        quality_index = M.build_quality_index([
            {
                "path": Path("/tmp/external_recall_manifest_quality.json"),
                "data": {
                    "generated_at": "2026-06-02T00:00:00Z",
                    "rows": [
                        {
                            "id": "shared-id",
                            "attack_class": "admin-bypass",
                            "source": "external_repo:shared",
                            "target_language": "solidity",
                            "gap_prioritization_eligible": False,
                            "quality_state": "fixed",
                        }
                    ],
                },
            }
        ])
        measured = [
            _sample(
                "admin-bypass",
                "shared-id",
                sample_origin="external_repo",
                source="external_repo:shared",
                target_language="go",
            ),
            _sample(
                "admin-bypass",
                "shared-id",
                sample_origin="external_repo",
                source="external_repo:shared",
                target_language="solidity",
            ),
        ]

        filtered, _manifests, counts = M.apply_quality_filter(measured, [], quality_index)

        self.assertEqual(counts["measured_external_rows_filtered"], 1)
        self.assertEqual(len(filtered), 1)
        self.assertEqual(filtered[0]["target_language"], "go")

    def test_quality_index_unknown_language_matches_inferred_legacy_rows(self):
        quality_index = M.build_quality_index([
            {
                "path": Path("/tmp/external_recall_manifest_quality.json"),
                "data": {
                    "generated_at": "2026-06-02T00:00:00Z",
                    "rows": [
                        {
                            "id": "legacy-solidity",
                            "attack_class": "admin-bypass",
                            "source": "external_repo:legacy",
                            "gap_prioritization_eligible": False,
                            "quality_state": "fixed",
                        }
                    ],
                },
            }
        ])
        measured = [
            _sample(
                "admin-bypass",
                "legacy-solidity",
                sample_origin="external_repo",
                source="external_repo:legacy",
                target_language="solidity",
            )
        ]

        filtered, _manifests, counts = M.apply_quality_filter(measured, [], quality_index)

        self.assertEqual(counts["measured_external_rows_filtered"], 1)
        self.assertEqual(filtered, [])

    def test_miss_examples_include_target_language(self):
        measured = [
            _sample(
                "apphash-divergence",
                "go-processproposal-accept-without-block-validation",
                target_language="go",
                own=True,
                indep_any=False,
                indep_same=False,
            )
        ]

        priorities, taxonomy_debt, _totals = M.aggregate_priorities(
            measured_samples=measured,
            manifest_samples=[],
            include_uncategorized=False,
        )

        self.assertEqual(taxonomy_debt, [])
        self.assertEqual(priorities[0]["miss_examples"][0]["target_language"], "go")
        md = M.build_markdown({
            "schema": M.SCHEMA,
            "generated_at": "2026-06-02T00:00:00Z",
            "summary": {"ranked_attack_classes": 1},
            "inputs": {},
            "priorities": priorities,
            "taxonomy_debt": [],
        })
        self.assertIn("go-processproposal-accept-without-block-validation (go)", md)

    def test_manifest_matching_bridges_unknown_and_solidity_only(self):
        measured = [
            _sample(
                "admin-bypass",
                "same-solidity",
                sample_origin="external_repo",
                source="external_repo:legacy",
                target_language="solidity",
                own=False,
            ),
            _sample(
                "admin-bypass",
                "same-go",
                sample_origin="external_repo",
                source="external_repo:legacy",
                target_language="go",
                own=False,
            ),
        ]
        manifest = [
            {
                "id": "same-solidity",
                "attack_class": "admin-bypass",
                "source": "external_repo:legacy",
            },
            {
                "id": "same-go",
                "attack_class": "admin-bypass",
                "source": "external_repo:legacy",
            },
        ]

        priorities, _taxonomy_debt, _totals = M.aggregate_priorities(
            measured_samples=measured,
            manifest_samples=manifest,
            include_uncategorized=False,
        )

        ext = priorities[0]["external_evidence"]
        self.assertEqual(ext["manifest_external_samples"], 2)
        self.assertEqual(ext["manifest_external_unmeasured"], 1)

    def test_historical_same_class_flag_reconciles_against_alias(self):
        measured = [
            _sample(
                "timestamp-manipulation",
                "deadline-row",
                sample_origin="internal_fixture",
                source="test",
                own=False,
                indep_any=True,
                indep_same=False,
                dets=["sig-signed-action-missing-deadline"],
            )
        ]

        reconciled = [M._reconcile_recall_flags(dict(row)) for row in measured]

        self.assertTrue(reconciled[0]["independent_same_class_fired"])
        self.assertTrue(reconciled[0]["_same_class_reconciled_from_current_map"])
        self.assertEqual(
            reconciled[0]["_same_class_reconciled_detectors"],
            ["sig-signed-action-missing-deadline"],
        )

    def test_manifest_attack_class_uses_canonical_aliases(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            reports = root / "reports"
            reports.mkdir()

            manifest = reports / "external_recall_samples_reentrancy.json"
            manifest.write_text(
                json.dumps(
                    {
                        "schema": "auditooor.external_recall_samples.v1",
                        "samples": [
                            {
                                "id": "morpho-preliquidation",
                                "path": "PreLiquidation.sol",
                                "attack_class": "reentrancy",
                                "source": "external_repo:morpho:preliquidation",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )

            (reports / "realworld_recall_scoreboard.json").write_text(
                json.dumps(
                    _scoreboard(
                        generated_at="2026-06-02T13:00:00Z",
                        per_sample=[
                            _sample(
                                "reentrancy-cross-contract",
                                "internal-reentrancy",
                                indep_any=True,
                                indep_same=True,
                                dets=["external-call-before-state-finalization-reentrancy"],
                            )
                        ],
                    )
                ),
                encoding="utf-8",
            )

            (reports / "realworld_recall_scoreboard_external_reentrancy.json").write_text(
                json.dumps(
                    _scoreboard(
                        generated_at="2026-06-02T13:01:00Z",
                        external_manifest=str(manifest),
                        per_sample=[
                            _sample(
                                "reentrancy-cross-contract",
                                "morpho-preliquidation",
                                sample_origin="external_repo",
                                source="external_repo:morpho:preliquidation",
                                own=False,
                                indep_any=True,
                                indep_same=True,
                                dets=["external-call-before-state-finalization-reentrancy"],
                            )
                        ],
                    )
                ),
                encoding="utf-8",
            )

            payload = M.run(
                scoreboard_path=reports / "realworld_recall_scoreboard.json",
                reports_dir=reports,
                include_uncategorized=False,
                top_n=10,
            )

            classes = {row["attack_class"] for row in payload["priorities"]}
            self.assertNotIn("reentrancy", classes)
            self.assertIn("reentrancy-cross-contract", classes)
            self.assertEqual(payload["summary"]["manifest_samples"], 1)
            row = payload["priorities"][0]
            self.assertEqual(row["same_class_misses"], 0)
            self.assertEqual(row["same_class_recall"], 1.0)

    def test_external_quality_reports_filter_disqualified_rows_before_ranking(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            reports = root / "reports"
            reports.mkdir()

            manifest = reports / "external_recall_samples_snowbridge.json"
            manifest.write_text(
                json.dumps(
                    {
                        "schema": "auditooor.external_recall_samples.v1",
                        "samples": [
                            {
                                "id": "snowbridge-contracts-src/beefyclient",
                                "path": "BeefyClient.sol",
                                "attack_class": "bridge-proof-domain-bypass",
                                "source": "external_repo:snowbridge:production",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )

            (reports / "external_recall_manifest_quality_snowbridge.json").write_text(
                json.dumps(
                    {
                        "schema": "auditooor.external_recall_manifest_quality.v1",
                        "generated_at": "2026-05-18T00:00:00Z",
                        "rows": [
                            {
                                "id": "snowbridge-contracts-src/beefyclient",
                                "path": "BeefyClient.sol",
                                "attack_class": "bridge-proof-domain-bypass",
                                "source": "external_repo:snowbridge:production",
                                "source_state": "out_of_class",
                                "quality_state": "disqualified_source_state",
                                "gap_prioritization_eligible": False,
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )

            (reports / "realworld_recall_scoreboard.json").write_text(
                json.dumps(
                    _scoreboard(
                        generated_at="2026-05-18T01:00:00Z",
                        per_sample=[
                            _sample(
                                "access-control",
                                "access-int-1",
                                indep_any=True,
                                indep_same=False,
                                dets=["wrong-access-detector"],
                            )
                        ],
                    )
                ),
                encoding="utf-8",
            )

            (reports / "realworld_recall_scoreboard_external_snowbridge.json").write_text(
                json.dumps(
                    _scoreboard(
                        generated_at="2026-05-18T01:10:00Z",
                        external_manifest=str(manifest),
                        per_sample=[
                            _sample(
                                "bridge-proof-domain-bypass",
                                "snowbridge-contracts-src/beefyclient",
                                sample_origin="external_repo",
                                source="external_repo:snowbridge:production",
                                own=False,
                                indep_any=False,
                                indep_same=False,
                            )
                        ],
                    )
                ),
                encoding="utf-8",
            )

            payload = M.run(
                scoreboard_path=reports / "realworld_recall_scoreboard.json",
                reports_dir=reports,
                include_uncategorized=False,
                top_n=10,
            )

            self.assertEqual(
                [row["attack_class"] for row in payload["priorities"]],
                ["admin-bypass"],
            )
            quality_counts = payload["inputs"]["quality_counts"]
            self.assertEqual(quality_counts["measured_external_rows_filtered"], 1)
            self.assertEqual(quality_counts["manifest_external_rows_filtered"], 1)

    def test_quality_filter_does_not_cross_match_same_slug_different_source(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            reports = root / "reports"
            reports.mkdir()

            manifest = reports / "external_recall_samples_bridge.json"
            manifest.write_text(
                json.dumps(
                    {
                        "schema": "auditooor.external_recall_samples.v1",
                        "samples": [
                            {
                                "id": "same-id",
                                "path": "Bridge.sol",
                                "attack_class": "bridge-proof-domain-bypass",
                                "source": "external_repo:snowbridge:vulnerable",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            (reports / "external_recall_manifest_quality_other_source.json").write_text(
                json.dumps(
                    {
                        "schema": "auditooor.external_recall_manifest_quality.v1",
                        "generated_at": "2026-05-18T00:00:00Z",
                        "rows": [
                            {
                                "id": "same-id",
                                "path": "Bridge.sol",
                                "attack_class": "bridge-proof-domain-bypass",
                                "source": "external_repo:snowbridge:fixed-current",
                                "source_state": "fixed",
                                "quality_state": "disqualified_source_state",
                                "gap_prioritization_eligible": False,
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            (reports / "realworld_recall_scoreboard.json").write_text(
                json.dumps(_scoreboard(generated_at="2026-05-18T01:00:00Z", per_sample=[])),
                encoding="utf-8",
            )
            (reports / "realworld_recall_scoreboard_external_bridge.json").write_text(
                json.dumps(
                    _scoreboard(
                        generated_at="2026-05-18T01:10:00Z",
                        external_manifest=str(manifest),
                        per_sample=[
                            _sample(
                                "bridge-proof-domain-bypass",
                                "same-id",
                                sample_origin="external_repo",
                                source="external_repo:snowbridge:vulnerable",
                                own=False,
                                indep_any=False,
                                indep_same=False,
                            )
                        ],
                    )
                ),
                encoding="utf-8",
            )

            payload = M.run(
                scoreboard_path=reports / "realworld_recall_scoreboard.json",
                reports_dir=reports,
                include_uncategorized=False,
                top_n=10,
            )

            self.assertEqual(payload["inputs"]["quality_counts"]["measured_external_rows_filtered"], 0)
            self.assertEqual(payload["inputs"]["quality_counts"]["manifest_external_rows_filtered"], 0)
            self.assertEqual(payload["priorities"][0]["attack_class"], "bridge-proof-domain-bypass")

    def test_uncategorized_goes_to_taxonomy_debt(self):
        priorities, taxonomy_debt, totals = M.aggregate_priorities(
            measured_samples=[
                _sample("uncategorized", "uncat-1", indep_any=True, indep_same=False),
                _sample("access-control", "access-1", indep_any=True, indep_same=False),
            ],
            manifest_samples=[],
            include_uncategorized=False,
        )
        self.assertEqual(totals["measured_scorable_samples"], 2)
        self.assertEqual([row["attack_class"] for row in priorities], ["access-control"])
        self.assertEqual([row["attack_class"] for row in taxonomy_debt], ["uncategorized"])


class TestCli(unittest.TestCase):
    def test_main_writes_json_and_markdown(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            reports = root / "reports"
            reports.mkdir()

            scoreboard = reports / "realworld_recall_scoreboard.json"
            scoreboard.write_text(
                json.dumps(
                    _scoreboard(
                        generated_at="2026-05-17T10:00:00Z",
                        per_sample=[
                            _sample(
                                "fee-handling",
                                "fee-1",
                                indep_any=True,
                                indep_same=False,
                                dets=["wrong-detector-fee"],
                            ),
                            _sample(
                                "fee-handling",
                                "fee-2",
                                indep_any=False,
                                indep_same=False,
                            ),
                            _sample(
                                "fee-handling",
                                "fee-3",
                                indep_any=True,
                                indep_same=True,
                            ),
                        ],
                    )
                ),
                encoding="utf-8",
            )

            out_json = reports / "gap.json"
            out_md = reports / "gap.md"
            rc = M.main(
                [
                    "--scoreboard",
                    str(scoreboard),
                    "--reports-dir",
                    str(reports),
                    "--out-json",
                    str(out_json),
                    "--out-md",
                    str(out_md),
                    "--top-n",
                    "5",
                    "--quiet",
                ]
            )
            self.assertEqual(rc, 0)
            payload = json.loads(out_json.read_text(encoding="utf-8"))
            self.assertEqual(payload["schema"], M.SCHEMA)
            self.assertEqual(payload["summary"]["ranked_attack_classes"], 1)
            self.assertIn("fee-redirect", out_md.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
