"""CAP-FIX-W11 regression tests for vault_global_chain_template_match
per-row invariant_ids inference.

<!-- r36-rebuttal: pathspec registered via agent-pathspec-register.py for
     lane lane-CAP-FIX-W11-global-chain-template-per-row -->

Scope: verifies that when `broken_invariant_ids` is not passed as kwarg
AND `exploit_queue.json` does not carry a top-level `broken_invariant_ids`
/ `invariant_ids` roll-up, the handler scans queue rows for per-row
fields (`broken_invariant_ids` list, `invariant_ids` list, `invariant_id`
str, `invariant_violated` str, `predicate_id` str, `predicate_ids` list)
and merges them into the resolution set. Also verifies precedence:

    kwarg > top-level field > per-row scan > empty (none)

and the new `resolution_source` envelope field surfaces which path won.

Schema asserted: auditooor.vault_global_chain_template_match.v1
"""
from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = REPO_ROOT / "tools" / "vault-mcp-server.py"
EXPECTED_SCHEMA = "auditooor.vault_global_chain_template_match.v1"


def _load_vault_mcp():
    spec = importlib.util.spec_from_file_location(
        "vault_mcp_server_gct_per_row_inference", MODULE_PATH
    )
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


def _write_jsonl(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fh:
        for row in rows:
            fh.write(json.dumps(row) + "\n")


def _tpl(
    chain_template_id: str,
    member_ids: list[str],
    *,
    tuple_size: int | None = None,
    score: float = 0.7,
    tier: str = "tier-2-verified-public-archive",
) -> dict:
    return {
        "schema_version": "auditooor.global_chain_template.v1",
        "chain_template_id": chain_template_id,
        "member_invariant_ids": sorted(member_ids),
        "tuple_size": tuple_size or len(member_ids),
        "composition_score": score,
        "composition_rationale": "per-row-inference test composition",
        "verification_tier": tier,
        "evidence_incidents": [],
        "advisory_only": True,
        "submission_posture": "NOT_SUBMIT_READY",
    }


class VaultGlobalChainTemplateMatchPerRowInferenceTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(
            prefix="vault-gct-per-row-"
        )
        self.base = Path(self.tmp.name)
        self.vault_dir = self.base / "vault"
        self.repo = self.base / "repo"
        self.ws = self.base / "workspace"
        self.vault_dir.mkdir()
        self.repo.mkdir()
        self.ws.mkdir()
        self.vault_mcp = _load_vault_mcp()
        self.vault = self.vault_mcp.VaultQuery(
            self.vault_dir, repo_root=self.repo
        )
        self.tpl_path = (
            self.repo
            / "audit"
            / "corpus_tags"
            / "derived"
            / "global_chain_templates.jsonl"
        )
        self.queue_path = self.ws / ".auditooor" / "exploit_queue.json"
        self.queue_path.parent.mkdir(parents=True, exist_ok=True)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    # --- Test 1: empty queue -> resolution_source=none, matched=[] ---
    def test_empty_queue_resolution_source_none(self) -> None:
        _write_jsonl(
            self.tpl_path,
            [_tpl("GCT-empty", ["INV-X-1", "INV-X-2"])],
        )
        # Queue exists but has no usable ids at any level.
        self.queue_path.write_text(
            json.dumps({"queue": []}),
            encoding="utf-8",
        )
        result = self.vault.vault_global_chain_template_match(
            workspace_path=str(self.ws),
        )
        self.assertEqual(result["schema"], EXPECTED_SCHEMA)
        self.assertEqual(result["matched_templates"], [])
        self.assertEqual(result["resolution_source"], "none")
        self.assertEqual(
            result["summary"]["resolution_source"], "none"
        )
        self.assertEqual(
            result["summary"]["broken_invariant_id_count"], 0
        )

    # --- Test 2: top-level field only -> resolution_source=top-level-field ---
    def test_top_level_field_only(self) -> None:
        _write_jsonl(
            self.tpl_path,
            [_tpl("GCT-top", ["INV-TOP-1", "INV-TOP-2"])],
        )
        self.queue_path.write_text(
            json.dumps(
                {
                    "broken_invariant_ids": [
                        "INV-TOP-1",
                        "INV-TOP-2",
                    ],
                    # rows present but should NOT be scanned because
                    # top-level wins.
                    "queue": [
                        {
                            "lead_id": "L1",
                            "invariant_id": "INV-SHOULD-NOT-MATCH-1",
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        result = self.vault.vault_global_chain_template_match(
            workspace_path=str(self.ws),
            min_match_density=0.5,
        )
        self.assertEqual(
            result["resolution_source"], "top-level-field"
        )
        self.assertEqual(
            sorted(result["broken_invariant_ids_input"]),
            ["INV-TOP-1", "INV-TOP-2"],
        )
        self.assertEqual(len(result["matched_templates"]), 1)
        self.assertEqual(
            result["matched_templates"][0]["chain_template_id"],
            "GCT-top",
        )

    # --- Test 3: per-row invariant_id strings (no top-level) ---
    def test_per_row_invariant_id_strings(self) -> None:
        _write_jsonl(
            self.tpl_path,
            [
                _tpl(
                    "GCT-row-str",
                    ["INV-PR-1", "INV-PR-2", "INV-PR-3"],
                ),
            ],
        )
        # Per-row `invariant_id` strings only. No top-level field.
        self.queue_path.write_text(
            json.dumps(
                {
                    "queue": [
                        {"lead_id": "L1", "invariant_id": "INV-PR-1"},
                        {
                            "lead_id": "L2",
                            "invariant_violated": "INV-PR-2",
                        },
                        {
                            "lead_id": "L3",
                            "predicate_id": "INV-PR-3",
                        },
                    ]
                }
            ),
            encoding="utf-8",
        )
        result = self.vault.vault_global_chain_template_match(
            workspace_path=str(self.ws),
            min_match_density=0.5,
        )
        self.assertEqual(result["resolution_source"], "per-row-fields")
        self.assertEqual(
            sorted(result["broken_invariant_ids_input"]),
            ["INV-PR-1", "INV-PR-2", "INV-PR-3"],
        )
        # Full match expected (3/3).
        self.assertEqual(len(result["matched_templates"]), 1)
        self.assertEqual(
            result["matched_templates"][0]["match_density"], 1.0
        )

    # --- Test 4: per-row list fields merged + de-duped ---
    def test_per_row_list_fields_merged_dedup(self) -> None:
        _write_jsonl(
            self.tpl_path,
            [
                _tpl(
                    "GCT-row-list",
                    [
                        "INV-LIST-A",
                        "INV-LIST-B",
                        "INV-LIST-C",
                        "INV-LIST-D",
                    ],
                ),
            ],
        )
        self.queue_path.write_text(
            json.dumps(
                {
                    "queue": [
                        {
                            "lead_id": "L1",
                            "broken_invariant_ids": [
                                "INV-LIST-A",
                                "INV-LIST-B",
                            ],
                        },
                        {
                            "lead_id": "L2",
                            "invariant_ids": [
                                "INV-LIST-B",  # duplicate (must de-dup)
                                "INV-LIST-C",
                            ],
                        },
                        {
                            "lead_id": "L3",
                            "predicate_ids": [
                                "INV-LIST-D",
                                "INV-LIST-A",  # duplicate
                            ],
                        },
                    ]
                }
            ),
            encoding="utf-8",
        )
        result = self.vault.vault_global_chain_template_match(
            workspace_path=str(self.ws),
            min_match_density=0.5,
        )
        self.assertEqual(result["resolution_source"], "per-row-fields")
        self.assertEqual(
            sorted(result["broken_invariant_ids_input"]),
            ["INV-LIST-A", "INV-LIST-B", "INV-LIST-C", "INV-LIST-D"],
        )
        self.assertEqual(
            result["summary"]["broken_invariant_id_count"], 4
        )
        # Full match expected (4/4 -> density 1.0).
        self.assertEqual(len(result["matched_templates"]), 1)
        self.assertEqual(
            result["matched_templates"][0]["match_density"], 1.0
        )

    # --- Test 5: top-level AND per-row both present -> top-level wins ---
    def test_precedence_top_level_wins_over_per_row(self) -> None:
        _write_jsonl(
            self.tpl_path,
            [
                _tpl("GCT-top-only", ["INV-TOP-A", "INV-TOP-B"]),
                _tpl(
                    "GCT-row-only", ["INV-ROW-A", "INV-ROW-B"]
                ),
            ],
        )
        self.queue_path.write_text(
            json.dumps(
                {
                    # Top-level field -> the resolution that must win.
                    "broken_invariant_ids": [
                        "INV-TOP-A",
                        "INV-TOP-B",
                    ],
                    # Per-row data that the gate must NOT scan because
                    # top-level took precedence.
                    "queue": [
                        {
                            "lead_id": "L1",
                            "invariant_id": "INV-ROW-A",
                        },
                        {
                            "lead_id": "L2",
                            "invariant_ids": ["INV-ROW-B"],
                        },
                    ],
                }
            ),
            encoding="utf-8",
        )
        result = self.vault.vault_global_chain_template_match(
            workspace_path=str(self.ws),
            min_match_density=0.5,
        )
        self.assertEqual(
            result["resolution_source"], "top-level-field"
        )
        # Only top-level ids surfaced.
        self.assertEqual(
            sorted(result["broken_invariant_ids_input"]),
            ["INV-TOP-A", "INV-TOP-B"],
        )
        ids_matched = sorted(
            m["chain_template_id"] for m in result["matched_templates"]
        )
        # Per-row template must NOT match because per-row scan was skipped.
        self.assertEqual(ids_matched, ["GCT-top-only"])

    # --- Test 6 (bonus): explicit kwarg precedence over both ---
    def test_kwarg_wins_over_top_level_and_per_row(self) -> None:
        _write_jsonl(
            self.tpl_path,
            [
                _tpl(
                    "GCT-kwarg",
                    ["INV-KW-A", "INV-KW-B"],
                ),
                _tpl(
                    "GCT-noise",
                    ["INV-TOP-A", "INV-ROW-A"],
                ),
            ],
        )
        self.queue_path.write_text(
            json.dumps(
                {
                    "broken_invariant_ids": ["INV-TOP-A"],
                    "queue": [
                        {
                            "lead_id": "L1",
                            "invariant_id": "INV-ROW-A",
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )
        result = self.vault.vault_global_chain_template_match(
            workspace_path=str(self.ws),
            broken_invariant_ids=["INV-KW-A", "INV-KW-B"],
            min_match_density=0.5,
        )
        self.assertEqual(result["resolution_source"], "kwarg")
        self.assertEqual(
            sorted(result["broken_invariant_ids_input"]),
            ["INV-KW-A", "INV-KW-B"],
        )
        ids_matched = sorted(
            m["chain_template_id"] for m in result["matched_templates"]
        )
        # Only the kwarg-aligned template matches.
        self.assertEqual(ids_matched, ["GCT-kwarg"])

    # --- Test 7 (bonus): queue is a bare list of row-dicts ---
    def test_queue_root_is_bare_list(self) -> None:
        _write_jsonl(
            self.tpl_path,
            [
                _tpl(
                    "GCT-bare-list",
                    ["INV-BL-1", "INV-BL-2"],
                ),
            ],
        )
        # Some legacy queues are a top-level list, not a dict.
        self.queue_path.write_text(
            json.dumps(
                [
                    {"lead_id": "L1", "invariant_id": "INV-BL-1"},
                    {
                        "lead_id": "L2",
                        "predicate_ids": ["INV-BL-2"],
                    },
                ]
            ),
            encoding="utf-8",
        )
        result = self.vault.vault_global_chain_template_match(
            workspace_path=str(self.ws),
            min_match_density=0.5,
        )
        self.assertEqual(result["resolution_source"], "per-row-fields")
        self.assertEqual(
            sorted(result["broken_invariant_ids_input"]),
            ["INV-BL-1", "INV-BL-2"],
        )
        self.assertEqual(len(result["matched_templates"]), 1)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
