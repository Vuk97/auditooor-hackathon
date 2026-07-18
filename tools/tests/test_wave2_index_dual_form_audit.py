"""Tests for ``tools/wave2-index-dual-form-audit.py``.

All fixtures here are synthesised in temp dirs and explicitly marked
``synthetic_fixture: true`` in the record bodies (per operator-codified
validation discipline). The tool's behaviour against the LIVE corpus
is validated separately by the ``make wave2-index-dual-form-audit``
Makefile target; this file exercises the audit logic in isolation
with controlled fixtures so failure modes are pinpointable.
"""
from __future__ import annotations

import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path
from typing import Optional

REPO_ROOT = Path(__file__).resolve().parents[2]
TOOL_PATH = REPO_ROOT / "tools" / "wave2-index-dual-form-audit.py"


def _load_tool():
    spec = importlib.util.spec_from_file_location(
        "_wave2_index_dual_form_audit", str(TOOL_PATH)
    )
    mod = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(mod)
    return mod


tool = _load_tool()


def _write_yaml(path: Path, record_id: str, *, synthetic: bool = True) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "schema_version: auditooor.hackerman_record.v1\n"
        f"record_id: {record_id}\n"
        f"synthetic_fixture: {'true' if synthetic else 'false'}\n",
        encoding="utf-8",
    )


def _write_json(path: Path, record_id: str, *, synthetic: bool = True) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "schema_version": "auditooor.hackerman_record.v1",
        "record_id": record_id,
        "synthetic_fixture": synthetic,
    }
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def _write_index(path: Path, rows: list) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r) + "\n")


def _make_workspace(root: Path) -> Path:
    """Create the bare audit/corpus_tags/{tags,index} layout under ``root``."""
    (root / "audit" / "corpus_tags" / "tags").mkdir(parents=True, exist_ok=True)
    (root / "audit" / "corpus_tags" / "index").mkdir(parents=True, exist_ok=True)
    return root


class WaveIndexDualFormAuditTests(unittest.TestCase):
    """Wave-2 dual-form audit fixtures (synthetic_fixture: true)."""

    def test_pass_no_dual_form(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _make_workspace(Path(td))
            tags = ws / "audit" / "corpus_tags" / "tags"
            # 3 single-form yaml records in distinct prefixes
            _write_yaml(tags / "amm_yield" / "rec1" / "record.yaml", "amm-yield-lst:rec1:hashA")
            _write_yaml(tags / "code4rena" / "rec2" / "record.yaml", "code4rena:rec2:hashB")
            _write_yaml(tags / "sherlock" / "rec3" / "record.yaml", "sherlock:rec3:hashC")
            # Empty additive indexes
            for idx in tool.ADDITIVE_INDEXES:
                _write_index(ws / "audit" / "corpus_tags" / "index" / f"{idx}.jsonl", [])
            pack = tool.audit(ws)
        self.assertEqual(pack["overall_status"], "PASS", pack["summary"])
        self.assertEqual(pack["dual_form_record_count"], 0)
        self.assertEqual(pack["affected_prefixes"], [])

    def test_warning_dual_form_consistent(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _make_workspace(Path(td))
            tags = ws / "audit" / "corpus_tags" / "tags"
            rid = "bridge-incident:syntheticA:deadbeef0000"
            _write_yaml(tags / "bridge_incidents" / "syntheticA" / "record.yaml", rid)
            _write_json(tags / "bridge_incidents" / "syntheticA" / "record.json", rid)
            _write_yaml(
                tags / "sherlock" / "rec2" / "record.yaml",
                "sherlock:rec2:hash22",
            )
            # Index with 1 row per record_id (correctly deduplicated)
            for idx in tool.ADDITIVE_INDEXES:
                _write_index(
                    ws / "audit" / "corpus_tags" / "index" / f"{idx}.jsonl",
                    [
                        {"record_id": rid, "tag_file": "record.yaml", "key": "k"},
                        {"record_id": "sherlock:rec2:hash22", "tag_file": "record.yaml", "key": "k"},
                    ],
                )
            pack = tool.audit(ws)
        self.assertEqual(pack["overall_status"], "WARNING", pack["summary"])
        self.assertEqual(pack["dual_form_record_count"], 1)
        self.assertIn("bridge-incident", pack["affected_prefixes"])
        self.assertEqual(pack["prefix_breakdown"]["bridge-incident"]["inconsistent_record_ids"], 0)
        # Indexes are NOT inflated (1 row per record_id == unique count)
        for info in pack["index_inflation_per_index"].values():
            self.assertFalse(info["inflated"], info)

    def test_fail_dual_form_inconsistent(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _make_workspace(Path(td))
            tags = ws / "audit" / "corpus_tags" / "tags"
            # Yaml claims X; json claims Y. Both legitimate-looking records.
            _write_yaml(
                tags / "mev_exploits" / "syntheticDivergent" / "record.yaml",
                "mev-exploits:divergent:XAAAA00000",
            )
            _write_json(
                tags / "mev_exploits" / "syntheticDivergent" / "record.json",
                "mev-exploits:divergent:YBBBB11111",
            )
            for idx in tool.ADDITIVE_INDEXES:
                _write_index(ws / "audit" / "corpus_tags" / "index" / f"{idx}.jsonl", [])
            pack = tool.audit(ws)
        self.assertEqual(pack["overall_status"], "FAIL", pack["summary"])
        self.assertEqual(len(pack["inconsistent_examples"]), 1)
        ex = pack["inconsistent_examples"][0]
        self.assertNotEqual(ex["yaml_record_id"], ex["json_record_id"])
        # Prefix-level counter must record the inconsistency
        pfx_st = pack["prefix_breakdown"]["mev-exploits"]
        self.assertEqual(pfx_st["inconsistent_record_ids"], 1)

    def test_index_inflation_detected(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _make_workspace(Path(td))
            tags = ws / "audit" / "corpus_tags" / "tags"
            rid = "zkbugs:syntheticC:cafebabe0000"
            _write_yaml(tags / "zk" / "synC" / "record.yaml", rid)
            _write_json(tags / "zk" / "synC" / "record.json", rid)
            # Synthetic inflated index: 2 rows for the same record_id
            for idx in tool.ADDITIVE_INDEXES:
                _write_index(
                    ws / "audit" / "corpus_tags" / "index" / f"{idx}.jsonl",
                    [
                        {"record_id": rid, "tag_file": "record.yaml", "key": "k"},
                        {"record_id": rid, "tag_file": "record.json", "key": "k"},
                    ],
                )
            pack = tool.audit(ws)
        # Inflation present in every additive index
        for idx in tool.ADDITIVE_INDEXES:
            info = pack["index_inflation_per_index"][idx]
            self.assertEqual(info["current_row_count"], 2, idx)
            self.assertEqual(info["unique_record_id_count"], 1, idx)
            self.assertEqual(info["inflated_by"], 1, idx)
            self.assertTrue(info["inflated"], idx)
        self.assertEqual(pack["overall_status"], "WARNING")

    def test_excluded_subtree_skipped(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _make_workspace(Path(td))
            tags = ws / "audit" / "corpus_tags" / "tags"
            # Records inside _QUARANTINE_X and _deprecated must NOT count
            _write_yaml(
                tags / "_QUARANTINE_FABRICATED" / "drop" / "record.yaml",
                "quarantine:drop:zzz",
            )
            _write_json(
                tags / "_QUARANTINE_FABRICATED" / "drop" / "record.json",
                "quarantine:drop:zzz",
            )
            _write_yaml(
                tags / "_deprecated" / "old" / "record.yaml",
                "deprecated:old:yyy",
            )
            # One real single-form record outside the excluded subtrees
            _write_yaml(
                tags / "sherlock" / "real1" / "record.yaml",
                "sherlock:real1:realhash",
            )
            for idx in tool.ADDITIVE_INDEXES:
                _write_index(ws / "audit" / "corpus_tags" / "index" / f"{idx}.jsonl", [])
            pack = tool.audit(ws)
        # quarantine + deprecated subtrees must be absent from prefix_breakdown
        self.assertNotIn("quarantine", pack["prefix_breakdown"])
        self.assertNotIn("deprecated", pack["prefix_breakdown"])
        self.assertIn("sherlock", pack["prefix_breakdown"])
        # The excluded dirs must surface in skipped_subtrees
        skipped_str = "\n".join(pack["skipped_subtrees"])
        self.assertIn("_QUARANTINE_FABRICATED", skipped_str)
        self.assertIn("_deprecated", skipped_str)
        self.assertEqual(pack["overall_status"], "PASS")

    def test_emit_corrected_indexes(self):
        with tempfile.TemporaryDirectory() as td:
            ws = _make_workspace(Path(td))
            tags = ws / "audit" / "corpus_tags" / "tags"
            rid = "zkbugs:dedupe:hash1234"
            _write_yaml(tags / "zk" / "dedupe" / "record.yaml", rid)
            _write_json(tags / "zk" / "dedupe" / "record.json", rid)
            for idx in tool.ADDITIVE_INDEXES:
                _write_index(
                    ws / "audit" / "corpus_tags" / "index" / f"{idx}.jsonl",
                    [
                        {"record_id": rid, "tag_file": "record.yaml", "key": "k"},
                        {"record_id": rid, "tag_file": "record.json", "key": "k"},
                    ],
                )
            out_dir = Path(td) / "corrected"
            pack = tool.audit(ws, emit_corrected_dir=out_dir)
            # The corrected dir should contain exactly one row per index
            for idx in tool.ADDITIVE_INDEXES:
                corrected = out_dir / f"{idx}.jsonl"
                self.assertTrue(corrected.exists(), idx)
                rows = [
                    json.loads(line)
                    for line in corrected.read_text(encoding="utf-8").splitlines()
                    if line.strip()
                ]
                self.assertEqual(len(rows), 1, idx)
                self.assertEqual(rows[0]["record_id"], rid)
            # Live index dir must NOT have been mutated
            live_idx = ws / "audit" / "corpus_tags" / "index" / "by_cve_id.jsonl"
            live_rows = [
                line
                for line in live_idx.read_text(encoding="utf-8").splitlines()
                if line.strip()
            ]
            self.assertEqual(len(live_rows), 2)
        self.assertEqual(pack["overall_status"], "WARNING")


if __name__ == "__main__":
    unittest.main()
