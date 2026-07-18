"""Guard: S9-depth-crossws - the depth-ledger ETL banks genuine gaps cross-workspace
AND banks ruled-out (gap_found==false) negative-space reasons as DEAD-ENDS.

Load-bearing assertions:
 (a) a gap_found=True negative_space row AND a guard-asymmetry sibling row each yield a
     CANDIDATE hackerman corpus record (so cross-workspace banking actually happens);
 (b) learning-loop B2: a gap_found=False negative_space row WITH a substantive
     ruled_out_reason + (guard_id or file_line) is NOT discarded - it banks as exactly
     one DEAD-END record (auditooor.known_dead_end.v1, verdict="ruled-out") into
     reports/known_dead_ends.jsonl (NOT into the candidate corpus); reason non-empty;
 (c) anti-stub: a gap_found=False row with NO ruled_out_reason is dropped (no signal).

KDE_PATH is redirected to a temp file via AUDITOOOR_KDE_PATH so the real corpus is
untouched. The module is reloaded per-test so the env override is read at import time.

Fails before the dead-end banking exists / if the anti-stub filter regresses; passes after.
"""
import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "hackerman-etl-from-depth-ledgers.py"


def _load():
    spec = importlib.util.spec_from_file_location("depth_etl", TOOL)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class TestDepthLedgerEtl(unittest.TestCase):
    def _make_ws(self, base: Path, include_reasonless_false: bool = False) -> Path:
        ws = base / "sample-ws"
        aud = ws / ".auditooor"
        aud.mkdir(parents=True)
        neg = [
            {"guard_id": "NS-aaa", "file_line": "src/Vault.sol:42", "gap_found": True,
             "ruled_out_reason": "withdraw lacks the paused check present on deposit",
             "schema": "auditooor.negative_space_gap.v1"},
            {"guard_id": "NS-bbb", "file_line": "src/Vault.sol:99", "gap_found": False,
             "ruled_out_reason": "trait decl, no body - guard not applicable",
             "code_excerpt": "fn foo();", "decided_by": "sonnet",
             "schema": "auditooor.negative_space_gap.v1"},
        ]
        if include_reasonless_false:
            neg.append(
                {"guard_id": "NS-ddd", "file_line": "src/Vault.sol:120",
                 "gap_found": False, "ruled_out_reason": "",
                 "schema": "auditooor.negative_space_gap.v1"})
        (aud / "negative_space_gaps.jsonl").write_text(
            "\n".join(json.dumps(r) for r in neg), encoding="utf-8")
        sib = [
            {"candidate_gap_id": "ASYM-ccc", "file_lines": ["src/A.sol:10", "src/B.sol:20"],
             "guard_on_a_missing_on_b": ["onlyOwner"], "guard_on_b_missing_on_a": [],
             "pair": "deposit~withdraw", "pair_kind": "variant-arm",
             "shared_invariant_hint": "both arms must enforce onlyOwner",
             "schema": "auditooor.sibling_path_guard_diff.v1"},
        ]
        (aud / "sibling_guard_asymmetries.jsonl").write_text(
            "\n".join(json.dumps(r) for r in sib), encoding="utf-8")
        return ws

    def test_banks_candidates_and_dead_ends(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            os.environ["AUDITOOOR_KDE_PATH"] = str(base / "known_dead_ends.jsonl")
            try:
                mod = _load()
                ws = self._make_ws(base)
                out = base / "out"
                written = mod.process_workspace(ws, out, dry_run=False)

                candidates = [w for w in written
                              if w.get("schema_version") != mod.KDE_SCHEMA]
                dead_ends = [w for w in written
                             if w.get("schema_version") == mod.KDE_SCHEMA]

                # 2 candidates: 1 gap_found negspace + 1 sibling asymmetry.
                self.assertEqual(len(candidates), 2,
                                 f"expected 2 candidate records, got {candidates}")
                classes = {w["bug_class"] for w in candidates}
                self.assertIn("missing-guard-negative-space", classes)
                self.assertIn("guard-asymmetry-sibling-path", classes)

                # exactly 1 dead-end from the gap_found=False(+reason) negspace row.
                self.assertEqual(len(dead_ends), 1,
                                 f"expected 1 dead-end, got {dead_ends}")
                de = dead_ends[0]
                self.assertEqual(de["schema_version"], "auditooor.known_dead_end.v1")
                self.assertEqual(de["verdict"], "ruled-out")
                self.assertTrue(de["kill_reason"].strip(),
                                "dead-end reason must be non-empty")
                self.assertTrue(de["dead_end_id"])
                self.assertEqual(de["workspace"], "sample-ws")
                self.assertEqual(de["workspace_path"], str(ws))
                self.assertEqual(de["file_line"], "src/Vault.sol:99")
                self.assertEqual(de["decided_by"], "sonnet")

                # candidate corpus files written; dead-end NOT among them.
                files = list(out.glob("*.yaml"))
                self.assertEqual(len(files), 2)

                # dead-end persisted to the (redirected) KDE jsonl.
                kde_lines = [l for l in mod.KDE_PATH.read_text().splitlines() if l.strip()]
                self.assertEqual(len(kde_lines), 1)
                self.assertEqual(json.loads(kde_lines[0])["verdict"], "ruled-out")
            finally:
                os.environ.pop("AUDITOOOR_KDE_PATH", None)

    def test_reasonless_false_row_dropped(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            os.environ["AUDITOOOR_KDE_PATH"] = str(base / "known_dead_ends.jsonl")
            try:
                mod = _load()
                ws = self._make_ws(base, include_reasonless_false=True)
                out = base / "out"
                written = mod.process_workspace(ws, out, dry_run=False)
                dead_ends = [w for w in written
                             if w.get("schema_version") == mod.KDE_SCHEMA]
                # still exactly 1 dead-end: the reasonless false row is dropped.
                self.assertEqual(len(dead_ends), 1,
                                 f"reasonless false row must be dropped, got {dead_ends}")
            finally:
                os.environ.pop("AUDITOOOR_KDE_PATH", None)

    def test_dead_end_idempotent(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            os.environ["AUDITOOOR_KDE_PATH"] = str(base / "known_dead_ends.jsonl")
            try:
                mod = _load()
                ws = self._make_ws(base)
                out = base / "out"
                mod.process_workspace(ws, out, dry_run=False)
                mod.process_workspace(ws, out, dry_run=False)  # re-run
                kde_lines = [l for l in mod.KDE_PATH.read_text().splitlines() if l.strip()]
                self.assertEqual(len(kde_lines), 1,
                                 "re-run must not duplicate the dead-end record")
            finally:
                os.environ.pop("AUDITOOOR_KDE_PATH", None)

    def test_dry_run_writes_nothing(self):
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            os.environ["AUDITOOOR_KDE_PATH"] = str(base / "known_dead_ends.jsonl")
            try:
                mod = _load()
                ws = self._make_ws(base)
                out = base / "out"
                written = mod.process_workspace(ws, out, dry_run=True)
                candidates = [w for w in written
                              if w.get("schema_version") != mod.KDE_SCHEMA]
                self.assertEqual(len(candidates), 2)
                self.assertFalse(out.exists() and list(out.glob("*.yaml")))
                self.assertFalse(mod.KDE_PATH.exists())
            finally:
                os.environ.pop("AUDITOOOR_KDE_PATH", None)


if __name__ == "__main__":
    unittest.main()
