#!/usr/bin/env python3
"""B-merge + F-reader unit tests for dataflow_schema.

merge_write (language-scoped replace):
  - keeps OTHER-language rows, replaces THIS arm's rows (idempotent re-run).
  - an empty new-records list still PURGES this arm's stale rows.
  - corrupt prior sidecar -> rewrite from scratch (no crash).
  - byte-identical to write_jsonl when no other-language rows exist (single-language).

read_paths (canonical reader):
  - skips degraded rows by default; returns them with skip_degraded=False.
  - languages= filter restricts to an allow-list.
  - absent file -> [] (no crash).
  - schema-invalid rows are dropped.
"""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
_spec = importlib.util.spec_from_file_location("dfs_merge_test", REPO / "tools" / "dataflow_schema.py")
dfs = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(dfs)


def _rec(lang, pid, degraded=False):
    r = dfs.new_path(
        path_id=pid, language=lang, direction="backward", engine="t",
        source={"kind": "param", "fn": "f", "var": "v", "file": "a", "line": 1},
        sink={"kind": "call", "callee": "transfer", "arg_pos": 0, "fn": "g", "file": "a", "line": 2},
        hops=[{"from_var": "v", "to_var": "v", "fn": "f", "via": "internal_call",
               "file": "a", "line": 1, "ir": "", "guarded": False}],
        confidence="semantic-ssa", degraded=degraded,
    )
    return r


def _read(path):
    return [json.loads(l) for l in Path(path).read_text().splitlines() if l.strip()]


def test_merge_keeps_other_languages(tmp_path):
    p = tmp_path / "df.jsonl"
    # Go arm writes first
    dfs.merge_write(str(p), [_rec("go", "go-0"), _rec("go", "go-1")], "go")
    # Solidity arm writes next - MUST NOT delete go rows (the truncation bug)
    n = dfs.merge_write(str(p), [_rec("solidity", "sol-0")], "solidity")
    assert n == 1
    rows = _read(p)
    langs = sorted(r["language"] for r in rows)
    assert langs == ["go", "go", "solidity"], langs


def test_merge_idempotent_replaces_own_rows(tmp_path):
    p = tmp_path / "df.jsonl"
    dfs.merge_write(str(p), [_rec("go", "go-0"), _rec("solidity", "sol-0")], "go")
    # re-run the go arm: its prior go rows are dropped, new appended; sol kept
    dfs.merge_write(str(p), [_rec("go", "go-NEW")], "go")
    rows = _read(p)
    ids = sorted(r["path_id"] for r in rows)
    assert ids == ["go-NEW", "sol-0"], ids


def test_merge_empty_records_purges_own_stale(tmp_path):
    p = tmp_path / "df.jsonl"
    dfs.merge_write(str(p), [_rec("rust", "r-0"), _rec("go", "g-0")], "rust")
    # re-run rust with ZERO flows -> rust rows removed, go preserved
    n = dfs.merge_write(str(p), [], "rust")
    assert n == 0
    rows = _read(p)
    assert [r["language"] for r in rows] == ["go"], rows


def test_merge_corrupt_sidecar_rewrites(tmp_path):
    p = tmp_path / "df.jsonl"
    p.write_text("not json at all\n{broken\n")
    n = dfs.merge_write(str(p), [_rec("go", "g-0")], "go")
    assert n == 1
    rows = _read(p)
    assert [r["path_id"] for r in rows] == ["g-0"]


def test_merge_single_language_byte_identical_to_write_jsonl(tmp_path):
    recs = [_rec("solidity", "s0"), _rec("solidity", "s1")]
    a = tmp_path / "merge.jsonl"
    b = tmp_path / "trunc.jsonl"
    dfs.merge_write(str(a), recs, "solidity")  # no prior rows
    dfs.write_jsonl(str(b), recs)
    assert a.read_bytes() == b.read_bytes()


def test_read_paths_skips_degraded_by_default(tmp_path):
    ws = tmp_path
    (ws / ".auditooor").mkdir()
    p = ws / ".auditooor" / "dataflow_paths.jsonl"
    dfs.write_jsonl(str(p), [_rec("go", "ok"), _rec("go", "bad", degraded=True)])
    got = dfs.read_paths(ws)
    assert [r["path_id"] for r in got] == ["ok"]
    got_all = dfs.read_paths(ws, skip_degraded=False)
    assert sorted(r["path_id"] for r in got_all) == ["bad", "ok"]


def test_read_paths_language_filter(tmp_path):
    ws = tmp_path
    (ws / ".auditooor").mkdir()
    p = ws / ".auditooor" / "dataflow_paths.jsonl"
    dfs.write_jsonl(str(p), [_rec("go", "g"), _rec("solidity", "s"), _rec("rust", "r")])
    got = dfs.read_paths(ws, languages=["go", "rust"])
    assert sorted(r["language"] for r in got) == ["go", "rust"]


def test_read_paths_absent_file_returns_empty(tmp_path):
    assert dfs.read_paths(tmp_path) == []


def test_read_paths_drops_invalid_rows(tmp_path):
    ws = tmp_path
    (ws / ".auditooor").mkdir()
    p = ws / ".auditooor" / "dataflow_paths.jsonl"
    p.write_text(json.dumps(_rec("go", "good")) + "\n" + json.dumps({"schema": "wrong"}) + "\n")
    got = dfs.read_paths(ws)
    assert [r["path_id"] for r in got] == ["good"]


if __name__ == "__main__":
    import pytest
    raise SystemExit(pytest.main([__file__, "-q"]))


def test_merge_write_scope_prefix_preserves_out_of_scope_same_language(tmp_path=None):
    """A TARGETED re-slice (scope_prefix) must replace ONLY this language's rows
    UNDER the scope and PRESERVE same-language rows outside it. Without this, a
    `dataflow-slice.py --target <subdir>` partial re-slice silently wiped the
    other in-scope projects' rows (polygon: re-slicing sPOL dropped pos-contracts/
    agglayer/pol-token from the shared sidecar)."""
    import tempfile, os, json as _j
    d = Path(tempfile.mkdtemp())
    p = d / "dataflow_paths.jsonl"
    # prior: 2 solidity rows in projectA + 1 in projectB + 1 go row
    prior = [
        {"language": "solidity", "path_id": "a1", "source": {"file": "/ws/src/projectA/X.sol"}, "sink": {"file": "/ws/src/projectA/X.sol"}},
        {"language": "solidity", "path_id": "a2", "source": {"file": "/ws/src/projectA/Y.sol"}, "sink": {"file": "/ws/src/projectA/Y.sol"}},
        {"language": "solidity", "path_id": "b1", "source": {"file": "/ws/src/projectB/Z.sol"}, "sink": {"file": "/ws/src/projectB/Z.sol"}},
        {"language": "go", "path_id": "g1", "source": {"file": "/ws/src/mod/a.go"}, "sink": {"file": "/ws/src/mod/a.go"}},
    ]
    p.write_text("\n".join(_j.dumps(r) for r in prior) + "\n", encoding="utf-8")
    # targeted re-slice of projectA only -> 1 new solidity row under projectA
    new = [{"language": "solidity", "path_id": "a_new", "source": {"file": "/ws/src/projectA/X.sol"}, "sink": {"file": "/ws/src/projectA/X.sol"}}]
    dfs.merge_write(str(p), new, "solidity", scope_prefix="/ws/src/projectA")
    rows = [_j.loads(l) for l in p.read_text().splitlines() if l.strip()]
    ids = {r["path_id"] for r in rows}
    assert "b1" in ids, "out-of-scope same-language row (projectB) must be PRESERVED"
    assert "g1" in ids, "other-language row (go) must be preserved"
    assert "a_new" in ids, "the new targeted row must be written"
    assert "a1" not in ids and "a2" not in ids, "in-scope prior rows (projectA) must be replaced"


def test_merge_write_no_scope_replaces_whole_language():
    """Full-ws run (no scope_prefix) keeps the legacy replace-all-language behavior."""
    import tempfile, json as _j
    d = Path(tempfile.mkdtemp())
    p = d / "dataflow_paths.jsonl"
    prior = [
        {"language": "solidity", "path_id": "a1", "source": {"file": "/ws/src/projectA/X.sol"}, "sink": {"file": "/ws/src/projectA/X.sol"}},
        {"language": "solidity", "path_id": "b1", "source": {"file": "/ws/src/projectB/Z.sol"}, "sink": {"file": "/ws/src/projectB/Z.sol"}},
    ]
    p.write_text("\n".join(_j.dumps(r) for r in prior) + "\n", encoding="utf-8")
    dfs.merge_write(str(p), [{"language": "solidity", "path_id": "full"}], "solidity")
    ids = {_j.loads(l)["path_id"] for l in p.read_text().splitlines() if l.strip()}
    assert ids == {"full"}, "no scope_prefix must replace ALL of the language"
