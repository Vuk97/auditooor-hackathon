#!/usr/bin/env python3
"""Guard test: git-mining ETL discovers workspace mines (the severed-feeder fix).

Before the fix, discover_reports globbed ONE dir for ONE prefix, so per-workspace
miner output (.auditooor/git_commits_mining_*.json and mining_rounds/*/
<slug>_<lang>_git_commits_mining.json) never reached the corpus. This proves rglob
+ dual-pattern discovery finds both shapes.
"""
import importlib.util
import json
import os
import tempfile
from pathlib import Path

_HERE = os.path.dirname(os.path.abspath(__file__))
_MOD = os.path.join(_HERE, "..", "hackerman-etl-from-git-mining.py")
spec = importlib.util.spec_from_file_location("git_mining_etl", _MOD)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


def test_discovers_both_workspace_mine_shapes():
    with tempfile.TemporaryDirectory() as td:
        ws = Path(td)
        (ws / ".auditooor").mkdir()
        (ws / "mining_rounds" / "2026-06-18-bidirectional-commit-mining").mkdir(parents=True)
        a = ws / ".auditooor" / "git_commits_mining_provlabs_vault.json"
        b = ws / "mining_rounds" / "2026-06-18-bidirectional-commit-mining" / "nuva_solidity_git_commits_mining.json"
        for p in (a, b):
            p.write_text(json.dumps({"commits": [], "shaped_commits_index": []}))
        found = m.discover_reports(ws)
        assert a in found, f"MCP-form mine not discovered: {found}"
        assert b in found, f"pipeline-form mine not discovered: {found}"
        assert len(found) == 2


def test_no_duplicate_when_both_patterns_match():
    with tempfile.TemporaryDirectory() as td:
        ws = Path(td)
        # a file matching both globs must appear once
        p = ws / "git_commits_mining_x_git_commits_mining.json"
        p.write_text("{}")
        found = m.discover_reports(ws)
        assert found.count(p) == 1


if __name__ == "__main__":
    import traceback
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    failed = 0
    for fn in fns:
        try:
            fn(); print(f"ok   {fn.__name__}")
        except Exception:
            failed += 1; print(f"FAIL {fn.__name__}"); traceback.print_exc()
    print("ok" if not failed else f"{failed} FAILED")
    raise SystemExit(1 if failed else 0)
