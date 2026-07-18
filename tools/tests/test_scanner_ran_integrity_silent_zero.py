"""Guard test for scanner-ran-integrity.py (silent-0 false-green monitor).

Reproduces the optimism case: Slither records status=ok/reason=completed/rc=0 with
an EMPTY stdout log and 0 findings (it never compiled the tree) - this MUST be
classified silent-skip, not trusted as "scanned clean". A scanner with real output
or a real files-scanned count MUST classify as ran.
"""
import importlib.util
import json
from pathlib import Path

_TOOL = Path(__file__).resolve().parent.parent / "scanner-ran-integrity.py"
_spec = importlib.util.spec_from_file_location("scanner_ran_integrity", _TOOL)
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)


def _mk_ws(tmp_path: Path) -> Path:
    ws = tmp_path / "ws"
    sda = ws / ".auditooor" / "solidity-deep-audit"
    sda.mkdir(parents=True)
    # silent slither: completed/rc=0 but empty stdout log + no findings
    empty_log = sda / "slither-resilient.stdout.log"
    empty_log.write_text("")  # 0 bytes
    (sda / "slither-resilient.json").write_text(json.dumps({
        "status": "ok", "reason": "completed", "returncode": 0,
        "stdout_log": str(empty_log), "stderr_log": str(sda / "slither-resilient.stderr.log"),
    }))
    # honest prereq-skip (rc=2)
    (sda / "wave14-slither-ast.json").write_text(json.dumps({
        "status": "ok", "reason": "PREREQ NOTICE: fix compile prerequisites", "returncode": 2,
    }))
    # genuine semgrep run (non-empty tail)
    (sda / "semgrep-solidity.json").write_text(json.dumps({
        "status": "ok", "reason": "completed", "returncode": 0,
        "stdout_tail": "[semgrep] status=rc_7 findings=0", "stderr_tail": "",
    }))
    return ws


def test_silent_slither_flagged_as_false_green(tmp_path):
    ws = _mk_ws(tmp_path)
    res = _mod.analyze(ws)
    assert res["verdict"] == "fail-silent-scanner-false-green"
    silent_engines = {s["engine"] for s in res["silent_skips"]}
    assert "slither-resilient" in silent_engines, res
    # the honest prereq-skip must NOT be a silent-skip (it is errored/honest)
    assert "wave14-slither-ast" not in silent_engines


def test_genuine_scanner_is_ran_not_silent(tmp_path):
    ws = _mk_ws(tmp_path)
    res = _mod.analyze(ws)
    sol = {e["engine"]: e["verdict"] for e in res["arms"]["solidity"]}
    assert sol["semgrep-solidity"] == "ran"
    assert sol["slither-resilient"] == "silent-skip"
    assert sol["wave14-slither-ast"] == "errored"


def test_pattern_scanner_files_scanned_counts_as_ran(tmp_path):
    ws = tmp_path / "ws2"
    (ws / ".auditooor").mkdir(parents=True)
    (ws / ".auditooor" / "go_findings.json").write_text(json.dumps({
        "go_files_scanned": 2686,
        "patterns": {"go.x": {"hit_count": 3}, "go.y": {"hit_count": 0}},
    }))
    res = _mod.analyze(ws)
    go = res["arms"]["go"][0]
    assert go["verdict"] == "ran", go
    assert res["verdict"] == "pass-scanners-honest"


def test_pattern_scanner_zero_files_is_silent(tmp_path):
    ws = tmp_path / "ws3"
    (ws / ".auditooor").mkdir(parents=True)
    (ws / ".auditooor" / "go_findings.json").write_text(json.dumps({
        "go_files_scanned": 0,
        "patterns": {"go.x": {"hit_count": 0}},
    }))
    res = _mod.analyze(ws)
    assert res["arms"]["go"][0]["verdict"] == "silent-skip", res
