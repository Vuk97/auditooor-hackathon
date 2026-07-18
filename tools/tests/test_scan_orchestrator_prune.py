"""Regression: workspace-scan-orchestrator.detect_languages must PRUNE heavy /
regenerable dirs (target/, .git/, node_modules/, ...) at walk-time, so a
workspace carrying build artifacts (near-intents: 3.3 GB of Rust target/) does
not I/O-stall the scan orchestrator at startup (the 0%-CPU hang before its first
log line)."""
import importlib.util
import sys
import time
from pathlib import Path

_MOD = Path(__file__).resolve().parents[1] / "workspace-scan-orchestrator.py"
_spec = importlib.util.spec_from_file_location("wso", _MOD)
wso = importlib.util.module_from_spec(_spec)
sys.modules["wso"] = wso
_spec.loader.exec_module(wso)


def _w(p: Path, body="// x\n"):
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(body, encoding="utf-8")


def test_target_dir_is_pruned_not_detected(tmp_path):
    ws = tmp_path / "ws"
    # ONLY a .rs under target/ -> must NOT be detected (target pruned)
    _w(ws / "target" / "build_artifact.rs", "fn x(){}")
    langs = wso.detect_languages(ws)
    assert "rs" not in langs, "target/ must be pruned (build artifact, not source)"


def test_real_source_is_detected(tmp_path):
    ws = tmp_path / "ws"
    _w(ws / "crates" / "core" / "lib.rs", "pub fn f(){}")
    _w(ws / "contracts" / "A.sol", "contract A{}")
    langs = wso.detect_languages(ws)
    assert "rs" in langs and "sol" in langs


def test_git_and_node_modules_pruned(tmp_path):
    ws = tmp_path / "ws"
    _w(ws / ".git" / "hooks" / "x.rs", "fn g(){}")
    _w(ws / "node_modules" / "pkg" / "B.sol", "contract B{}")
    langs = wso.detect_languages(ws)
    assert "rs" not in langs
    assert "sol" not in langs


def test_detection_is_fast_with_many_artifact_files(tmp_path):
    ws = tmp_path / "ws"
    _w(ws / "src" / "main.rs", "fn main(){}")
    # simulate a build-artifact blowup under target/ (pruned) - must stay fast
    for i in range(300):
        _w(ws / "target" / "debug" / f"dep_{i}.rs", "// gen\n")
    t = time.time()
    langs = wso.detect_languages(ws)
    elapsed = time.time() - t
    assert "rs" in langs
    assert elapsed < 3, f"detection walked the pruned tree: {elapsed:.2f}s"
