"""Regression: the scan-orchestrator stage timeout (engage._solidity_scan_timeout)
must scale by TOTAL source files (.sol + .rs + .go), not .sol alone - else a
Rust-heavy workspace (near-intents: 573 .rs, 18 .sol) sits at the 1200s floor and
the stage wrapper kills the orchestrator mid-rust-detect (whose internal per-tool
budget is 1800s). The count must also PRUNE target/ etc. so it stays fast."""
import importlib.util
import sys
from pathlib import Path

_TOOLS = Path(__file__).resolve().parents[1]
if str(_TOOLS) not in sys.path:
    sys.path.insert(0, str(_TOOLS))
_spec = importlib.util.spec_from_file_location("engage_for_test", _TOOLS / "engage.py")
eng = importlib.util.module_from_spec(_spec)
sys.modules["engage_for_test"] = eng
try:
    _spec.loader.exec_module(eng)
except SystemExit:
    pass


def _mk(ws, rel, body="x\n"):
    p = ws / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(body, encoding="utf-8")


def test_small_workspace_uses_floor(tmp_path):
    ws = tmp_path / "small"
    for i in range(5):
        _mk(ws, f"contracts/C{i}.sol", "contract C{}{{}}\n".format(i))
    assert eng._solidity_scan_timeout(ws) == eng.SCAN_TIMEOUT  # 1200 floor


def test_rust_heavy_scales_above_floor(tmp_path):
    ws = tmp_path / "rusty"
    for i in range(200):  # 200 .rs -> must scale well above the 1200 floor
        _mk(ws, f"crates/c{i}/src/lib.rs", "pub fn f(){}\n")
    to = eng._solidity_scan_timeout(ws)
    assert to > eng.SCAN_TIMEOUT, f"rust-heavy ws must scale past floor, got {to}"
    assert to >= 1900, f"must exceed the 1800s internal tool budget, got {to}"


def test_target_dir_does_not_inflate_count(tmp_path):
    ws = tmp_path / "withtarget"
    _mk(ws, "crates/c/src/lib.rs", "pub fn f(){}\n")  # 1 real source
    for i in range(500):  # build artifacts under target/ must be pruned
        _mk(ws, f"target/debug/gen_{i}.rs", "// gen\n")
    # only 1 real source -> stays at the floor (target/ pruned, not counted)
    assert eng._solidity_scan_timeout(ws) == eng.SCAN_TIMEOUT


def test_env_override_wins(tmp_path, monkeypatch):
    monkeypatch.setenv("AUDITOOOR_SCAN_TIMEOUT", "777")
    assert eng._solidity_scan_timeout(tmp_path) == 777
