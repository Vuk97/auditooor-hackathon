"""Regression: rust-detect must bound each detector.run() with a per-call
wall-clock cap so ONE pathological (detector, file) pair cannot hang the whole
scan (near-intents: a single detector spun at ~93% CPU for 18+ min, forcing the
orchestrator's wholesale 1800s kill which discards every other detector's
results). _run_detector_call applies a SIGALRM cap and raises _DetectorTimeout
on overrun; a normal/fast call returns its hits unchanged."""
import importlib.util
import sys
import time
from pathlib import Path

import pytest

_TOOLS = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("rust_detect_mod", _TOOLS / "rust-detect.py")
rd = importlib.util.module_from_spec(_spec)
sys.modules["rust_detect_mod"] = rd
_spec.loader.exec_module(rd)


def test_fast_call_returns_hits():
    out = rd._run_detector_call(lambda: [{"severity": "info", "line": 1}], 30)
    assert out == [{"severity": "info", "line": 1}]


def test_none_result_normalizes_to_empty_list():
    assert rd._run_detector_call(lambda: None, 30) == []


def test_slow_call_times_out():
    # sleep is interrupted by SIGALRM -> _DetectorTimeout within ~1s, not 10s
    t0 = time.monotonic()
    with pytest.raises(rd._DetectorTimeout):
        rd._run_detector_call(lambda: time.sleep(10), 1)
    assert time.monotonic() - t0 < 5, "cap must fire well before the 10s sleep completes"


def test_zero_timeout_disables_cap():
    # timeout_s <= 0 => no alarm armed; a quick call still returns normally
    assert rd._run_detector_call(lambda: [{"x": 1}], 0) == [{"x": 1}]


def test_other_exception_propagates():
    # non-timeout errors must propagate so the caller's crash handler logs them
    with pytest.raises(ValueError):
        rd._run_detector_call(lambda: (_ for _ in ()).throw(ValueError("boom")), 30)
