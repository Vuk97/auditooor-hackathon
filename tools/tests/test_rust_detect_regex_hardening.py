"""Regression: rust-detect must bound catastrophic regex backtracking in the
auto-generated _INDICATOR_PATTERNS template detectors. The stdlib `re` engine
holds the GIL during matching, so the SIGALRM per-call cap CANNOT interrupt a
pattern like 'for.*in.*ids_and_amounts.*extend_from_slice' applied with DOTALL
to a large source (observed: 99% CPU, never returns on the 8008-line mpc
lib.rs). _harden_template_detector recompiles such patterns with the `regex`
module under a per-call timeout that interrupts at the C level (raises
TimeoutError), so the detector is skipped for that file instead of hanging."""
import importlib.util
import sys
import time
from pathlib import Path

import pytest

_TOOLS = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("rust_detect_rh", _TOOLS / "rust-detect.py")
rd = importlib.util.module_from_spec(_spec)
sys.modules["rust_detect_rh"] = rd
_spec.loader.exec_module(rd)

regex = pytest.importorskip("regex")

# Catastrophic on any sizeable text with no match: common short literals +
# multiple wildcards + DOTALL => exponential backtracking in stdlib re.
_CATASTROPHIC = "for.*in.*ids_and_amounts.*extend_from_slice"
_BIG_TEXT = ("for x in y { let z = a.foo(); } // in foo bar baz\n" * 4000)


class _FakeTemplateDetector:
    _INDICATOR_PATTERNS = [_CATASTROPHIC]
    _COMPILED = []  # would normally be stdlib-re compiled; harden replaces it


def test_harden_replaces_compiled_with_timeout_patterns():
    mod = _FakeTemplateDetector()
    n = rd._harden_template_detector(mod, timeout_s=2.0)
    assert n == 1
    assert isinstance(mod._COMPILED[0], rd._TimeoutPattern)


def test_hardened_pattern_raises_timeout_not_hang():
    mod = _FakeTemplateDetector()
    rd._harden_template_detector(mod, timeout_s=2.0)
    t0 = time.monotonic()
    with pytest.raises(TimeoutError):
        mod._COMPILED[0].search(_BIG_TEXT)
    assert time.monotonic() - t0 < 6, "timeout must fire promptly, not hang"


def test_non_template_module_is_noop():
    class _Plain:
        pass
    assert rd._harden_template_detector(_Plain(), timeout_s=2.0) == 0


def test_fast_pattern_still_matches_normally():
    class _FastDetector:
        _INDICATOR_PATTERNS = ["transfer"]
        _COMPILED = []
    mod = _FastDetector()
    rd._harden_template_detector(mod, timeout_s=5.0)
    assert bool(mod._COMPILED[0].search("fn transfer() {}")) is True
    assert bool(mod._COMPILED[0].search("nothing here")) is False
