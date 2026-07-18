"""Regression: function-coverage-completeness must normalize verdict=NEGATIVE
(the sonnet per-fn hunt fan-out's clean rule-out token) to the terminal-clean
status 'ruled-out', exactly like KILL. Before this, 'negative' had no alias so it
normalized to the unmapped token and every clean per-fn rule-out was dropped ->
the function false-downgraded to 'hollow' (the near-intents step-3 false-red,
identical to the earlier hyperlane 'kill' bug). Body-trivial + R80 gating
downstream is unchanged, so non-trivial functions still require real evidence."""
import importlib.util
import sys
from pathlib import Path

_TOOLS = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("fcc_alias", _TOOLS / "function-coverage-completeness.py")
m = importlib.util.module_from_spec(_spec)
sys.modules["fcc_alias"] = m
try:
    _spec.loader.exec_module(m)
except SystemExit:
    pass


def test_negative_normalizes_to_ruled_out():
    assert m._normalize_terminal_status("NEGATIVE") == "ruled-out"
    assert m._normalize_terminal_status("negative") == "ruled-out"
    assert m._normalize_terminal_status("source-verified-negative") == "ruled-out"


def test_negative_is_terminal_clean():
    assert m._normalize_terminal_status("NEGATIVE") in m._TERMINAL_CLEAN_STATUSES


def test_kill_alias_still_intact():
    # do not regress the prior hyperlane fix
    assert m._normalize_terminal_status("KILL") == "ruled-out"
    assert m._normalize_terminal_status("killed") == "ruled-out"


def test_confirmed_still_maps_to_finding():
    assert m._normalize_terminal_status("CONFIRMED") == "finding"
