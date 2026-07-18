"""Tests for the corpus-hunt-fuel surface dedup + ungrounded-drop in
unhunted-surface-followthrough-gate (the SSV 2652->0 fixes)."""
import importlib.util
from pathlib import Path

_MOD = Path(__file__).resolve().parents[1] / "unhunted-surface-followthrough-gate.py"
_spec = importlib.util.spec_from_file_location("ug", _MOD)
ug = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ug)


def test_corpus_fuel_surface_key_extracts_class_fn():
    k = ug._corpus_fuel_surface_key(
        "corpus-hunt-fuel: INV-ATM-EX-0003 (reentrancy_atomicity) @ onCSSVTransfer")
    assert k == ("reentrancy_atomicity", "oncssvtransfer")


def test_corpus_fuel_surface_key_distinct_inv_same_surface_collapse():
    # different INV ids, SAME (class, fn) -> identical key (one surface)
    a = ug._corpus_fuel_surface_key("corpus-hunt-fuel: INV-DET-EX-0025 (crypto_signing) @ _verifyEBRoots")
    b = ug._corpus_fuel_surface_key("corpus-hunt-fuel: INV-FRE-EX-0088 (crypto_signing) @ _verifyEBRoots")
    assert a == b == ("crypto_signing", "_verifyebroots")


def test_corpus_fuel_surface_key_ungrounded_returns_none():
    # "no in-target fn" form has no `@ fn` -> not a grounded surface
    assert ug._corpus_fuel_surface_key(
        "corpus-hunt-fuel: INV-FINDING-foo (general) no in-target fn") is None


def test_non_corpus_fuel_title_returns_none():
    assert ug._corpus_fuel_surface_key("some other lead @ foo") is None
    assert ug._corpus_fuel_surface_key("") is None


def test_prod_skip_seg_excludes_chimera_harnesses():
    # the chimera_harnesses dir must be a production-fn skip segment so step-2c
    # chimera harness accessors are not mistaken for production functions
    assert "/chimera_harnesses/" in ug._PROD_SKIP_SEG


def test_prod_fn_names_excludes_chimera(tmp_path):
    ws = tmp_path / "ws"
    (ws / "chimera_harnesses" / "H").mkdir(parents=True)
    (ws / "chimera_harnesses" / "H" / "Harness.sol").write_text(
        "contract H { function _pickOperatorId() internal {} }\n", encoding="utf-8")
    (ws / "src").mkdir()
    (ws / "src" / "Real.sol").write_text(
        "contract Real { function deposit() external {} }\n", encoding="utf-8")
    names = ug._production_fn_names(ws)
    assert "deposit" in names
    assert "_pickoperatorid" not in names  # chimera harness fn excluded
