"""Regression: L29-Filing Check D (manifest cross-cite + test-name) must
recognize Rust #[test]/#[tokio::test] `fn` definitions and must NOT treat a cited
file-STEM (tests/test_foo.rs -> 'test_foo') or a cargo `--test test_foo` target
selector as a test FUNCTION name. Generic false-RED fix from the near-intents
clear-rbf finalization (the runnable near-workspaces PoC fns
poc_clear_rbf_* live in .rs files; the gate previously only knew
Solidity/Go/Python test patterns + greedily matched file stems). Never-false-pass:
the widening only recognizes MORE genuine on-disk fn definitions + drops path
tokens from the must-be-defined set; it never marks a hallucinated name defined."""
import importlib.util
import sys
import tempfile
from pathlib import Path

_MOD = Path(__file__).resolve().parents[1] / "l29_filing_check.py"
_spec = importlib.util.spec_from_file_location("l29_fc", _MOD)
m = importlib.util.module_from_spec(_spec)
sys.modules["l29_fc"] = m
_spec.loader.exec_module(m)


def _mkpaste(body: str) -> Path:
    d = Path(tempfile.mkdtemp(prefix="l29_rs_"))
    (d / "tests").mkdir(parents=True, exist_ok=True)
    p = d / "finding.md"
    p.write_text(body, encoding="utf-8")
    return p


def test_rust_fn_testname_recognized():
    pp = _mkpaste(
        "Manifest: PoC test `poc_clear_rbf_asymmetry` in tests/test_poc.rs\n"
    )
    (pp.parent / "tests" / "test_poc.rs").write_text(
        "#[tokio::test]\nasync fn poc_clear_rbf_asymmetry() { assert!(true); }\n",
        encoding="utf-8",
    )
    ok, detail = m.check_d_manifest_and_testnames(pp)
    # the real fn is defined on disk -> must NOT be reported as a missing test-name
    assert "poc_clear_rbf_asymmetry" not in detail or ok, detail


def test_file_stem_token_not_treated_as_testname():
    # citing only the file path (no fn name) must not fail as a "missing test"
    pp = _mkpaste("See PoC at tests/test_clear_rbf_access_control_poc.rs\n")
    (pp.parent / "tests" / "test_clear_rbf_access_control_poc.rs").write_text(
        "#[test]\nfn poc_real() { assert_eq!(1, 1); }\n", encoding="utf-8",
    )
    ok, detail = m.check_d_manifest_and_testnames(pp)
    assert "test_clear_rbf_access_control_poc" not in detail, (
        "file stem must not be resolved as a test fn name: " + detail
    )
