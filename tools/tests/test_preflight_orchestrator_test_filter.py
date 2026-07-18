"""Regression: the per-function preflight orchestrator must exclude OOS Rust
test code from the units it processes. The cross-crate source graph does not
carry cfg(test) attrs per entrypoint (they live on the enclosing `mod tests`
block), so test fns like `test_proposed_updates_interface_resharing` were fanned
out to the hunt - burning budget on, and risking findings in, out-of-scope test
code (Rule 6), diverging from the clean inscope_units.jsonl manifest.
_is_test_unit() applies the standard Rust test conventions."""
import importlib.util
import sys
from pathlib import Path

_TOOLS = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location(
    "preflight_orch_mod", _TOOLS / "per-function-preflight-orchestrator.py"
)
po = importlib.util.module_from_spec(_spec)
sys.modules["preflight_orch_mod"] = po
_spec.loader.exec_module(po)


def test_test_prefixed_fn_is_test_unit():
    assert po._is_test_unit("test_proposed_updates_interface_resharing",
                            "src/mpc/crates/contract/src/lib.rs") is True


def test_tests_dir_path_is_test_unit():
    assert po._is_test_unit("verify_proof", "crates/btc/tests/integration.rs") is True


def test_tests_rs_and_underscore_test_files_are_test_units():
    assert po._is_test_unit("foo", "src/lib/tests.rs") is True
    assert po._is_test_unit("foo", "src/bridge_test.rs") is True
    assert po._is_test_unit("foo", "src/bridge_tests.rs") is True


def test_production_fn_is_not_test_unit():
    # real production entrypoints must NOT be filtered out
    assert po._is_test_unit("transfer", "src/mpc/crates/contract/src/lib.rs") is False
    assert po._is_test_unit("clear_invalid_pending_verify_rbf",
                            "contracts/satoshi-bridge/src/api/bridge.rs") is False


def test_empty_inputs_are_not_test_units():
    assert po._is_test_unit("", "") is False
    assert po._is_test_unit(None, None) is False
