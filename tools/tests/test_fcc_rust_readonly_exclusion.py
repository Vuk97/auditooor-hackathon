"""Regression: function-coverage-completeness must recognize Rust read-only
views (getter-named + `&self` + no state-write/Promise tokens) as non-attack
boilerplate, mirroring the Go rule. Before this, _is_read_only returned False for
ALL Rust, so pure accessors inflated the coverage denominator. CONSERVATIVE: a
`&mut self` receiver, any write/Promise/transfer token, or a non-getter name
(verify / assert_*) KEEPS the function (never drops a mutator or a validator)."""
import importlib.util
import sys
from pathlib import Path

_MOD = Path(__file__).resolve().parents[1] / "function-coverage-completeness.py"
_spec = importlib.util.spec_from_file_location("fcc_rro", _MOD)
m = importlib.util.module_from_spec(_spec)
sys.modules["fcc_rro"] = m
_spec.loader.exec_module(m)


def ro(name, sig, body):
    return m._is_read_only(name, sig, "rust", body)


def test_pure_getter_view_is_read_only():
    assert ro("get_user_deposit_address", "pub fn get_user_deposit_address(&self) -> String",
              "{ self.deposit_address.clone() }") is True
    assert ro("is_paused", "fn is_paused(&self) -> bool", "{ self.paused }") is True


def test_getter_with_state_write_is_kept():
    # a getter-named fn that actually writes (or &mut self) must NOT be excluded
    assert ro("get_and_bump", "fn get_and_bump(&mut self) -> u64",
              "{ self.n += 1; self.n }") is False
    assert ro("get_or_insert", "fn get_or_insert(&self, k: u64)",
              "{ self.map.insert(k, 1); }") is False


def test_getter_with_promise_is_kept():
    # a &self getter that fires a cross-contract Promise can move funds -> keep
    assert ro("get_balance_remote", "fn get_balance_remote(&self)",
              "{ Promise::new(self.acc.clone()).transfer(1) }") is False


def test_security_validators_are_kept():
    # verify / assert_* are NOT getter-named -> never excluded as read-only
    assert ro("verify", "pub fn verify(&self, pk: &P, m: &S) -> bool", "{ ... }") is False
    assert ro("assert_participant_inputs", "pub fn assert_participant_inputs(p: &[u8])", "{ ... }") is False


def test_non_rust_unaffected():
    assert m._is_read_only("get_x", "fn get_x(&self)", "go", "{ return s.x }") is False  # go needs Get-prefix
    assert m._is_read_only("bar", "function bar() view", "solidity", "{}") is True
