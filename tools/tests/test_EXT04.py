#!/usr/bin/env python3
"""Non-vacuity tests for EXT04 cross-layer committed-vs-consumed cardinality-
divergence screen (tools/cross-layer-cardinality-divergence-screen.py).

Three load-bearing legs (per the build spec):
  1. PLANTED POSITIVE fires  - a shared buffer iterated by a physical-length
     loop AND an attacker-scalar-count loop, no binding -> fires.
  2. COVERED / benign NEGATIVE is silent - the same shape but with a
     require(count == buf.length) cardinality binding, and the same-bound and
     constant-arith variants -> silent.
  3. NEUTRALIZING the core predicate (monkeypatch `_is_scalar_count` to a
     constant) STOPS the positive firing - proving the scalar-count predicate is
     load-bearing, not decorative.
"""
import importlib.util
import json
import os
import sys
from pathlib import Path

import pytest

_TOOL = (Path(__file__).resolve().parent.parent
         / "cross-layer-cardinality-divergence-screen.py")
_spec = importlib.util.spec_from_file_location("ext04_mod", _TOOL)
mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mod)


# ---------------------------------------------------------------- fixtures ----
POSITIVE_SOL = """
pragma solidity ^0.8.0;
contract Settlement {
    function settle(bytes32[] calldata txs, uint256 numRealTxs) external {
        // commit loop: proves/validates ALL physical rows
        for (uint256 i = 0; i < txs.length; i++) {
            _commit(txs[i]);
        }
        // settle loop: consumes only an attacker-supplied count
        for (uint256 j = 0; j < numRealTxs; j++) {
            _settle(txs[j]);
        }
    }
    function _commit(bytes32 x) internal {}
    function _settle(bytes32 x) internal {}
}
"""

# same shape, but the cardinality-binding invariant is present (written against
# the length ALIAS, the way real code does it)
NEGATIVE_BOUND_SOL = """
pragma solidity ^0.8.0;
contract Settlement {
    function settle(bytes32[] calldata txs, uint256 numRealTxs) external {
        uint256 phys = txs.length;
        require(numRealTxs == phys);
        for (uint256 i = 0; i < phys; i++) {
            _commit(txs[i]);
        }
        for (uint256 j = 0; j < numRealTxs; j++) {
            _settle(txs[j]);
        }
    }
    function _commit(bytes32 x) internal {}
    function _settle(bytes32 x) internal {}
}
"""

# both loops iterate the buffer's own physical length -> no divergence
NEGATIVE_SAME_SOL = """
pragma solidity ^0.8.0;
contract Settlement {
    function settle(bytes32[] calldata txs) external {
        for (uint256 i = 0; i < txs.length; i++) {
            _commit(txs[i]);
        }
        for (uint256 j = 0; j < txs.length; j++) {
            _settle(txs[j]);
        }
    }
    function _commit(bytes32 x) internal {}
    function _settle(bytes32 x) internal {}
}
"""

# two loops with fixed constant-arithmetic bounds -> structural, not an attacker
# cardinality -> silent
NEGATIVE_CONST_SOL = """
pragma solidity ^0.8.0;
contract Tree {
    uint256 constant DEPTH = 32;
    function build(bytes32[] memory zeroes) internal {
        for (uint256 i = 0; i < DEPTH; i++) {
            zeroes[i] = keccak256(abi.encode(i));
        }
        for (uint256 j = 0; j < DEPTH - 1; j++) {
            zeroes[j] = keccak256(abi.encode(zeroes[j]));
        }
    }
}
"""

# Go positive: committing loop over len(msgs), consuming loop over scalar count
POSITIVE_GO = """
package settle

func Process(msgs [][]byte, count int) {
	for i := 0; i < len(msgs); i++ {
		commit(msgs[i])
	}
	for j := 0; j < count; j++ {
		apply(msgs[j])
	}
}

func commit(b []byte) {}
func apply(b []byte)  {}
"""

# Go negative: allocation sizes the buffer to the count -> self-bound
NEGATIVE_GO = """
package settle

func Decode(count int) [][]byte {
	out := make([][]byte, count)
	for i := 0; i < count; i++ {
		out[i] = decode(i)
	}
	for j := 0; j < len(out); j++ {
		verify(out[j])
	}
	return out
}

func decode(i int) []byte { return nil }
func verify(b []byte)     {}
"""

# ---- REGRESSION: the language-aware declared-constant FP class ---------------
# Go same-function Merkle build, bound by a CamelCase package-level const
# `Depth` and `Depth-1`. The ALL_CAPS naming proxy misclassified these as
# attacker counts and FIRED; a declared-const-aware predicate must be silent.
NEGATIVE_GO_CAMEL_CONST = """
package tree

const Depth = 32

func BuildZeroHashes(zeroes [][]byte) {
	for i := 0; i < Depth; i++ {
		zeroes[i] = hash(i)
	}
	for j := 0; j < Depth-1; j++ {
		zeroes[j] = hash2(zeroes[j])
	}
}

func hash(i int) []byte     { return nil }
func hash2(b []byte) []byte { return nil }
"""

# Go const-BLOCK form of the same thing (`const ( Depth = 32 )`).
NEGATIVE_GO_CONST_BLOCK = """
package tree

const (
	Depth = 32
	Other = 8
)

func BuildZeroHashes(zeroes [][]byte) {
	for i := 0; i < Depth; i++ {
		zeroes[i] = hash(i)
	}
	for j := 0; j < Depth-1; j++ {
		zeroes[j] = hash2(zeroes[j])
	}
}

func hash(i int) []byte     { return nil }
func hash2(b []byte) []byte { return nil }
"""

# Solidity same-function Merkle build bound by a mixedCase `immutable maxDepth`
# and `maxDepth-1`. Same benign-fire class as the Go CamelCase const.
NEGATIVE_SOL_IMMUTABLE = """
pragma solidity ^0.8.0;
contract Tree {
    uint256 immutable maxDepth;
    constructor(uint256 d) { maxDepth = d; }
    function build(bytes32[] memory zeroes) internal {
        for (uint256 i = 0; i < maxDepth; i++) {
            zeroes[i] = keccak256(abi.encode(i));
        }
        for (uint256 j = 0; j < maxDepth - 1; j++) {
            zeroes[j] = keccak256(abi.encode(zeroes[j]));
        }
    }
}
"""

# CONTROL: a mixedCase bound that is NOT declared constant/immutable (a plain
# local param `numRealDomains`) must STILL fire - the fix must not blanket-
# suppress every non-ALL_CAPS token.
POSITIVE_SOL_MIXEDCASE_LOCAL = """
pragma solidity ^0.8.0;
contract Registry {
    function apply_(address[] calldata domains, uint256 numRealDomains) external {
        for (uint256 i = 0; i < domains.length; i++) {
            _commit(domains[i]);
        }
        for (uint256 j = 0; j < numRealDomains; j++) {
            _settle(domains[j]);
        }
    }
    function _commit(address x) internal {}
    function _settle(address x) internal {}
}
"""


def _scan(text, name):
    return mod.scan_file(Path(name), name, file_text=text)


def _fired(rows):
    return [r for r in rows if r["fires"]]


# ------------------------------------------------------------------ LEG 1 -----
def test_leg1_planted_positive_sol_fires():
    rows = _scan(POSITIVE_SOL, "Settlement.sol")
    fired = _fired(rows)
    assert len(fired) == 1, rows
    r = fired[0]
    assert r["buffer"] == "txs"
    assert r["capability"] == "EXT04"
    assert set(r["distinct_bounds"]) == {"PHYS", "numRealTxs"}
    assert r["scalar_counts"] == ["numRealTxs"]
    assert r["binding"] == "none"
    assert r["pair_scope"] == "same-function"
    assert r["lead_kind"] == "same-function-divergence"
    # item-7: a fired same-function divergence is a real survivor -> an OPEN
    # obligation, not advisory-green (was `advisory is True`).
    assert r["advisory"] is False and r["auto_credit"] is False
    assert r["proof_status"] == "open"
    assert r["verdict"] == "needs-fuzz"


def test_leg1_planted_positive_go_fires():
    rows = _scan(POSITIVE_GO, "process.go")
    fired = _fired(rows)
    assert len(fired) == 1, rows
    r = fired[0]
    assert r["buffer"] == "msgs"
    assert "count" in r["scalar_counts"]
    assert "PHYS" in r["distinct_bounds"]


# ------------------------------------------------------------------ LEG 2 -----
def test_leg2_benign_binding_is_silent():
    rows = _scan(NEGATIVE_BOUND_SOL, "Settlement.sol")
    assert _fired(rows) == []
    # the enforcement point is still enumerated, with the binding recorded
    assert len(rows) == 1
    assert rows[0]["binding"] == "equality"


def test_leg2_benign_same_bound_is_silent():
    rows = _scan(NEGATIVE_SAME_SOL, "Settlement.sol")
    assert _fired(rows) == []


def test_leg2_benign_constant_arith_is_silent():
    rows = _scan(NEGATIVE_CONST_SOL, "Tree.sol")
    assert _fired(rows) == []


def test_leg2_benign_go_alloc_selfbound_is_silent():
    rows = _scan(NEGATIVE_GO, "decode.go")
    assert _fired(rows) == []


# --- REGRESSION: language-aware declared-constant FP (the fixed benign class) --
def test_reg_go_camelcase_const_is_silent():
    # Depth / Depth-1 bound by a CamelCase Go `const Depth = 32` -> structural,
    # not an attacker count. Fired under the ALL_CAPS-only proxy; must be silent.
    rows = _scan(NEGATIVE_GO_CAMEL_CONST, "tree.go")
    assert _fired(rows) == [], rows
    # the enforcement point is still enumerated - just not fired.
    assert len(rows) == 1 and rows[0]["scalar_counts"] == []


def test_reg_go_const_block_is_silent():
    rows = _scan(NEGATIVE_GO_CONST_BLOCK, "tree.go")
    assert _fired(rows) == [], rows


def test_reg_sol_mixedcase_immutable_is_silent():
    # maxDepth / maxDepth-1 bound by a mixedCase Solidity `immutable maxDepth`.
    rows = _scan(NEGATIVE_SOL_IMMUTABLE, "Tree.sol")
    assert _fired(rows) == [], rows
    assert len(rows) == 1 and rows[0]["scalar_counts"] == []


def test_reg_mixedcase_local_still_fires():
    # a mixedCase bound that is NOT a declared constant (plain local param) must
    # STILL fire - proving the fix targets DECLARED constants, not naming shape.
    rows = _scan(POSITIVE_SOL_MIXEDCASE_LOCAL, "Registry.sol")
    fired = _fired(rows)
    assert len(fired) == 1, rows
    assert fired[0]["buffer"] == "domains"
    assert fired[0]["scalar_counts"] == ["numRealDomains"]
    assert fired[0]["pair_scope"] == "same-function"


# ------------------------------------------------------------------ LEG 3 -----
def test_leg3_neutralizing_scalar_count_predicate_stops_firing(monkeypatch):
    # sanity: fires before neutralization
    assert len(_fired(_scan(POSITIVE_SOL, "Settlement.sol"))) == 1
    # neutralize the core predicate that decides whether a decoupled bound is a
    # genuine attacker cardinality count -> forced constant False
    monkeypatch.setattr(mod, "_is_scalar_count", lambda *_a, **_k: False)
    rows = _scan(POSITIVE_SOL, "Settlement.sol")
    assert _fired(rows) == [], (
        "positive still fired after neutralizing _is_scalar_count - predicate "
        "is not load-bearing")


def test_leg3b_neutralizing_norm_bound_collapse_stops_firing(monkeypatch):
    # a second neutralization: if every bound normalizes to one constant token,
    # no two loops can diverge -> positive must go silent.
    assert len(_fired(_scan(POSITIVE_SOL, "Settlement.sol"))) == 1
    monkeypatch.setattr(mod, "_norm_bound", lambda _b, _a: "SAME")
    rows = _scan(POSITIVE_SOL, "Settlement.sol")
    assert _fired(rows) == []


# --------------------------------------------------------------- plumbing -----
def test_source_mode_writes_no_sidecar(tmp_path):
    (tmp_path / "Settlement.sol").write_text(POSITIVE_SOL)
    rc = mod.main(["--source", str(tmp_path)])
    assert rc == 0  # advisory: default exit 0 even with a fired row
    assert not (tmp_path / ".auditooor").exists()


def test_workspace_mode_emits_sidecar_and_strict_exit(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "Settlement.sol").write_text(POSITIVE_SOL)
    rc = mod.main(["--workspace", str(tmp_path)])
    assert rc == 0
    side = tmp_path / ".auditooor" / mod._SIDE_NAME
    assert side.exists()
    rows = [json.loads(l) for l in side.read_text().splitlines() if l.strip()]
    assert any(r["fires"] for r in rows)
    for r in rows:
        for k in ("capability", "fires", "file", "line", "function", "advisory",
                  "auto_credit", "verdict"):
            assert k in r
    # strict elevates the exit code on a fired severity-eligible point
    rc_strict = mod.main(["--workspace", str(tmp_path), "--strict"])
    assert rc_strict == 1


def test_strict_env_elevates_exit(tmp_path, monkeypatch):
    src = tmp_path / "src"
    src.mkdir()
    (src / "Settlement.sol").write_text(POSITIVE_SOL)
    monkeypatch.setenv(mod._STRICT_ENV, "1")
    rc = mod.main(["--workspace", str(tmp_path)])
    assert rc == 1


def test_generated_and_test_files_skipped(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "gen.pb.go").write_text(POSITIVE_GO)
    (src / "x_test.go").write_text(POSITIVE_GO)
    gen = src / "hdr.go"
    gen.write_text("// Code generated by protoc. DO NOT EDIT.\n" + POSITIVE_GO)
    mod.main(["--workspace", str(tmp_path)])
    side = tmp_path / ".auditooor" / mod._SIDE_NAME
    rows = [json.loads(l) for l in side.read_text().splitlines() if l.strip()]
    assert rows == []  # all three excluded -> nothing scanned


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-q"]))
