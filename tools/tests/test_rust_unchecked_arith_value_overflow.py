"""Regression tests for tools/rust-unchecked-arith-value-overflow.py.

Proves the RUST value-overflow reasoning query over the owned MIR backend
(rust-dataflow parse_mir_text / _taint_reaches / _local_is_guarded):

  1. FIRES: a BARE `Add` whose operand taints back to a fn PARAMETER and whose
     result reaches a value use (the fn return) is a SURVIVOR (emitted).
  2. NON-VACUITY MUTATION: the SAME arithmetic, once a manual bound guard
     (Lt + switchInt) dominates its operands, is KEPT (removed from the
     set-difference) - proving the guard subtraction is load-bearing, not a
     constant. Deleting the guard lines (the mutation) flips KEPT -> SURVIVOR.
  3. NOT A SHAPE: a bare `Add` over two CONSTANTS (no param taint) never fires,
     even though the `+` token is present - membership is by taint, not text.
  4. REACH-TO-VALUE: a bare `Add` on a param whose result is DROPPED (never
     returned / never a sink / never compared) does not fire.
  5. CODEGEN EXCLUSION: an unchecked param-arith located in a build-script/prost
     generated `.rs` (target/.../out/*.rs) is never emitted.
  6. wrapping_* on a param feeding a value use IS emitted (silent truncation).
  7. R80 DEGRADE: no compilable crate + no mir-file -> degrade, exit 0.
"""
import importlib.util
import json
from pathlib import Path

_MOD_PATH = Path(__file__).resolve().parents[1] / "rust-unchecked-arith-value-overflow.py"
_spec = importlib.util.spec_from_file_location("ruavo", _MOD_PATH)
mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mod)


# ---------------------------------------------------------------------------
# Minimal text-MIR fixtures (the exact shape rustc --emit=mir produces).
# ---------------------------------------------------------------------------
def _span(f, l):
    return f"// scope 0 at {f}:{l}:5: {l}:20"


# fn credit(amount, bal) -> u64 { bal + amount }   -- UNCHECKED, param, returned.
MIR_UNCHECKED = f"""\
fn credit(_1: u64, _2: u64) -> u64 {{
    debug amount => _1;
    debug bal => _2;
    let mut _0: u64;
    bb0: {{
        _0 = Add(copy _2, copy _1); {_span('src/vault.rs', 2)}
        return; {_span('src/vault.rs', 3)}
    }}
}}
"""

# same body, but a `require(amount < 100)` bound guard dominates the operands
# (Lt -> switchInt) BEFORE the Add -> CHECKED -> KEPT.
MIR_GUARDED = f"""\
fn credit(_1: u64, _2: u64) -> u64 {{
    debug amount => _1;
    debug bal => _2;
    let mut _0: u64;
    let mut _3: bool;
    bb0: {{
        _3 = Lt(copy _1, const 100_u64); {_span('src/vault.rs', 2)}
        switchInt(move _3) -> [0: bb2, otherwise: bb1]; {_span('src/vault.rs', 2)}
    }}
    bb1: {{
        _0 = Add(copy _2, copy _1); {_span('src/vault.rs', 3)}
        return; {_span('src/vault.rs', 4)}
    }}
}}
"""

# bare Add over two CONSTANTS (no param taint) -> must NOT fire.
MIR_CONST = f"""\
fn constant() -> u64 {{
    let mut _0: u64;
    bb0: {{
        _0 = Add(const 3_u64, const 4_u64); {_span('src/vault.rs', 2)}
        return; {_span('src/vault.rs', 2)}
    }}
}}
"""

# param arith whose result is DROPPED (never returned/sink/compared) -> no fire.
MIR_DROPPED = f"""\
fn side(_1: u64, _2: u64) -> () {{
    debug a => _1;
    let mut _0: ();
    let mut _5: u64;
    bb0: {{
        _5 = Add(copy _1, copy _2); {_span('src/vault.rs', 2)}
        _0 = const (); {_span('src/vault.rs', 3)}
        return; {_span('src/vault.rs', 3)}
    }}
}}
"""

# unchecked param arith in GENERATED code (build-script OUT_DIR) -> excluded.
MIR_CODEGEN = f"""\
fn gen_len(_1: u64, _2: u64) -> u64 {{
    debug len => _1;
    let mut _0: u64;
    bb0: {{
        _0 = Add(copy _1, copy _2); {_span('target/debug/build/x-abc/out/proto.rs', 2)}
        return; {_span('target/debug/build/x-abc/out/proto.rs', 2)}
    }}
}}
"""


def _analyze(mir_text):
    fns = mod.rdf.parse_mir_text(mir_text)
    arith = mod._collect_arith_nodes(mir_text)
    return mod.analyze_fns(Path("/ws"), fns, arith, "vault")


def test_unchecked_param_arith_fires():
    rows, counts = _analyze(MIR_UNCHECKED)
    assert counts["survivors"] == 1, counts
    r = rows[0]
    assert r["function"] == "credit"
    assert r["op"] == "add"
    assert r["value_use"] == "return"
    assert r["attack_class"] == "unchecked-arith-value-overflow"
    assert any("src/vault.rs:2" in s for s in r["source_refs"]), r["source_refs"]


def test_non_vacuity_guard_mutation_flips_verdict():
    # guarded => KEPT (0 survivors, 1 checked_kept)
    rows_g, counts_g = _analyze(MIR_GUARDED)
    assert counts_g["survivors"] == 0, counts_g
    assert counts_g["checked_kept"] == 1, counts_g
    # MUTATION: delete the two guard lines (Lt + switchInt). The verdict must flip
    # to a SURVIVOR, proving the guard predicate is load-bearing (non-vacuous).
    mutated = "\n".join(
        ln for ln in MIR_GUARDED.splitlines()
        if "Lt(" not in ln and "switchInt(" not in ln
    )
    rows_m, counts_m = _analyze(mutated)
    assert counts_m["survivors"] == 1, counts_m
    assert counts_m["checked_kept"] == 0, counts_m


def test_const_operands_never_fire():
    rows, counts = _analyze(MIR_CONST)
    assert counts["survivors"] == 0, counts
    assert counts["untrusted_value_arith"] == 0


def test_dropped_result_no_value_use():
    rows, counts = _analyze(MIR_DROPPED)
    assert counts["survivors"] == 0, counts
    assert counts["untrusted_value_arith"] == 0


def test_codegen_arith_excluded():
    rows, counts = _analyze(MIR_CODEGEN)
    assert counts["survivors"] == 0, counts


def test_wrapping_call_on_param_fires():
    mir = f"""\
fn shrink(_1: u64, _2: u64) -> u64 {{
    debug amount => _1;
    let mut _0: u64;
    bb0: {{
        _0 = core::num::<impl u64>::wrapping_add(copy _1, copy _2) -> [return: bb1, unwind continue]; {_span('src/vault.rs', 2)}
    }}
    bb1: {{
        return; {_span('src/vault.rs', 3)}
    }}
}}
"""
    rows, counts = _analyze(mir)
    assert counts["survivors"] == 1, counts
    assert rows[0]["wrapping"] is True
    assert rows[0]["op"].startswith("wrapping_")


def test_degrade_when_no_crate(tmp_path):
    # empty workspace, no crate, no mir-file -> degrade, exit 0, no crash.
    rows, report = mod.run(tmp_path, None, timeout=5, mir_file=None)
    assert rows == []
    assert report.get("any_mir") is False
    assert report.get("degraded") is True


def test_emit_cited_empty_marker(tmp_path):
    # MIR that yields 0 survivors still writes an honest cited-empty jsonl marker.
    mf = tmp_path / "m.mir"
    mf.write_text(MIR_CONST, encoding="utf-8")
    out = tmp_path / "obl.jsonl"
    rc = mod.main(["--workspace", str(tmp_path), "--mir-file", str(mf),
                   "--out", str(out)])
    assert rc == 0
    lines = [json.loads(x) for x in out.read_text().splitlines() if x.strip()]
    assert len(lines) == 1
    assert lines[0]["survivors"] == 0
    assert "cited-empty" in lines[0]["note"]


if __name__ == "__main__":
    import sys
    import subprocess
    sys.exit(subprocess.call(["python3", "-m", "pytest", __file__, "-v"]))
