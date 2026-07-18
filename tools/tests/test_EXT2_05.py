"""Non-vacuity + regression tests for EXT2-05 (code token EXT2_05) - the
generic/phantom-type vs runtime-selector desync screen
(generic-type-vs-runtime-selector-desync-screen.py).

The class (OpenZeppelin "Critical bug patterns in Sui Move"): a call co-supplies a
COMPILE-TIME generic `<T>` (used as `Coin<T>`) AND a RUNTIME asset selector
(`pool_id`, `market_id`, `coin_type`, ...) for the SAME asset, but nothing asserts
`type_of<T>() == registry[selector].type_tag`. A caller pairs `Pool<A>` with a
`B`-index so one coin type is withdrawn while another is credited - type-check
PASSES (both types are valid), the run-time handle diverges.

Three non-vacuity legs:
  1. PLANTED POSITIVE fires - the uncoupled `<T>` + runtime-selector withdraw
     (Move + Rust) fires with fires=True, verdict='needs-fuzz'.
  2. COVERED / benign NEGATIVE silent - the SAME shape WITH a
     `type_name::get<T>()==pool.coin_type` / `TypeId::of::<T>()` coupling assert is
     SILENT (fires=False), and a generic fn with a type-safe `Pool<T>` handle and
     NO runtime selector is not even an enforcement point (no row).
  3. NEUTRALIZE the core predicate - monkeypatching `_has_type_selector_coupling`
     to a constant True (pretend everything is coupled) STOPS the positive;
     monkeypatching `_selector_params` to a constant empty (no selector enumerated)
     also STOPS it. Both are load-bearing.

These fixtures are TEXT fixtures for a static text screen; they need not compile.
"""
import importlib.util
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = REPO_ROOT / "tools" / \
    "generic-type-vs-runtime-selector-desync-screen.py"


def _load():
    spec = importlib.util.spec_from_file_location("ext2_05_screen", MODULE_PATH)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["ext2_05_screen"] = mod
    spec.loader.exec_module(mod)
    return mod


MOD = _load()


# --- fixtures ---------------------------------------------------------------

# PLANTED POSITIVE (Move): the OpenZeppelin anchor shape. `<CoinType>` is trusted,
# `pool_id` is attacker-chosen, coin::split withdraws pool.reserve, and NOTHING
# asserts type_name::get<CoinType>() == pool.coin_type -> asset substitution.
MOVE_POSITIVE = r'''
module dex::pool {
    struct PoolInfo has store { reserve: Coin<phantom u8>, coin_type: TypeName }
    struct Registry has key { pools: vector<PoolInfo> }

    /// VULNERABLE: type-erased selector desync (Pool<BTC> + USDC-index).
    public fun withdraw<CoinType>(reg: &mut Registry, pool_id: u64, amount: u64): Coin<CoinType> {
        let pool = vector::borrow_mut(&mut reg.pools, pool_id);
        coin::split(&mut pool.reserve, amount)
    }
}
'''

# PLANTED POSITIVE (Rust): the same class in Rust - Coin<T> + a runtime pool_id, no
# TypeId::of::<T>() cross-check.
RUST_POSITIVE = r'''
pub fn withdraw<T>(reg: &mut Registry, pool_id: u64, amount: u128) -> Coin<T> {
    let pool = &mut reg.pools[pool_id as usize];
    Coin::<T>::split(&mut pool.reserve, amount)
}
'''

# COVERED NEGATIVE (Move + Rust): the SAME shape WITH the coupling assert -> silent.
MOVE_COVERED = r'''
module dex::pool {
    public fun withdraw<CoinType>(reg: &mut Registry, pool_id: u64, amount: u64): Coin<CoinType> {
        let pool = vector::borrow_mut(&mut reg.pools, pool_id);
        assert!(type_name::get<CoinType>() == pool.coin_type, E_ASSET_MISMATCH);
        coin::split(&mut pool.reserve, amount)
    }
}
'''
RUST_COVERED = r'''
pub fn withdraw<T: 'static>(reg: &mut Registry, pool_id: u64, amount: u128) -> Coin<T> {
    let pool = &mut reg.pools[pool_id as usize];
    assert_eq!(TypeId::of::<T>(), pool.coin_type);
    Coin::<T>::split(&mut pool.reserve, amount)
}
'''

# BENIGN NEGATIVES (not enforcement points at all):
#  - a type-safe `Pool<T>` handle with NO runtime selector: the type binds the pool
#    to T at compile time -> the safe design -> no row.
#  - a generic fn taking a runtime id but with NO asset-wrapper use of the generic.
BENIGN_NEGATIVE = r'''
// type-safe: Pool<T> handle, no runtime selector -> safe, not an enforcement point.
pub fn withdraw_safe<T>(pool: &mut Pool<T>, amount: u128) -> Coin<T> {
    Coin::<T>::split(&mut pool.reserve, amount)
}

// generic over a serializer, an id param, but the generic never wraps a coin and
// there is no asset movement -> not an enforcement point.
pub fn load_object<T>(store: &Store, object_id: u64) -> Option<T> {
    store.decode::<T>(object_id)
}
'''


def _scan(src, fn):
    return MOD.scan_file(Path(fn), fn, file_text=src)


def _fired(rows):
    return [r for r in rows if r["fires"]]


# --- leg 1: planted positive fires ------------------------------------------

def test_move_positive_fires():
    rows = _scan(MOVE_POSITIVE, "pool.move")
    fired = _fired(rows)
    assert len(fired) == 1, f"expected 1 fire, got {rows}"
    r = fired[0]
    assert r["function"] == "withdraw"
    assert r["asset_generic"] == "CoinType"
    assert r["asset_wrapper"] == "Coin"
    assert r["runtime_selector"] == "pool_id"
    assert r["has_type_selector_coupling"] is False
    assert r["lang"] == "move"
    assert "withdraw" in r["movement_verbs"] and "split" in r["movement_verbs"]
    # advisory-first contract
    assert r["verdict"] == "needs-fuzz"
    assert r["advisory"] is True
    assert r["auto_credit"] is False
    assert r["capability"] == "EXT2_05"


def test_rust_positive_fires():
    rows = _scan(RUST_POSITIVE, "pool.rs")
    fired = _fired(rows)
    assert len(fired) == 1, f"expected 1 fire, got {rows}"
    r = fired[0]
    assert r["asset_generic"] == "T"
    assert r["asset_wrapper"] == "Coin"
    assert r["runtime_selector"] == "pool_id"
    assert r["lang"] == "rust"
    assert r["has_type_selector_coupling"] is False


# --- leg 2: covered / benign negatives silent -------------------------------

def test_move_covered_is_silent():
    rows = _scan(MOVE_COVERED, "pool.move")
    # the point is still ENUMERATED (not vacuously dropped) ...
    assert len(rows) == 1, rows
    # ... but does NOT fire: the type_name::get<CoinType>() assert couples the
    # generic to the resolved handle.
    assert rows[0]["fires"] is False
    assert rows[0]["has_type_selector_coupling"] is True


def test_rust_covered_is_silent():
    rows = _scan(RUST_COVERED, "pool.rs")
    assert len(rows) == 1, rows
    assert rows[0]["fires"] is False
    assert rows[0]["has_type_selector_coupling"] is True


def test_benign_negatives_not_enforcement_points():
    rows = _scan(BENIGN_NEGATIVE, "obj.rs")
    # neither the type-safe Pool<T> handle (no selector) nor the non-asset generic
    # loader is an enforcement point: no rows at all -> silent.
    assert rows == [], f"benign generics produced rows (FP-spray): {rows}"


# --- leg 3: neutralize the core predicate stops the positive ----------------

def test_neutralize_coupling_predicate_silences_positive(monkeypatch):
    # sanity: fires before neutralization.
    assert _fired(_scan(MOVE_POSITIVE, "pool.move"))
    assert _fired(_scan(RUST_POSITIVE, "pool.rs"))
    # pretend EVERY point is coupled (sound) -> the positive must stop firing. This
    # proves the coupling absence is what drives the fire (not a vacuous always-on).
    monkeypatch.setattr(MOD, "_has_type_selector_coupling", lambda *a, **k: True)
    assert not _fired(_scan(MOVE_POSITIVE, "pool.move")), \
        "move positive still fired after neutralizing coupling predicate"
    assert not _fired(_scan(RUST_POSITIVE, "pool.rs")), \
        "rust positive still fired after neutralizing coupling predicate"


def test_neutralize_selector_enumerator_silences_positive(monkeypatch):
    # the runtime-selector enumerator is also load-bearing: with NO selector
    # enumerated there is no enforcement point, so nothing fires.
    monkeypatch.setattr(MOD, "_selector_params", lambda *a, **k: iter(()))
    assert _scan(MOVE_POSITIVE, "pool.move") == []
    assert _scan(RUST_POSITIVE, "pool.rs") == []


def test_neutralize_coupling_to_false_makes_covered_fire(monkeypatch):
    # the inverse: forcing "never coupled" makes the COVERED negative fire, proving
    # the covered-negative silence is driven by the coupling predicate, not by a
    # structural difference.
    monkeypatch.setattr(MOD, "_has_type_selector_coupling", lambda *a, **k: False)
    assert _fired(_scan(MOVE_COVERED, "pool.move")), \
        "covered move point did not fire after forcing not-coupled"
    assert _fired(_scan(RUST_COVERED, "pool.rs"))


# --- schema sanity ----------------------------------------------------------

def test_row_schema_shape():
    rows = (_scan(MOVE_POSITIVE, "pool.move") + _scan(RUST_POSITIVE, "pool.rs")
            + _scan(MOVE_COVERED, "pool.move"))
    assert rows
    required = {"capability", "fires", "file", "line", "function", "advisory",
                "auto_credit", "verdict", "asset_generic", "asset_wrapper",
                "runtime_selector", "has_type_selector_coupling", "movement_verbs",
                "lang"}
    for r in rows:
        assert required <= set(r), f"missing keys: {required - set(r)}"
        assert r["advisory"] is True and r["auto_credit"] is False


if __name__ == "__main__":
    import subprocess
    subprocess.run([sys.executable, "-m", "pytest", __file__, "-q"], check=False)
