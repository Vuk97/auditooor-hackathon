"""Non-vacuity + regression tests for EXT06 - the Send/Sync/'static bound-omission
at a share/send/FFI boundary screen
(rust-send-sync-bound-omission-share-boundary-screen.py).

The NET-NEW value of this screen lives in two arms whose sinks BREAK auto-trait
propagation, so a missing bound is genuinely compiler-MISSED:

  * REGISTER / FFI arm - a repeatably-callable `Fn` handed to a foreign runtime
    (`new_closure`, `register_*`, ...) WITHOUT `Sync` (the pyo3 RUSTSEC-2026-0177
    anchor shape).
  * UNSAFE-AUTO-IMPL arm - a type manually `unsafe impl Send|Sync` that holds a
    `Box<dyn Fn>` whose OWN bound omits the asserted trait (rustc's auto-trait
    check is bypassed by the manual `unsafe impl`, so this is compiler-MISSED).

The SPAWN arm, in contrast, is COMPILER-REDUNDANT whenever the value is handed to
a well-known spawn primitive (`std::thread::spawn`, `tokio::spawn`,
`rayon::spawn`, a scoped `scope.spawn`, or a `.boxed()` -> `BoxFuture` hand-off):
the primitive's own signature bounds `Send` (+ `'static`), so `rustc` already
rejects a missing bound with E0277. Those rows are down-ranked
(`fires=False`, `compiler_redundant=True`) - see `_compiler_covered_bounds`. This
was the fix for the spawn-arm false positive (near futures.rs `spawn` ->
`f.boxed()` and orchard-halo2 `parallelize` scoped `scope.spawn`), which rustc
already catches / does not require.

These fixtures are TEXT fixtures for a static text screen; they need not compile.
"""
import importlib.util
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = REPO_ROOT / "tools" / \
    "rust-send-sync-bound-omission-share-boundary-screen.py"


def _load():
    spec = importlib.util.spec_from_file_location("ext06_screen", MODULE_PATH)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["ext06_screen"] = mod
    spec.loader.exec_module(mod)
    return mod


MOD = _load()

# --- fixtures ---------------------------------------------------------------

# NET-NEW (compiler-MISSED) positives: register/FFI Sync omission + unsafe-impl.
POSITIVE_SRC = r'''
use pyo3::prelude::*;

// pyo3 RUSTSEC-2026-0177 anchor shape: a repeatably-callable `Fn` is registered
// with the Python runtime (shared across threads) but the bound OMITS `Sync`.
pub fn new_closure<F>(py: Python, f: F) -> PyResult<Py<PyCFunction>>
where
    F: Fn(&PyTuple) -> PyResult<PyObject> + Send + 'static,
{
    register_callback(py, f)
}

// unsafe-auto-impl arm: a manual `unsafe impl Send` over a type holding a
// `Box<dyn Fn>` whose OWN bound OMITS `Send`. rustc's auto-trait check is
// bypassed by the manual `unsafe impl`, so this soundness gap is compiler-MISSED.
pub struct Registry {
    cb: Box<dyn Fn(u32) + 'static>,
}
unsafe impl Send for Registry {}
'''

# COMPILER-REDUNDANT spawn fires: rustc already rejects (or does not require) the
# missing bound, so the screen must stay SILENT (down-ranked). This is the
# regression for the spawn-arm false positive.
REDUNDANT_SPAWN_SRC = r'''
use futures::future::FutureExt;

// std::thread::spawn bounds `Send + 'static` in its own signature: a missing
// `Send` is rejected by rustc (E0277) -> compiler-redundant -> must stay SILENT.
pub fn run_task<F>(f: F)
where
    F: FnOnce() + 'static,
{
    std::thread::spawn(f);
}

// `.boxed()` -> `BoxFuture` hand-off: `FutureExt::boxed` requires `Self: Send`,
// so a missing `Send` is rejected by rustc -> compiler-redundant -> SILENT.
// (this is the exact near futures.rs `spawn` shape the false-positive came from)
pub fn spawn_fut<F>(&self, f: F)
where
    F: std::future::Future<Output = ()> + 'static,
{
    self.spawn_boxed(f.boxed());
}

// scoped spawn: crossbeam/rayon `scope(|s| s.spawn(..))` does NOT require
// `'static` (the whole point of scoped threads) -> missing `'static` is a
// non-requirement, not a gap -> SILENT. (orchard-halo2 `parallelize` shape)
pub fn parallelize<F: Fn() + Send + Sync>(f: F) {
    crossbeam::scope(|s| {
        s.spawn(move |_| f());
    });
}
'''

NEGATIVE_SRC = r'''
// correctly bounded spawn - Send + 'static present.
pub fn run_ok<F>(f: F)
where
    F: FnOnce() + Send + 'static,
{
    std::thread::spawn(f);
}

// type-erased boxed closure: no explicit lifetime, so Rust's DEFAULT OBJECT
// LIFETIME makes it `+ 'static`; Send is written. Sound -> must stay silent.
pub fn run_boxed(f: Box<dyn FnOnce() + Send>) {
    std::thread::spawn(f);
}

// a FnOnce hook registered with a runtime needs only Send + 'static (consumed
// once, never shared-by-&) - Sync is NOT required, so this must stay silent.
pub fn on_start<F>(f: F)
where
    F: FnOnce() + Send + 'static,
{
    register_callback(f);
}

// unsafe-auto-impl arm, benign: the held `Box<dyn Fn>` DOES carry `Send`, so the
// manual assertion is backed by the field bound -> must stay silent.
pub struct SafeRegistry {
    cb: Box<dyn Fn(u32) + Send>,
}
unsafe impl Send for SafeRegistry {}
'''


def _scan(src):
    return MOD.scan_file(Path("fixture.rs"), "fixture.rs", file_text=src)


# --- leg 1: net-new arms fire -----------------------------------------------

def test_register_arm_fires():
    rows = _scan(POSITIVE_SRC)
    fired = {r["function"]: r for r in rows if r["fires"]}
    # the register/FFI Fn without Sync fires with missing == {Sync}
    assert "new_closure" in fired, f"register-Fn-no-Sync did not fire: {rows}"
    assert fired["new_closure"]["missing_bounds"] == ["Sync"], fired["new_closure"]
    assert fired["new_closure"]["net_new_missing_bounds"] == ["Sync"]
    assert fired["new_closure"]["callable_kind"] == "Fn"
    assert "register" in fired["new_closure"]["boundary_kind"]
    assert fired["new_closure"]["compiler_redundant"] is False
    for r in rows:
        if r["fires"]:
            assert r["advisory"] is True
            assert r["auto_credit"] is False
            assert r["verdict"] == "needs-fuzz"
            assert r["capability"] == "EXT06"


def test_unsafe_auto_impl_arm_fires():
    rows = _scan(POSITIVE_SRC)
    fired = {r["function"]: r for r in rows if r["fires"]}
    # the manual `unsafe impl Send` over a `Box<dyn Fn>` omitting Send fires.
    assert "unsafe_impl_Send" in fired, f"unsafe-auto-impl did not fire: {rows}"
    u = fired["unsafe_impl_Send"]
    assert u["boundary_kind"] == "unsafe_auto_impl"
    assert u["missing_bounds"] == ["Send"]
    assert u["net_new_missing_bounds"] == ["Send"]
    # this arm has NO compiler-covered bounds - the manual unsafe impl bypasses
    # rustc's auto-trait check, which is exactly why it is compiler-MISSED.
    assert u["compiler_covered_bounds"] == []
    assert u["compiler_redundant"] is False


# --- leg 2 (REGRESSION): compiler-redundant spawn fires are silenced ---------

def test_spawn_arm_compiler_redundant_is_silent():
    rows = _scan(REDUNDANT_SPAWN_SRC)
    byfn = {r["function"]: r for r in rows}
    # all three spawn enforcement points ARE enumerated (not vacuously dropped) ...
    assert {"run_task", "spawn_fut", "parallelize"} <= set(byfn), byfn.keys()
    # ... but NONE fire - each is compiler-redundant (rustc already rejects, or
    # the scoped sink does not require the bound).
    fired = [r for r in rows if r["fires"]]
    assert not fired, f"compiler-redundant spawn fired (FP not fixed): {fired}"
    for fn in ("run_task", "spawn_fut", "parallelize"):
        r = byfn[fn]
        assert r["boundary_kind"] == "spawn"
        assert r["missing_bounds"], f"{fn} should have a RAW missing bound"
        assert r["compiler_redundant"] is True, r
        assert r["net_new_missing_bounds"] == [], r
    # the near futures.rs `.boxed()` case: Send is compiler-covered
    assert "Send" in byfn["spawn_fut"]["compiler_covered_bounds"]
    # the scoped-spawn case: 'static is compiler-covered (scoped != 'static)
    assert "'static" in byfn["parallelize"]["compiler_covered_bounds"]


def test_spawn_suppression_is_load_bearing(monkeypatch):
    # WITHOUT the compiler-redundancy screen, run_task WOULD fire (missing Send).
    # Neutralizing `_compiler_covered_bounds` proves the suppression is what
    # silences the compiler-redundant spawn fires (not a vacuous always-silent).
    monkeypatch.setattr(MOD, "_compiler_covered_bounds", lambda *a, **k: set())
    rows = _scan(REDUNDANT_SPAWN_SRC)
    fired = {r["function"] for r in rows if r["fires"]}
    assert {"run_task", "spawn_fut"} <= fired, (
        "spawn fires did not re-appear after neutralizing the covered-bounds "
        f"screen - suppression is not load-bearing: {fired}")


# --- leg 3: benign negatives silent (but enumerated) ------------------------

def test_benign_negative_silent():
    rows = _scan(NEGATIVE_SRC)
    fired = [r for r in rows if r["fires"]]
    assert not fired, f"benign, correctly-bounded APIs fired (FP): {fired}"
    fns = {r["function"] for r in rows}
    assert {"run_ok", "run_boxed", "on_start"} <= fns, (
        f"enforcement points not enumerated: {fns}")
    # the boxed-closure point proves the default-object-lifetime rule: 'static is
    # credited even though it is not written.
    boxed = next(r for r in rows if r["function"] == "run_boxed")
    assert "'static" in boxed["declared_bounds"], boxed
    assert boxed["type_erased"] is True
    # the benign unsafe-impl (field carries Send) is correctly silent / skipped.
    assert not any(r["function"] == "unsafe_impl_Send" and r["fires"]
                   for r in rows)


# --- leg 4: the bound-sufficiency predicates are load-bearing ---------------

def test_register_required_bounds_load_bearing(monkeypatch):
    # sanity: the register arm fires before neutralization.
    assert any(r["fires"] and "register" in r["boundary_kind"]
               for r in _scan(POSITIVE_SRC))
    # neutralize the register/spawn required-bound predicate -> nothing the
    # `_required_bounds` predicate drives can fire.
    monkeypatch.setattr(MOD, "_required_bounds", lambda *a, **k: set())
    rows = _scan(POSITIVE_SRC)
    assert not any(r["fires"] and "register" in r["boundary_kind"]
                   for r in rows), (
        "register point still fired after neutralizing `_required_bounds` - the "
        "bound-sufficiency predicate is NOT load-bearing")


def test_unsafe_impl_field_bound_load_bearing():
    # the unsafe-impl fire is driven by the FIELD's bound-vs-assertion gap: the
    # same `unsafe impl Send` is SILENT when the field carries Send (SafeRegistry)
    # and FIRES when it does not (Registry).
    assert any(r["function"] == "unsafe_impl_Send" and r["fires"]
               for r in _scan(POSITIVE_SRC)), "Registry (no Send) should fire"
    assert not any(r["function"] == "unsafe_impl_Send" and r["fires"]
                   for r in _scan(NEGATIVE_SRC)), "SafeRegistry (Send) must be silent"


# --- schema sanity ----------------------------------------------------------

def test_row_schema_shape():
    rows = _scan(POSITIVE_SRC) + _scan(REDUNDANT_SPAWN_SRC)
    assert rows
    required_keys = {"capability", "fires", "file", "line", "function",
                     "advisory", "auto_credit", "verdict", "boundary_kind",
                     "callable_kind", "required_bounds", "declared_bounds",
                     "missing_bounds", "compiler_covered_bounds",
                     "net_new_missing_bounds", "compiler_redundant"}
    for r in rows:
        assert required_keys <= set(r), f"missing keys: {required_keys - set(r)}"


if __name__ == "__main__":
    import subprocess
    subprocess.run([sys.executable, "-m", "pytest", __file__, "-q"], check=False)
