#!/usr/bin/env python3
"""Regression tests for rust_substrate_hook_unbounded_iteration.

Fixture-based (no Substrate workspace on disk): we write .rs fixtures that model
the FRAME pallet shapes and assert the detector fires on the genuine
unprivileged-reachable unbounded-hook-iteration and stays CLEAN on the bounded /
root-gated negatives.
"""
from __future__ import annotations

import importlib.util
import os
import sys
import textwrap

HERE = os.path.dirname(os.path.abspath(__file__))
DET = os.path.join(HERE, "..", "detectors",
                   "rust_substrate_hook_unbounded_iteration.py")

_spec = importlib.util.spec_from_file_location("rust_sub_hook_det", DET)
mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mod)


def _write(tmp_path, name, src):
    p = os.path.join(str(tmp_path), name)
    with open(p, "w", encoding="utf-8") as fh:
        fh.write(textwrap.dedent(src))
    return p


# ---------------------------------------------------------------------------
# POSITIVE: on_initialize iterates a StorageMap grown by a permissionless
# (ensure_signed-only) extrinsic, with NO bound. A sibling hook (on_idle) DOES
# bound -> asymmetry -> CRITICAL.
# ---------------------------------------------------------------------------
POS_SRC = """
    #[frame_support::pallet]
    pub mod pallet {
        use super::*;

        #[pallet::storage]
        pub type PendingClaims<T: Config> = StorageMap<_, Blake2_128, T::AccountId, u128>;

        #[pallet::storage]
        pub type ScratchIndex<T: Config> = StorageMap<_, Twox64, u32, u32>;

        #[pallet::hooks]
        impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
            fn on_initialize(_n: BlockNumberFor<T>) -> Weight {
                let mut total: u128 = 0;
                for (who, amount) in PendingClaims::<T>::iter() {
                    total = total.saturating_add(amount);
                    Self::settle(&who, amount);
                }
                Weight::zero()
            }

            fn on_idle(_n: BlockNumberFor<T>, remaining_weight: Weight) -> Weight {
                let mut meter = WeightMeter::from_limit(remaining_weight);
                for (k, v) in ScratchIndex::<T>::iter() {
                    if meter.try_consume(T::WeightInfo::step()).is_err() {
                        break;
                    }
                    let _ = (k, v);
                }
                meter.consumed()
            }
        }

        #[pallet::call]
        impl<T: Config> Pallet<T> {
            #[pallet::call_index(0)]
            #[pallet::weight(10_000)]
            pub fn submit_claim(origin: OriginFor<T>, amount: u128) -> DispatchResult {
                let who = ensure_signed(origin)?;
                PendingClaims::<T>::insert(&who, amount);
                Ok(())
            }
        }
    }
"""


# ---------------------------------------------------------------------------
# NEGATIVE 1: same shape but the hook IS bounded (WeightMeter early-return).
# NEGATIVE 2: the grower is root-gated (ensure_root) -> not permissionless.
# NEGATIVE 3: hook iterates a plain Vec local (not a StorageMap) -> not storage.
# ---------------------------------------------------------------------------
NEG_BOUNDED_SRC = """
    #[frame_support::pallet]
    pub mod pallet {
        use super::*;

        #[pallet::storage]
        pub type PendingClaims<T: Config> = StorageMap<_, Blake2_128, T::AccountId, u128>;

        #[pallet::hooks]
        impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
            fn on_initialize(_n: BlockNumberFor<T>) -> Weight {
                let mut meter = WeightMeter::max_limit();
                for (who, amount) in PendingClaims::<T>::iter() {
                    if meter.try_consume(T::WeightInfo::settle()).is_err() {
                        break;
                    }
                    Self::settle(&who, amount);
                }
                meter.consumed()
            }
        }

        #[pallet::call]
        impl<T: Config> Pallet<T> {
            #[pallet::call_index(0)]
            #[pallet::weight(10_000)]
            pub fn submit_claim(origin: OriginFor<T>, amount: u128) -> DispatchResult {
                let who = ensure_signed(origin)?;
                PendingClaims::<T>::insert(&who, amount);
                Ok(())
            }
        }
    }
"""

NEG_ROOT_GATED_SRC = """
    #[frame_support::pallet]
    pub mod pallet {
        use super::*;

        #[pallet::storage]
        pub type Registry<T: Config> = StorageMap<_, Blake2_128, u32, u128>;

        #[pallet::hooks]
        impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
            fn on_finalize(_n: BlockNumberFor<T>) {
                for (k, v) in Registry::<T>::iter() {
                    Self::process(k, v);
                }
            }
        }

        #[pallet::call]
        impl<T: Config> Pallet<T> {
            #[pallet::call_index(0)]
            #[pallet::weight(10_000)]
            pub fn force_register(origin: OriginFor<T>, k: u32, v: u128) -> DispatchResult {
                ensure_root(origin)?;
                Registry::<T>::insert(k, v);
                Ok(())
            }
        }
    }
"""

NEG_VEC_LOCAL_SRC = """
    #[frame_support::pallet]
    pub mod pallet {
        use super::*;

        #[pallet::hooks]
        impl<T: Config> Hooks<BlockNumberFor<T>> for Pallet<T> {
            fn on_initialize(_n: BlockNumberFor<T>) -> Weight {
                let items: Vec<u32> = build_scratch();
                for it in items.iter() {
                    let _ = it;
                }
                Weight::zero()
            }
        }

        #[pallet::call]
        impl<T: Config> Pallet<T> {
            #[pallet::call_index(0)]
            #[pallet::weight(10_000)]
            pub fn noop(origin: OriginFor<T>) -> DispatchResult {
                let _ = ensure_signed(origin)?;
                Ok(())
            }
        }
    }
"""


def test_positive_fires_critical(tmp_path):
    _write(tmp_path, "pallet.rs", POS_SRC)
    rep = mod.scan_root(str(tmp_path))
    assert rep["finding_count"] >= 1, rep
    f = rep["findings"][0]
    assert f["function"] == "on_initialize"
    assert f["receiver"] == "PendingClaims"
    assert f["iter"] == "iter"
    assert f["impact"] == "chain-halt"
    assert f["mechanism"] == "consensus-hook-unbounded-iteration"
    # sibling on_idle bounds -> asymmetry -> critical
    assert f["severity_hint"] == "critical", f
    # required common schema keys
    for k in ("schema", "mechanism", "impact", "severity_hint", "file", "line",
              "function", "reason", "source_record_id"):
        assert k in f, (k, f)


def test_negative_bounded_hook_clean(tmp_path):
    _write(tmp_path, "pallet.rs", NEG_BOUNDED_SRC)
    rep = mod.scan_root(str(tmp_path))
    assert rep["finding_count"] == 0, rep["findings"]


def test_negative_root_gated_grower_clean(tmp_path):
    _write(tmp_path, "pallet.rs", NEG_ROOT_GATED_SRC)
    rep = mod.scan_root(str(tmp_path))
    assert rep["finding_count"] == 0, rep["findings"]


def test_negative_vec_local_clean(tmp_path):
    _write(tmp_path, "pallet.rs", NEG_VEC_LOCAL_SRC)
    rep = mod.scan_root(str(tmp_path))
    assert rep["finding_count"] == 0, rep["findings"]


def test_high_when_no_sibling_asymmetry(tmp_path):
    # remove the bounded sibling: the unbounded hook is the only hook -> HIGH.
    src = POS_SRC.replace(
        """            fn on_idle(_n: BlockNumberFor<T>, remaining_weight: Weight) -> Weight {
                let mut meter = WeightMeter::from_limit(remaining_weight);
                for (k, v) in ScratchIndex::<T>::iter() {
                    if meter.try_consume(T::WeightInfo::step()).is_err() {
                        break;
                    }
                    let _ = (k, v);
                }
                meter.consumed()
            }
""", "")
    _write(tmp_path, "pallet.rs", src)
    rep = mod.scan_root(str(tmp_path))
    assert rep["finding_count"] >= 1, rep
    assert rep["findings"][0]["severity_hint"] == "high", rep["findings"][0]


def test_scan_root_shape():
    rep = mod.scan_root(os.path.dirname(DET))
    for k in ("schema", "mechanism", "impact", "findings", "finding_count"):
        assert k in rep


if __name__ == "__main__":
    sys.exit(__import__("pytest").main([__file__, "-q"]))
