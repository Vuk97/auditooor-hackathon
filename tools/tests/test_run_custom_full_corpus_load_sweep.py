"""Wave-3 W3.6 regression sweep: every detector file the production loader
would touch must import cleanly.

Background: Wave-2 PR-B commit 60b1cf03e3 recovered 9 silently-skipped
detectors:
  - 6 wave17 @dataclass detectors recovered via loader-side sys.modules
    pre-registration fix (covered by test_run_custom_loader_dataclass_safety).
  - 3 wave_overnight_quarantine detectors recovered via file-level edits
    (51_percent_attack_party_governance class rename, airdrop_fee_evasion
    triple-quote terminator, block_number_vs_block_timestamp import path).

This Wave-3 W3.6 sweep guards against future regressions across the FULL
default `detectors/*.py + detectors/wave*/*.py` glob (mirrors
`_detector_py_files(detectors_dir, include_graveyard=False)` in
`detectors/run_custom.py`). It does NOT load `wave_graveyard/*/` files,
which are intentionally quarantined (the `syntax_broken` subdir is
literally named for the failure class).

Invariants:
1. Every .py file the default-mode loader would touch can be imported
   without exception via the same `importlib.util.spec_from_file_location
   + module_from_spec + sys.modules-pre-register + exec_module` sequence
   used by production.
2. The original 9 documented broken detectors all load cleanly.
3. The default corpus load count is at or above the pinned baseline
   (currently 2715 wave*/*.py files; bump if intentional).

synthetic_fixture: false (production source files, real imports).
"""

import importlib.util
import sys
import unittest
from pathlib import Path


_REPO_ROOT = Path(__file__).resolve().parents[2]
_DETECTORS = _REPO_ROOT / "detectors"

# The original 9 detectors from docs/SLITHER_IR_BROKEN_DETECTORS_2026-05-16.md.
# Each must load cleanly after Wave-2 PR-B fix.
_ORIGINAL_9_BROKEN = [
    "detectors/wave17/dual_direction_swap_math_asymmetry.py",
    "detectors/wave17/exact_output_floor_input_drain.py",
    "detectors/wave17/v4_hook_beforeswap_slippage_bypass.py",
    "detectors/wave17/v4_hook_take_before_pricing_state_mutation.py",
    "detectors/wave17/v4_settle_without_prior_sync.py",
    "detectors/wave17/wrapper_passes_zero_slippage_to_internal_call.py",
    "detectors/wave_overnight_quarantine/51_percent_attack_party_governance.py",
    "detectors/wave_overnight_quarantine/airdrop_fee_evasion_wrap_unwrap.py",
    "detectors/wave_overnight_quarantine/block_number_vs_block_timestamp_misuse.py",
]

# Baseline count of wave*/*.py files under default load path. If detector
# corpus grows, this can rise; intentional shrinks should bump this DOWN
# in the same PR that shrinks the corpus.
_DEFAULT_CORPUS_BASELINE = 2700


def _default_glob_files():
    """Mirror `_detector_py_files(detectors_dir, include_graveyard=False)`
    in detectors/run_custom.py."""
    files = sorted(_DETECTORS.glob("*.py")) + sorted(_DETECTORS.glob("wave*/*.py"))
    return [
        p
        for p in files
        if not p.name.startswith("_") and p.name != "run_custom.py"
    ]


def _try_load(py_file: Path):
    """Mirror the FIXED loader shape used by detectors/run_custom.py:
    sys.modules-pre-register before exec_module, pop on failure."""
    stem = py_file.stem
    # Be hygienic: don't carry state across files in the sweep.
    prev = sys.modules.pop(stem, None)
    try:
        spec = importlib.util.spec_from_file_location(stem, py_file)
        if spec is None:
            return f"spec is None for {py_file}"
        module = importlib.util.module_from_spec(spec)
        sys.modules[stem] = module
        try:
            spec.loader.exec_module(module)
            return None  # success
        except Exception as exc:
            sys.modules.pop(stem, None)
            return f"{type(exc).__name__}: {exc}"
    finally:
        if prev is not None:
            sys.modules[stem] = prev


class TestRunCustomFullCorpusLoadSweep(unittest.TestCase):
    """W3.6 sweep: every default-glob detector file imports cleanly."""

    @classmethod
    def setUpClass(cls):
        # Add detectors/ to sys.path so any sibling _template_utils style
        # imports succeed - matches production behavior at run_custom.py:376-377.
        # Insert at index 0 so the real detectors/ wins over any temp-dir
        # entries left behind by sibling tests (e.g., the graveyard loader
        # test class registers a tmp detectors root that ships a stub
        # _template_utils without `is_vendored_or_test_contract`).
        detectors_root = str(_DETECTORS.resolve())
        cls._inserted_path = False
        if detectors_root not in sys.path:
            sys.path.insert(0, detectors_root)
            cls._inserted_path = True
        else:
            # Make sure detectors/ is BEFORE any stale tmp entry.
            sys.path.remove(detectors_root)
            sys.path.insert(0, detectors_root)
        # Evict any cached shared helpers (e.g., _template_utils) loaded
        # from a temp-dir under a sibling test's setUp; we want fresh
        # imports against the real detectors/ tree.
        for shared in ("_template_utils", "_util"):
            sys.modules.pop(shared, None)

    def test_default_corpus_load_count_at_or_above_baseline(self):
        """The default-glob file count must not regress below the pin."""
        files = _default_glob_files()
        self.assertGreaterEqual(
            len(files),
            _DEFAULT_CORPUS_BASELINE,
            f"Default-glob detector count {len(files)} dropped below baseline "
            f"{_DEFAULT_CORPUS_BASELINE}; check for accidental removals.",
        )

    def test_original_9_documented_broken_detectors_load_cleanly(self):
        """Every file from SLITHER_IR_BROKEN_DETECTORS_2026-05-16.md loads."""
        failures = []
        for rel in _ORIGINAL_9_BROKEN:
            p = _REPO_ROOT / rel
            if not p.is_file():
                failures.append(f"{rel}: file not found")
                continue
            err = _try_load(p)
            if err is not None:
                failures.append(f"{rel}: {err}")
        self.assertEqual(
            failures,
            [],
            "Wave-2 PR-B 9-detector recovery regressed: " + "; ".join(failures),
        )

    def test_default_glob_full_sweep_zero_load_failures(self):
        """W3.6 invariant: every default-mode detector .py imports cleanly.

        This is the broad regression net. If any new detector ships with
        a syntax error, stale slither import, or non-pre-registered
        @dataclass shape, this test surfaces it BEFORE production load
        silently drops the detector via the loader's `[warn] skipping`
        path.
        """
        failures = []
        for p in _default_glob_files():
            err = _try_load(p)
            if err is not None:
                failures.append(f"{p.relative_to(_REPO_ROOT)}: {err}")
        # Cap reported failures to avoid log explosions on a future
        # large-scale regression; the first 10 are enough to diagnose.
        if failures:
            shown = "\n".join(failures[:10])
            self.fail(
                f"{len(failures)} detector(s) failed to load under default "
                f"glob (showing first 10):\n{shown}"
            )


if __name__ == "__main__":
    unittest.main()
