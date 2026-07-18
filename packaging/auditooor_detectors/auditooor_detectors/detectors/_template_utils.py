"""
_template_utils.py — shared utilities for auditooor custom Slither detectors.

Import from detector files as:

    import sys
    from pathlib import Path as _Path
    sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
    from _template_utils import is_vendored_or_test_contract

DO NOT modify _template.py, run_custom.py, or run_tests.sh.
"""

import os

# Path substrings that indicate a contract should be skipped regardless of its
# Solidity name.  Ordered from most- to least-specific; first match wins.
_VENDORED_OR_TEST_SUBSTRINGS = (
    "/test/",
    "/tests/",
    "/mocks/",
    "/mock/",
    "/fixtures/",
    "/fixture/",
    "/dev/",
    "/examples/",
    "/example/",
    "/lib/",
    "/node_modules/",
    "forge-std",
    "solady/src",
    "solmate/src",
    "openzeppelin",
)


def is_vendored_or_test_contract(contract) -> bool:
    """Return True if *contract* lives in a test, mock, vendored, or dev path.

    Inspects the path returned by ``contract.source_mapping.filename``.
    Slither stores paths in a ``Filename`` namedtuple-like object with
    ``.absolute``, ``.used``, ``.relative``, and ``.short`` string fields.
    We check all non-empty fields to maximise coverage across Slither versions
    and build configurations.

    This catches production-named contracts (e.g. ``CollateralVault``) that
    happen to live under ``src/test/dev/mocks/`` — a case that the name-based
    SKIP_KEYWORDS check alone misses.

    Args:
        contract: A Slither ``Contract`` object.

    Returns:
        ``True`` if any of the contract's path strings contains a substring
        from ``_VENDORED_OR_TEST_SUBSTRINGS``, ``False`` otherwise.

    When ``AUDITOOOR_FIXTURE_SMOKE_MODE=1`` is set in the environment, this
    function always returns ``False`` so that detector smoke tests against the
    canonical ``patterns/fixtures/<arg>_vuln.sol`` / ``_clean.sol`` files are
    not skipped by the path-based filter (the substring ``/fixtures/`` would
    otherwise match every fixture under ``patterns/fixtures/``). Production
    runs leave the variable unset and the filter behaves as before.
    """
    if os.environ.get("AUDITOOOR_FIXTURE_SMOKE_MODE") == "1":
        return False
    try:
        sm = contract.source_mapping
        fn = getattr(sm, "filename", None)
        if fn is None:
            return False
        # Collect all non-empty path strings from the Filename object.
        candidates = []
        for attr in ("absolute", "used", "relative", "short"):
            val = getattr(fn, attr, None)
            if val:
                candidates.append(str(val))
        if not candidates:
            return False
    except Exception:
        return False
    return any(
        sub in path
        for path in candidates
        for sub in _VENDORED_OR_TEST_SUBSTRINGS
    )


def is_leaf_helper(f) -> bool:
    """Return True if *f* is a pure/view leaf helper with no calls of any kind.

    A function is a "leaf helper" when it reads state / inputs and returns a
    value but performs no internal calls, no high-level calls, and no
    low-level calls. These are the pure-math library functions (e.g.
    SharesMathLib.toSharesDown, MorphoStorageLib.marketTotalSupplyAssetsAndSharesSlot)
    that trivially match every name_match_missing_call detector's second-half
    predicate ("reads state X but never calls guard Y") simply because leaf
    helpers never call anything.

    Skipping them eliminates the dominant FP class on well-structured DeFi
    codebases (Morpho, Aave, Uniswap) that push math into pure libraries.
    See auditooor SKILL_ISSUE #55.
    """
    try:
        pure = getattr(f, "pure", False)
        view = getattr(f, "view", False)
        internal = list(getattr(f, "internal_calls", []) or [])
        high = list(getattr(f, "high_level_calls", []) or [])
        low = list(getattr(f, "low_level_calls", []) or [])
        writes = list(getattr(f, "state_variables_written", []) or [])
        if not internal and not high and not low and not writes:
            return True
        if (pure or view) and not internal and not high and not low:
            return True
        return False
    except Exception:
        return False
