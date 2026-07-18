#!/usr/bin/env python3
"""iter13 T2 regression tests — packager silent-fallback behavior locks.

Re-spawn of iter12 T5 (work lost to wrong-worktree routing). Pairs with
``docs/PACKAGER_AUDIT_ITER13.md``.

Each test locks ONE INTENTIONAL fail-open site in
``tools/submission-packager.py``. Tests assert the *current* behavior
(malformed/unreadable input → safe stub). Any future refactor that
changes the stub (raises instead, returns a truthy stub, etc.) will
force a deliberate test update — the refactor becomes an explicit
behavior change, not a silent drift.

Sites locked here:

  1. ``load_angle_map`` (submission-packager.py line 110-113): corrupt
     ``angle_map.json`` JSON → ``{}``. Supports the iter12 T1 documented
     fail-open: "packager silently skips harness emission when no
     authoritative mapping is available".

  2. ``_load_fork_replay_manifest`` (line 940-943): corrupt
     ``_manifest.json`` → ``{}``. The caller at line 1061 converts this
     into a fail-closed ``summary["malformed"].append(rel)`` — the
     ``{}`` return value is the contract between the loader and the
     manifest-build routine. Test asserts the loader's half of the
     contract.

  3. ``_draft_cites_source_only`` (line 1502-1506): unreadable draft →
     ``False``. Pairs with the iter9 T5
     ``_extract_severity_from_draft`` lock — both functions silently
     return a safe default on ``OSError`` rather than raising. A
     refactor that unifies read-error handling MUST preserve this.

RISKY sites (B2 ln 2098-2102, C5 ln 1070-1077 + 1168-1174, C6 ln
1237-1241 + 1272-1276) are INTENTIONALLY NOT locked here — see
``docs/PACKAGER_AUDIT_ITER13.md`` §3. Locking RISKY behavior would
cement the degradation class that iter14+ needs to fix.

No network, no subprocess. Imports the packager module via
``importlib.util`` (the dash in the filename blocks a normal import).

No modifications to ``tools/submission-packager.py`` are made by this
test file. Pure audit + regression lock.
"""
from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
PACKAGER_SRC = ROOT / "tools" / "submission-packager.py"


def _load_packager_module():
    """Import ``tools/submission-packager.py`` as ``_packager_under_test``.

    Mirrors ``test_submission_packager_hygiene.py``'s loader so two
    copies of the packager module don't end up in memory under
    conflicting names.
    """
    spec = importlib.util.spec_from_file_location(
        "_packager_under_test_fallbacks", PACKAGER_SRC
    )
    assert spec is not None and spec.loader is not None, (
        f"failed to build import spec for {PACKAGER_SRC}"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


PKG = _load_packager_module()


class LoadAngleMapFallbackTest(unittest.TestCase):
    """Lock: ``load_angle_map`` returns ``{}`` on malformed JSON.

    Line 110-113 of ``tools/submission-packager.py``. iter12 T1 adopted
    this fail-open so that bundle-local symbolic-harness emission
    (``bundle_symbolic_harness``) silently skips when no authoritative
    angle→family mapping is available, rather than aborting the whole
    packaging step.
    """

    def test_load_angle_map_returns_empty_on_malformed_json(self) -> None:
        """Corrupt ``angle_map.json`` → ``{}`` (not raise).

        Hard-positive lock: a future refactor that tightens this to
        ``raise`` would break the ``bundle_symbolic_harness``
        fail-open contract at line 1825-1832 ("harness emission is
        advisory and must never break the package step").
        """
        with tempfile.TemporaryDirectory() as tmp:
            bad_map = Path(tmp) / "angle_map.json"
            bad_map.write_text("{ not valid json")
            result = PKG.load_angle_map(bad_map)
            self.assertEqual(
                result,
                {},
                msg=(
                    f"load_angle_map must return {{}} on malformed JSON, "
                    f"got {result!r}. Iter12 T1's bundle_symbolic_harness "
                    f"depends on this fail-open."
                ),
            )


class LoadForkReplayManifestFallbackTest(unittest.TestCase):
    """Lock: ``_load_fork_replay_manifest`` returns ``{}`` on parse failure.

    Line 940-943 of ``tools/submission-packager.py``. The caller at
    line 1061 inspects ``if not payload:`` and appends to
    ``summary["malformed"]`` — this is how the silent ``{}`` becomes a
    fail-closed signal at the packaging level. Test asserts the
    loader's half of that contract.
    """

    def test_load_fork_replay_manifest_returns_empty_on_malformed(self) -> None:
        """Corrupt ``_manifest.json`` → ``{}`` (not raise, not None).

        Hard-positive lock: downstream code at
        ``summarize_fork_replay`` line 1061-1064 does
        ``payload = _load_fork_replay_manifest(resolved)`` then
        ``if not payload: summary["malformed"].append(rel); continue``.
        If the loader raises instead of returning ``{}``, the
        ``except`` wrapper two levels up does not exist and the whole
        packaging aborts with an unhandled exception — making every
        draft that happens to cite a malformed manifest un-packageable
        instead of surfacing ``malformed_fork_replay`` fail-closed at
        line 1937-1942.
        """
        with tempfile.TemporaryDirectory() as tmp:
            bad = Path(tmp) / "0xabc_manifest.json"
            bad.write_text("{ corrupt")
            result = PKG._load_fork_replay_manifest(bad)
            self.assertEqual(
                result,
                {},
                msg=(
                    f"_load_fork_replay_manifest must return {{}} on "
                    f"malformed JSON (the caller at line 1061 appends to "
                    f"summary['malformed'] only when the return is "
                    f"falsy). Got {result!r}."
                ),
            )


class DraftCitesSourceOnlyFallbackTest(unittest.TestCase):
    """Lock: ``_draft_cites_source_only`` returns ``False`` on unreadable draft.

    Line 1502-1506 of ``tools/submission-packager.py``. Parallels the
    iter9 T5 lock on ``_extract_severity_from_draft`` — both functions
    silently return a safe default on file read failure.
    """

    def test_draft_cites_source_only_returns_false_on_unreadable_draft(self) -> None:
        """Unreadable draft path → ``False`` (not raise).

        Uses a nonexistent path to trigger the read-failure branch.
        ``Path.read_text`` on a missing file raises
        ``FileNotFoundError`` (a subclass of ``OSError``), which the
        bare ``except Exception`` swallows. Hard-positive lock:
        downstream evidence-matrix row 2 at line 1610-1613 reads
        ``_draft_cites_source_only(draft_path)`` to decide whether
        ``fork_replay`` status is ``"N/A"`` (source-only claim) or
        ``"PARTIAL"`` (High+ missing cite). A raising refactor here
        would propagate up and kill the evidence-matrix build.
        """
        with tempfile.TemporaryDirectory() as tmp:
            phantom = Path(tmp) / "nonexistent-draft.md"
            self.assertFalse(phantom.exists())
            result = PKG._draft_cites_source_only(phantom)
            self.assertIs(
                result,
                False,
                msg=(
                    f"_draft_cites_source_only must return False on "
                    f"unreadable draft. Got {result!r}. Parallels the "
                    f"iter9 T5 _extract_severity_from_draft lock; "
                    f"evidence-matrix row 2 at line 1610 depends on "
                    f"this fail-open."
                ),
            )


if __name__ == "__main__":
    unittest.main()
