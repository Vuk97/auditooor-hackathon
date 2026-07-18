#!/usr/bin/env python3
"""capv3 FIX-8B — End-to-end packager dataflow tests for Row-7 factory header.

These two hermetic tests fire ``package_submission()`` end-to-end (not
``build_evidence_matrix()`` in isolation like T4's unit tests) and prove
that a factory-rendered ``cantina_ready.md`` present in the *existing*
packaged bundle is preserved into the newly-rebuilt bundle's Row-7
``notes`` string.

Why these tests exist
---------------------
Codex caught a false-green in T4's unit coverage:

  * T4's 3 tests pass because they invoke ``build_evidence_matrix()``
    directly with a synthetic ``bundle_dir`` that has
    ``cantina_ready.md`` pre-written.
  * But the real dataflow in ``package_submission()`` does
    ``shutil.rmtree(out_dir)`` *before* the matrix is built, wiping any
    factory-rendered header that lived in the previous bundle.
  * Result: T4's hook was inert in production — these tests reintroduce
    that lifecycle.

Pre-fix expectation (proved via stash-and-rerun in the PR notes):
  ``test_package_submission_e2e_preserves_factory_markers_present_in_row_7``
  fails because the rmtree destroys ``cantina_ready.md`` before Row-7
  reads it.

Post-fix expectation:
  ``package_submission()`` caches the header's first line BEFORE
  ``rmtree`` and threads it through to ``build_evidence_matrix`` as
  ``factory_header``, so Row-7 sees the factory vocabulary even though
  the on-disk file was deleted.

Hermeticity
-----------
These tests never shell out to ``pre-submit-check.sh`` /
``variant-detector.py`` / ``scope-review-inline.sh``. They call
``package_submission()`` (the packaging function) and then call
``build_evidence_matrix()`` with the cached header that
``package_submission()`` has threaded out — which is exactly the same
contract ``main()`` uses in production.

No network; no subprocess; no writes outside ``tempfile``.
"""
from __future__ import annotations

import importlib.util
import inspect
import json
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PACKAGER_PATH = ROOT / "tools" / "submission-packager.py"


def _load_packager_module():
    """Load ``tools/submission-packager.py`` by file path (the dash in the
    filename blocks direct ``import``)."""
    spec = importlib.util.spec_from_file_location(
        "submission_packager_for_fix8b", PACKAGER_PATH,
    )
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _make_workspace(tmp: Path, *, severity: str = "Medium") -> tuple[Path, Path]:
    """Build a minimal workspace with a staging draft.

    Returns ``(ws, draft_path)``. ``ws`` is the workspace root; the draft
    lives at ``ws/submissions/staging/e2e-finding.md``.
    """
    ws = tmp / "audits" / "e2e-ws"
    staging = ws / "submissions" / "staging"
    staging.mkdir(parents=True, exist_ok=True)
    draft = staging / "e2e-finding.md"
    # Title is extracted from the first ``# `` line by ``package_submission``
    # and fed to ``slugify``; body must include the severity for the
    # evidence-matrix severity extraction.
    draft.write_text(
        "# FIX-8B e2e finding\n\n"
        f"**Severity**: {severity}\n\n"
        "Target: some contract.\n"
    )
    return ws, draft


def _pre_write_factory_bundle(
    ws: Path, draft_title_slug: str, header_line: str,
) -> Path:
    """Simulate ``tools/submission-factory.py`` having run against the
    previous bundle: write ``cantina_ready.md`` with ``header_line`` as
    its first line into the bundle directory that ``package_submission``
    will later wipe with ``shutil.rmtree``.

    Returns the pre-existing bundle path.
    """
    packaged = ws / "submissions" / "packaged" / draft_title_slug
    packaged.mkdir(parents=True, exist_ok=True)
    # Exact factory vocabulary from ``tools/submission-factory.py`` +
    # iter-v3-7 T1 ``build_cantina_ready``. The first line is what Row-7
    # reads; the rest is irrelevant for this test but mirrors the
    # factory's actual output shape.
    (packaged / "cantina_ready.md").write_text(
        f"{header_line}\n"
        "---\n"
        "title: irrelevant\n"
        "---\n"
        "body\n"
    )
    # A stale sibling file lets us also assert that rmtree still fires
    # (hard negative for acceptance item #7). If this file survives, the
    # rmtree was accidentally skipped, which would be a different bug.
    (packaged / "stale-sibling.txt").write_text("stale\n")
    return packaged


class E2EFactoryHeaderDataflowTest(unittest.TestCase):
    """Lock the end-to-end dataflow: factory header in prior bundle →
    cached by packager before rmtree → surfaced into Row-7 notes of the
    rebuilt bundle's evidence matrix."""

    # ------------------------------------------------------------------
    # 1. markers present  →  Row-7 notes say "factory header confirms
    #    markers present".
    # ------------------------------------------------------------------
    def test_package_submission_e2e_preserves_factory_markers_present_in_row_7(
        self,
    ) -> None:
        pkg = _load_packager_module()
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            ws, draft = _make_workspace(tmp_path)
            # Slug derived from "# FIX-8B e2e finding" via ``slugify``.
            slug = pkg.slugify("FIX-8B e2e finding")
            prior_bundle = _pre_write_factory_bundle(
                ws, slug, "<!-- triager-risk: markers present -->",
            )
            self.assertTrue((prior_bundle / "cantina_ready.md").exists())
            self.assertTrue((prior_bundle / "stale-sibling.txt").exists())

            # Call package_submission directly (skips main()'s gates).
            out = pkg.package_submission(ws, draft)
            # FIX-8B changes the return type to
            # ``(out_dir, cached_factory_header)``; accept either form
            # so that pre-fix runs also exercise this path and fail for
            # the right reason (row notes, not TypeError).
            if isinstance(out, tuple):
                out_dir, cached_header = out
            else:
                out_dir, cached_header = out, None

            self.assertIsNotNone(out_dir)
            self.assertTrue(out_dir.exists())
            # rmtree must still fire: the stale sibling must be gone.
            self.assertFalse((out_dir / "stale-sibling.txt").exists())

            # Build the evidence matrix the same way ``main()`` does in
            # production (threading the cached factory header through).
            # Pre-submit #20 output is simulated as present so that the
            # BOTH-PRESENT branch of the precedence table fires.
            results = {
                "gates": {
                    "variant": {"risk_level": "LOW"},
                    "pre_submit": {
                        "rc": 0,
                        "output": "  ✅ 20. Triager-risk rules — ok\n",
                    },
                },
            }
            # Mirror ``main()``: pass ``bundle_dir`` always; pass
            # ``factory_header`` only if the packager has been taught the
            # new kwarg (FIX-8B). Pre-fix builds lack the kwarg; passing
            # it would raise TypeError and mask the real regression (Row-7
            # notes falling back to pre-submit-only because the on-disk
            # cantina_ready.md was rmtree'd).
            kwargs = dict(
                draft_path=draft,
                ws=ws,
                poc_found=False,
                bundle_dir=out_dir,
            )
            if "factory_header" in inspect.signature(
                pkg.build_evidence_matrix
            ).parameters:
                kwargs["factory_header"] = cached_header
            matrix = pkg.build_evidence_matrix(results, **kwargs)
            row7 = next(r for r in matrix["rows"] if r["key"] == "triager_risk")
            # Status still derives from pre-submit #20 (unchanged contract).
            self.assertEqual(row7["status"], "PRESENT")
            # The load-bearing assertion: the factory vocabulary must
            # reach the notes string even though the on-disk
            # ``cantina_ready.md`` has been wiped by the packager's
            # rmtree.
            self.assertEqual(
                row7["notes"],
                "pre-submit #20 executed; factory header confirms markers present",
            )

    # ------------------------------------------------------------------
    # 2. no-known-class  →  Row-7 notes say "factory header confirms
    #    no-known-class".
    # ------------------------------------------------------------------
    def test_package_submission_e2e_preserves_factory_no_known_class_in_row_7(
        self,
    ) -> None:
        pkg = _load_packager_module()
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            ws, draft = _make_workspace(tmp_path)
            slug = pkg.slugify("FIX-8B e2e finding")
            prior_bundle = _pre_write_factory_bundle(
                ws, slug, "<!-- triager-risk: no-known-class -->",
            )
            self.assertTrue((prior_bundle / "cantina_ready.md").exists())

            out = pkg.package_submission(ws, draft)
            if isinstance(out, tuple):
                out_dir, cached_header = out
            else:
                out_dir, cached_header = out, None

            self.assertIsNotNone(out_dir)
            self.assertTrue(out_dir.exists())
            self.assertFalse((out_dir / "stale-sibling.txt").exists())

            results = {
                "gates": {
                    "variant": {"risk_level": "LOW"},
                    "pre_submit": {
                        "rc": 0,
                        "output": "  ✅ 20. Triager-risk rules — ok\n",
                    },
                },
            }
            # Mirror ``main()``: pass ``bundle_dir`` always; pass
            # ``factory_header`` only if the packager has been taught the
            # new kwarg (FIX-8B). Pre-fix builds lack the kwarg; passing
            # it would raise TypeError and mask the real regression (Row-7
            # notes falling back to pre-submit-only because the on-disk
            # cantina_ready.md was rmtree'd).
            kwargs = dict(
                draft_path=draft,
                ws=ws,
                poc_found=False,
                bundle_dir=out_dir,
            )
            if "factory_header" in inspect.signature(
                pkg.build_evidence_matrix
            ).parameters:
                kwargs["factory_header"] = cached_header
            matrix = pkg.build_evidence_matrix(results, **kwargs)
            row7 = next(r for r in matrix["rows"] if r["key"] == "triager_risk")
            self.assertEqual(row7["status"], "PRESENT")
            self.assertEqual(
                row7["notes"],
                "pre-submit #20 executed; factory header confirms no-known-class",
            )


if __name__ == "__main__":
    unittest.main()
