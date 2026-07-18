#!/usr/bin/env python3
"""Regression tests for the our-submissions -> corpus ETL (the missing feeder)."""
import importlib.util
import os
from pathlib import Path

_HERE = os.path.dirname(os.path.abspath(__file__))
_MOD = os.path.join(_HERE, "..", "hackerman-etl-from-our-submissions.py")
spec = importlib.util.spec_from_file_location("own_etl", _MOD)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


def test_confirmed_finding_requires_severity_in_filename():
    assert m.is_confirmed_finding(Path("/ws/submissions/filed/foo-CRITICAL.md"))
    assert not m.is_confirmed_finding(Path("/ws/submissions/filed/foo-no-sev.md"))


def test_skips_oos_superseded_staging_subdocs():
    assert not m.is_confirmed_finding(Path("/ws/submissions/_oos/foo-HIGH.md"))
    assert not m.is_confirmed_finding(Path("/ws/submissions/_superseded/foo-HIGH.md"))
    assert not m.is_confirmed_finding(Path("/ws/submissions/staging/foo-HIGH.md"))
    assert not m.is_confirmed_finding(Path("/ws/submissions/packaged/x/EVIDENCE_MATRIX-HIGH.md"))
    assert not m.is_confirmed_finding(Path("/ws/submissions/packaged/x/FN6_HIGH_SUBMIT_PACKET.md"))


def test_only_confirmed_dirs():
    assert not m.is_confirmed_finding(Path("/ws/submissions/notes/foo-HIGH.md"))
    assert m.is_confirmed_finding(Path("/ws/submissions/paste_ready/foo-MEDIUM.md"))


def test_record_is_schema_shaped_and_honest():
    rec = m.build_own_record("mezo", "submissions/filed/x-HIGH.md", "Some real finding title",
                             "body with vault withdraw transfer", filename_severity="high", filed=True)
    # required fields
    assert rec["schema_version"] == "auditooor.hackerman_record.v1.1"
    assert rec["record_id"].startswith("own-finding:mezo:")
    assert rec["verification_tier"] == "tier-1-officially-disclosed"  # filed -> disclosed
    assert rec["record_tier"] == "submission-derived"
    assert rec["severity_at_finding"] == "high"
    assert rec["source_audit_ref"].startswith("own-finding:mezo:")
    assert rec["record_extensions"]["confirmed_finding"] is True
    # no disallowed root keys
    for bad in ("severity", "title", "provenance"):
        assert bad not in rec


def test_unfiled_uses_self_poc_tier():
    rec = m.build_own_record("nuva", "submissions/paste_ready/x-CRITICAL.md", "t", "b",
                             filename_severity="critical", filed=False)
    assert rec["verification_tier"] == "tier-1-self-poc-confirmed"


if __name__ == "__main__":
    import traceback
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    failed = 0
    for fn in fns:
        try:
            fn(); print(f"ok   {fn.__name__}")
        except Exception:
            failed += 1; print(f"FAIL {fn.__name__}"); traceback.print_exc()
    print("ok" if not failed else f"{failed} FAILED")
    raise SystemExit(1 if failed else 0)
