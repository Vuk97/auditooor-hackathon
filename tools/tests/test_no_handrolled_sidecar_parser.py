"""Ratchet lint: no NEW hand-rolled hunt-verdict sidecar parser.

The recurring serving-join family (a gate reader blind to a sidecar schema it did
not hand-roll for) is retired by tools/lib/hunt_sidecar_schema.py. This test FAILS
if a tool that reads a hunt_findings_sidecars record + parses JSON does so WITHOUT
importing the canonical normalizer AND is not in the committed baseline of
pre-existing parsers - so the NEXT gate cannot silently re-introduce the blindness.

Ratchet contract:
  * current offenders MUST be a subset of the baseline (no NET-NEW hand-rolled parser).
  * a new sidecar reader either imports hunt_sidecar_schema (preferred) or is added
    to _sidecar_parser_baseline.txt in the SAME commit (a deliberate, reviewable act).
  * the baseline SHRINKS as readers are converted; it must never grow silently.
Static heuristic (deliberately broad) - a tool "parses a sidecar" if it mentions the
hunt_findings_sidecars path AND calls json.load(s); precise enough to catch the family,
grandfathered against false positives via the baseline.
"""
import os
import re
import unittest

TOOLS = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
_BASELINE = os.path.join(os.path.dirname(__file__), "_sidecar_parser_baseline.txt")

_READS_SIDECAR = re.compile(r"hunt_findings_sidecars")
_PARSES_JSON = re.compile(r"json\.loads?\(|\.load\(")
_IMPORTS_NORMALIZER = re.compile(r"hunt_sidecar_schema")


def _current_offenders() -> set[str]:
    out = set()
    for name in sorted(os.listdir(TOOLS)):
        if not name.endswith(".py"):
            continue
        try:
            with open(os.path.join(TOOLS, name), encoding="utf-8", errors="replace") as fh:
                src = fh.read()
        except OSError:
            continue
        if (_READS_SIDECAR.search(src) and _PARSES_JSON.search(src)
                and not _IMPORTS_NORMALIZER.search(src)):
            out.add(name)
    return out


def _baseline() -> set[str]:
    try:
        with open(_BASELINE, encoding="utf-8") as fh:
            return {ln.strip() for ln in fh if ln.strip() and not ln.startswith("#")}
    except OSError:
        return set()


class TestNoHandrolledSidecarParser(unittest.TestCase):
    def test_no_net_new_handrolled_sidecar_parser(self):
        cur = _current_offenders()
        base = _baseline()
        new = sorted(cur - base)
        self.assertEqual(
            new, [],
            "NET-NEW tool(s) parse a hunt_findings_sidecars record without importing "
            "tools/lib/hunt_sidecar_schema.py. Import the shared normalizer "
            "(normalize_sidecar_record / unit_key / is_engaged / credit_ok) so the "
            "serving-join schema-blindness family cannot recur, OR (if genuinely not a "
            "verdict parse) add it to tools/tests/_sidecar_parser_baseline.txt in this "
            f"commit. New offenders: {new}")

    def test_baseline_only_shrinks(self):
        # A stale baseline entry (converted or deleted) is fine (subset ok); the point
        # is the baseline must not be padded far beyond the real parser set.
        base = _baseline()
        cur = _current_offenders()
        stale = sorted(base - cur)
        self.assertLessEqual(
            len(stale), 8,
            "Baseline has many entries that are no longer offenders "
            f"(converted/removed) - prune them to keep the ratchet honest: {stale}")


if __name__ == "__main__":
    unittest.main()
