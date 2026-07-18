#!/usr/bin/env python3
"""Regression (Strata 2026-07-07): two serving-join false-reds in the hunt-complete gate.

(1) PARSE: some SCOPE.md files list in-scope files as BARE relative paths, one per line
    (contracts/tranches/UnstakeCooldown.sol), not markdown bullets. _parse_scope_clusters
    only matched `- `/`* `/`+ ` bullets -> 0 clusters -> fail-missing-cluster-coverage
    "enumerates 0 in-scope clusters" while Step-1 had enumerated 388 units from the file.
(2) MATCH: a path-form cluster (contracts/.../DiscreteAccounting.sol) is credited only if a
    coverage token contains its contract name. hunt sidecars key as
    hunt__DiscreteAccounting__fn; the full-path norm carries the dir prefix + `sol` suffix
    so the shared contract name sits mid-string in BOTH and neither is a substring of the
    other -> every path cluster false-read uncovered. Fix: also match the file basename."""
import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path

_HERE = Path(__file__).resolve().parent


def _load(name, rel):
    spec = importlib.util.spec_from_file_location(name, _HERE.parent / rel)
    m = importlib.util.module_from_spec(spec)
    sys.modules[name] = m
    spec.loader.exec_module(m)
    return m


_MB = _load("mb_bare", "capability-coverage-matrix-build.py")
_HCC = _load("hcc_bare", "hunt-completeness-check.py")


class TestBarePathClusters(unittest.TestCase):
    def _ws(self, sidecar_names):
        ws = Path(tempfile.mkdtemp())
        (ws / "SCOPE.md").write_text(
            "# Scope\n\n## In-scope files (2 .sol)\n"
            "contracts/tranches/DiscreteAccounting.sol\n"
            "contracts/tranches/base/cooldown/UnstakeCooldown.sol\n\n"
            "## OUT-OF-SCOPE\n- UI bugs\n")
        sd = ws / ".auditooor" / "hunt_findings_sidecars"
        sd.mkdir(parents=True)
        for n in sidecar_names:
            (sd / f"{n}.json").write_text("{}")
        return ws

    def test_bare_paths_are_parsed_as_clusters(self):
        ws = self._ws([])
        clusters = _MB._parse_scope_clusters(ws)
        self.assertEqual(len(clusters), 2)
        self.assertTrue(any("DiscreteAccounting.sol" in c for c in clusters))

    def test_basename_match_credits_path_cluster(self):
        # sidecars keyed by contract name -> both path clusters credited
        ws = self._ws(["hunt__DiscreteAccounting__calculateNAVSplit__x",
                       "hunt__UnstakeCooldown__transfer__y"])
        r = _HCC.check_cluster_coverage(ws)
        self.assertTrue(r.ok, r.reason)

    def test_genuinely_uncovered_cluster_still_flagged(self):
        # only one contract has a sidecar -> the other stays uncovered (never-false-pass)
        ws = self._ws(["hunt__DiscreteAccounting__calculateNAVSplit__x"])
        r = _HCC.check_cluster_coverage(ws)
        self.assertFalse(r.ok)
        # detail is lowercased by the parser
        self.assertIn("unstakecooldown", str(r.detail.get("uncovered")).lower())


if __name__ == "__main__":
    unittest.main()
