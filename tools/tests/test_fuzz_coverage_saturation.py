#!/usr/bin/env python3
"""Regression tests for fuzz-coverage-saturation-check.py.

Proves the checker turns a raw call-count into a MEASURED adequacy verdict:
a campaign whose coverage flatlined = SATURATED (floor was enough); a campaign
whose coverage is still rising at the end = STILL_CLIMBING (floor insufficient,
extend); too few / no coverage samples = UNMEASURED. Uses synthetic medusa and
go-native progress logs (the real STRATA campaigns are all SATURATED, so a fake
still-climbing log is required to exercise that arm)."""
import importlib.util
import os
import unittest
from pathlib import Path

_H = Path(__file__).resolve().parent
_s = importlib.util.spec_from_file_location(
    "fcs", _H.parent / "fuzz-coverage-saturation-check.py")
m = importlib.util.module_from_spec(_s)
_s.loader.exec_module(m)


def _medusa(rows):
    # rows: list of (calls, branches, corpus)
    return "\n".join(
        f"fuzz: elapsed: {i*3}s, calls: {c} ( 5000/sec), seq/s: 100, "
        f"branches: {b}, corpus: {cp}, failures: 0/0, gas/s: 1"
        for i, (c, b, cp) in enumerate(rows))


def _go(rows):
    # rows: list of (execs, total_interesting)
    return "\n".join(
        f"fuzz: elapsed: {i*3}s, execs: {e} (5000/sec), new interesting: 1 (total: {t})"
        for i, (e, t) in enumerate(rows))


class T(unittest.TestCase):
    def test_flatlined_medusa_is_saturated(self):
        # branches climb early then flatline for the back 60% of calls.
        log = _medusa([(0, 1000, 0), (100_000, 3000, 30), (300_000, 3317, 37),
                       (600_000, 3317, 37), (900_000, 3317, 37), (1_200_000, 3317, 37)])
        r = m.classify(m.parse_samples(log)[1])
        self.assertEqual(r["verdict"], "SATURATED", r)

    def test_still_rising_medusa_is_still_climbing(self):
        # branches keep rising through the final window -> floor insufficient.
        log = _medusa([(0, 1000, 0), (100_000, 2000, 20), (300_000, 3000, 30),
                       (600_000, 4000, 40), (900_000, 5000, 50), (1_200_000, 6200, 62)])
        r = m.classify(m.parse_samples(log)[1])
        self.assertEqual(r["verdict"], "STILL_CLIMBING", r)

    def test_engine_detection_medusa(self):
        eng, s = m.parse_samples(_medusa([(0, 1, 0)] * 5))
        self.assertEqual(eng, "medusa")

    def test_go_native_flatlined_is_saturated(self):
        log = _go([(0, 0), (100_000, 25), (300_000, 40), (600_000, 40),
                   (900_000, 40), (1_200_000, 40)])
        eng, s = m.parse_samples(log)
        self.assertEqual(eng, "go-native")
        self.assertEqual(m.classify(s)["verdict"], "SATURATED")

    def test_go_native_still_growing_is_climbing(self):
        log = _go([(0, 0), (100_000, 10), (300_000, 25), (600_000, 40),
                   (900_000, 60), (1_200_000, 85)])
        self.assertEqual(m.classify(m.parse_samples(log)[1])["verdict"], "STILL_CLIMBING")

    def test_too_few_samples_unmeasured(self):
        log = _medusa([(0, 1000, 0), (600_000, 3317, 37)])  # only 2 samples
        self.assertEqual(m.classify(m.parse_samples(log)[1])["verdict"], "UNMEASURED")

    def test_workspace_strict_fails_on_climbing(self):
        import tempfile
        ws = Path(tempfile.mkdtemp())
        d = ws / ".auditooor" / "fuzz_logs"
        d.mkdir(parents=True)
        (d / "medusa_Climber.log").write_text(_medusa(
            [(0, 1000, 0), (100_000, 2000, 20), (300_000, 3000, 30),
             (600_000, 4000, 40), (900_000, 5000, 50), (1_200_000, 6200, 62)]))
        os.environ["AUDITOOOR_FUZZ_SATURATION_STRICT"] = "1"
        try:
            r = m.check_workspace(ws)
            self.assertEqual(r["verdict"], "fail-fuzz-still-climbing", r)
        finally:
            del os.environ["AUDITOOOR_FUZZ_SATURATION_STRICT"]

    def test_discovers_intree_harness_log(self):
        # A lane runs medusa IN-PLACE under chimera_harnesses/<H>/ - the gate must
        # find it, not only .auditooor/fuzz_logs (Strata serving-join fix).
        import tempfile
        ws = Path(tempfile.mkdtemp())
        h = ws / "chimera_harnesses" / "LaneHarness"
        h.mkdir(parents=True)
        (h / "medusa_run.log").write_text(_medusa(
            [(0, 1000, 0), (100_000, 3000, 30), (300_000, 3317, 37),
             (600_000, 3317, 37), (900_000, 3317, 37), (1_200_000, 3317, 37)]))
        logs = m._discover_campaign_logs(ws)
        self.assertEqual(len(logs), 1, logs)
        r = m.check_workspace(ws)
        self.assertEqual(r["campaigns"], 1)
        self.assertEqual(r["saturated"], 1)

    def test_excludes_non_campaign_log(self):
        # a build/stderr log that merely mentions the engine name (no progress
        # line) must NOT be admitted (else it UNMEASURED-warns falsely).
        import tempfile
        ws = Path(tempfile.mkdtemp())
        h = ws / "chimera_harnesses" / "H"
        h.mkdir(parents=True)
        (h / "build.log").write_text("Compiling with medusa 1.5.1\nDeploy OK\nechidna not run\n")
        self.assertEqual(m._discover_campaign_logs(ws), [])
        self.assertEqual(m.check_workspace(ws)["verdict"], "pass-no-campaign-logs")

    def test_skips_dep_noise_dirs(self):
        import tempfile
        ws = Path(tempfile.mkdtemp())
        noise = ws / "chimera_harnesses" / "H" / "lib" / "forge-std"
        noise.mkdir(parents=True)
        (noise / "medusa_run.log").write_text(_medusa([(0, 1, 0)] * 6))
        self.assertEqual(m._discover_campaign_logs(ws), [])

    def test_workspace_advisory_warns_not_fails(self):
        import tempfile
        ws = Path(tempfile.mkdtemp())
        d = ws / ".auditooor" / "fuzz_logs"
        d.mkdir(parents=True)
        (d / "medusa_Climber.log").write_text(_medusa(
            [(0, 1000, 0), (100_000, 2000, 20), (300_000, 3000, 30),
             (600_000, 4000, 40), (900_000, 5000, 50), (1_200_000, 6200, 62)]))
        # ensure strict envs are off
        for k in ("AUDITOOOR_FUZZ_SATURATION_STRICT", "AUDITOOOR_L37_STRICT"):
            os.environ.pop(k, None)
        r = m.check_workspace(ws)
        self.assertEqual(r["verdict"], "warn-fuzz-still-climbing", r)


if __name__ == "__main__":
    unittest.main()
