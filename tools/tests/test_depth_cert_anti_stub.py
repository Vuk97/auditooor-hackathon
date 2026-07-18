#!/usr/bin/env python3
"""Tests for the R81 anti-stub adjudication-genuineness layer in
tools/depth-certificate-build.py.

An adjudication counts as GENUINE only if its ruled_out_reason is BOTH
(a) SUBSTANTIVE (cites the specific guard via file:line / per-guard id /
backtick code / a concrete check keyword) AND (b) NOT BULK-TEMPLATED (not in
the largest near-identical cluster when that cluster exceeds
AUDITOOOR_DEPTH_TEMPLATE_FRACTION, default 0.25 of all adjudications).

The cert verdict is depth-audited ONLY IF genuine_adjudicated ==
guards_enumerated AND every candidate gap is genuinely disposed. Bulk/generic
stubs drop the verdict to depth-pending (which the gate fails on).

Empirical anchors:
  - zebra: 1240 identical-prefix boilerplate stubs -> depth-pending.
  - morpho-midnight: 124 distinct substantive per-guard analyses -> depth-audited.
"""
from __future__ import annotations

import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1]
BUILD_TOOL = TOOLS / "depth-certificate-build.py"
CHECK_TOOL = TOOLS / "depth-certificate-check.py"


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    assert spec and spec.loader
    spec.loader.exec_module(mod)
    return mod


BUILD = _load("_depth_cert_build_anti_stub", BUILD_TOOL)
CHECK = _load("_depth_cert_check_anti_stub", CHECK_TOOL)


def _jsonl(p: Path, rows: list[dict]) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")


# A reason that cites the specific guard: file:line + the actual `require(...)`.
def _substantive_reason(gid: str, line: int, check: str) -> str:
    return (
        f"Probed guard NS-{gid} at src/src/Midnight.sol:{line}; checks "
        f"`{check}`. No negative-space gap: every input that passes this guard "
        "preserves the protected invariant. No constructible input passes the "
        "guard yet violates the invariant. Ruled out by source-level "
        "adversarial reading of the call site; not a survivor."
    )


# The zebra bulk-template stub: identical prefix, no file:line / code / keyword.
_ZEBRA_STUB = (
    "Probed: guard adjudicated against its protected invariant; no input found "
    "that passes the guard yet violates the invariant (inferred from file_line "
    "context). No exploitable negative-space gap. Probed candidates=0, "
    "survivors=0, drops=0."
)


class TestDepthCertAntiStub(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.ws = Path(self._tmp.name)
        self.aud = self.ws / ".auditooor"
        self.aud.mkdir(parents=True, exist_ok=True)
        # Keep env deterministic across cases.
        self._saved_env = os.environ.pop("AUDITOOOR_DEPTH_TEMPLATE_FRACTION", None)

    def tearDown(self):
        if self._saved_env is not None:
            os.environ["AUDITOOOR_DEPTH_TEMPLATE_FRACTION"] = self._saved_env
        else:
            os.environ.pop("AUDITOOOR_DEPTH_TEMPLATE_FRACTION", None)
        self._tmp.cleanup()

    def _populate(self, n_guards: int, reasons):
        """Write worklist (n guards) + gaps (one adjudicated row per guard with
        the supplied reason) + an asymmetries file (present, empty -> ran)."""
        worklist = [{"guard_id": f"g{i}", "file_line": f"src/x.sol:{i}"} for i in range(n_guards)]
        gaps = []
        for i, reason in enumerate(reasons):
            gaps.append({
                "guard_id": f"g{i}",
                "file_line": f"src/x.sol:{i}",
                "gap_found": False,
                "ruled_out_reason": reason,
            })
        _jsonl(self.aud / "negative_space_worklist.jsonl", worklist)
        _jsonl(self.aud / "negative_space_gaps.jsonl", gaps)
        # Sibling diff ran with one DISPOSED asymmetry pair so the gate's
        # independent field re-check has sibling_pairs_enumerated > 0 (the
        # anti-stub layer under test is orthogonal to the sibling pass).
        _jsonl(self.aud / "sibling_guard_asymmetries.jsonl", [{
            "schema": "auditooor.sibling_path_guard_diff.v1",
            "pair": "deposit/withdraw",
            "file_lines": ["src/a.sol:1", "src/b.sol:2"],
            "ruled_out_reason": "src/a.sol:1 and src/b.sol:2 share the same "
            "`require(amount <= cap)` guard; no asymmetry; ruled out.",
        }])

    # Case 1: all-identical-template adjudications -> depth-pending + templated high.
    def test_all_identical_template_is_pending(self):
        n = 1240
        self._populate(n, [_ZEBRA_STUB] * n)
        cert = BUILD.build_certificate(self.ws, None)
        self.assertEqual(cert["verdict"], BUILD.VERDICT_PENDING, cert)
        self.assertEqual(cert["genuine_adjudicated"], 0, cert)
        self.assertEqual(cert["templated_or_generic_count"], n, cert)
        self.assertEqual(cert["largest_template_cluster"], n, cert)
        self.assertEqual(cert["largest_template_fraction"], 1.0, cert)
        # The gate must FAIL on this cert.
        cert["build_schema"] = "auditooor.depth_certificate_build.v1"
        (self.aud / "depth_certificate.json").write_text(json.dumps(cert))
        res = CHECK.check_depth(self.ws)
        self.assertEqual(res["verdict"], CHECK.FAIL_DEPTH_PENDING, res)

    # Case 2: distinct substantive per-guard adjudications -> depth-audited.
    def test_distinct_substantive_is_audited(self):
        checks = [
            "require(msg.sender == roleSetter, OnlyRoleSetter())",
            "require(amount <= maxBorrow, ExceedsCap())",
            "revert(add(returnData, 0x20), mload(returnData))",
            "assert(totalSupply == sumBalances)",
            "if (block.timestamp < deadline) revert Expired()",
        ]
        reasons = [_substantive_reason(f"{i:012x}", 200 + i, checks[i % len(checks)]) for i in range(5)]
        self._populate(5, reasons)
        cert = BUILD.build_certificate(self.ws, None)
        self.assertEqual(cert["verdict"], BUILD.VERDICT_AUDITED, cert)
        self.assertEqual(cert["genuine_adjudicated"], 5, cert)
        self.assertEqual(cert["templated_or_generic_count"], 0, cert)
        self.assertLess(cert["largest_template_fraction"], 0.25, cert)
        cert["build_schema"] = "auditooor.depth_certificate_build.v1"
        (self.aud / "depth_certificate.json").write_text(json.dumps(cert))
        res = CHECK.check_depth(self.ws)
        self.assertEqual(res["verdict"], CHECK.PASS, res)

    # Case 3: mixed (some real, >25% template) -> depth-pending.
    def test_mixed_over_threshold_template_is_pending(self):
        # 4 distinct substantive + 6 identical bulk stubs = 10 total; bulk = 0.6 > 0.25.
        checks = [
            "require(a == b, Bad())",
            "require(x <= cap, Cap())",
            "assert(inv())",
            "revert NotAllowed()",
        ]
        substantive = [_substantive_reason(f"{i:012x}", 300 + i, checks[i]) for i in range(4)]
        bulk = [_ZEBRA_STUB] * 6
        self._populate(10, substantive + bulk)
        cert = BUILD.build_certificate(self.ws, None)
        self.assertEqual(cert["verdict"], BUILD.VERDICT_PENDING, cert)
        # Only the 4 distinct substantive ones are genuine; the 6 bulk are not.
        self.assertEqual(cert["genuine_adjudicated"], 4, cert)
        self.assertEqual(cert["templated_or_generic_count"], 6, cert)
        self.assertEqual(cert["largest_template_cluster"], 6, cert)
        self.assertGreater(cert["largest_template_fraction"], 0.25, cert)

    # Case 4: generic-boilerplate-only reason -> not genuine (even if unique).
    def test_generic_boilerplate_only_is_not_genuine(self):
        # 5 DISTINCT-but-generic reasons (vary the trailing count) so the cluster
        # detector does NOT flag them as bulk - genuineness must STILL fail via
        # the SUBSTANTIVE gate because none cite a guard/file:line/code/keyword.
        reasons = [
            f"Guard adjudicated against its protected invariant; outcome variant {i}, "
            "no exploitable gap found by inference."
            for i in range(5)
        ]
        self._populate(5, reasons)
        cert = BUILD.build_certificate(self.ws, None)
        # Cluster is small (distinct trailing variants) but each reason is
        # non-substantive -> genuine_adjudicated must be 0 -> depth-pending.
        self.assertEqual(cert["genuine_adjudicated"], 0, cert)
        self.assertEqual(cert["templated_or_generic_count"], 5, cert)
        self.assertEqual(cert["verdict"], BUILD.VERDICT_PENDING, cert)

    # Case 5: env threshold override changes the cut.
    def test_env_threshold_override(self):
        # 3 distinct substantive + 7 identical bulk = 10; bulk = 0.7.
        checks = ["require(a==b,E())", "assert(c)", "revert X()"]
        substantive = [_substantive_reason(f"{i:012x}", 400 + i, checks[i]) for i in range(3)]
        bulk = [_ZEBRA_STUB] * 7
        self._populate(10, substantive + bulk)

        # Default 0.25: bulk (0.7) is over threshold -> flagged -> 3 genuine.
        cert_default = BUILD.build_certificate(self.ws, None)
        self.assertEqual(cert_default["genuine_adjudicated"], 3, cert_default)
        self.assertEqual(cert_default["template_threshold"], 0.25, cert_default)

        # Raise threshold above 0.7: the bulk cluster is no longer "over
        # threshold", so the (b) bulk gate no longer flags it. The 7 bulk rows
        # are still non-SUBSTANTIVE, so they remain not-genuine via gate (a).
        os.environ["AUDITOOOR_DEPTH_TEMPLATE_FRACTION"] = "0.8"
        cert_hi = BUILD.build_certificate(self.ws, None)
        self.assertEqual(cert_hi["template_threshold"], 0.8, cert_hi)
        # Bulk rows are non-substantive so still not genuine; only 3 genuine.
        self.assertEqual(cert_hi["genuine_adjudicated"], 3, cert_hi)
        # But the largest_template_cluster reporting is unchanged.
        self.assertEqual(cert_hi["largest_template_cluster"], 7, cert_hi)

        # Lower threshold so even a benign small cluster trips (b): with
        # threshold 0.1, a 3-row substantive cluster (0.3) would also be flagged
        # if it shared a shingle - but distinct substantive reasons do not, so
        # only the 7-row bulk (0.7) trips. Sanity: genuine count stays at 3.
        os.environ["AUDITOOOR_DEPTH_TEMPLATE_FRACTION"] = "0.1"
        cert_lo = BUILD.build_certificate(self.ws, None)
        self.assertEqual(cert_lo["template_threshold"], 0.1, cert_lo)
        self.assertEqual(cert_lo["genuine_adjudicated"], 3, cert_lo)

    # Case 6: a small all-genuine set like morpho -> depth-audited (no
    # over-trigger on legitimately-similar-but-distinct reasons).
    def test_small_all_genuine_morpho_like_is_audited(self):
        # Mimic morpho-midnight: every reason shares the SAME analytical prose
        # frame but cites a DISTINCT guard id + file:line + the specific checked
        # statement. These must NOT be flagged as bulk template.
        checks = [
            "require(msg.sender == roleSetter, OnlyRoleSetter())",
            "require(newOwner != address(0), ZeroOwner())",
            "revert(add(returnData, 0x20), mload(returnData))",
            "require(amount <= balance, Insufficient())",
            "assert(supply == sum)",
            "require(deadline >= block.timestamp, Expired())",
            "require(allowance >= amount, NoAllowance())",
            "require(!paused, Paused())",
        ]
        n = 24
        reasons = [_substantive_reason(f"{i:012x}", 200 + i, checks[i % len(checks)]) for i in range(n)]
        self._populate(n, reasons)
        cert = BUILD.build_certificate(self.ws, None)
        self.assertEqual(cert["verdict"], BUILD.VERDICT_AUDITED, cert)
        self.assertEqual(cert["genuine_adjudicated"], n, cert)
        self.assertEqual(cert["templated_or_generic_count"], 0, cert)
        self.assertLess(cert["largest_template_fraction"], 0.25, cert)


class TestAdjudicationGenuinenessUnit(unittest.TestCase):
    """Direct unit coverage of the genuineness classifier helper."""

    def test_substantive_signals(self):
        self.assertTrue(BUILD._is_substantive_reason("checks src/Foo.sol:42 require"))
        self.assertTrue(BUILD._is_substantive_reason("cites `require(x > 0)` code"))
        self.assertTrue(BUILD._is_substantive_reason("guard NS-abc123def at call site"))
        self.assertTrue(BUILD._is_substantive_reason("msg.sender == owner check holds"))
        self.assertFalse(BUILD._is_substantive_reason(
            "guard adjudicated against its protected invariant, no gap"))
        self.assertTrue(BUILD._is_substantive_reason(
            "The module import is not a runtime guard and does not determine execution."))
        self.assertFalse(BUILD._is_substantive_reason(""))

    def test_empty_rows(self):
        g = BUILD.adjudication_genuineness([])
        self.assertEqual(g["genuine_adjudicated"], 0)
        self.assertEqual(g["largest_template_fraction"], 0.0)


if __name__ == "__main__":
    unittest.main()
