"""test_missing_guard_pairs_fold.py - FIX 3 wiring test.

Verifies tools/missing-guard-pairs-fold.py:
  - drives the L30 enumerator over the standard naming pairs,
  - folds UNGUARDED candidate rows into sibling_guard_asymmetries.jsonl as
    auditooor.sibling_path_guard_diff.v1 'asymmetry-candidate' rows,
  - is idempotent (re-run does not duplicate rows),
  - is wired into the audit-depth Makefile target.
"""
import importlib.util
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
TOOL = ROOT / "tools" / "missing-guard-pairs-fold.py"
MAKEFILE = ROOT / "Makefile"


def _load_module():
    spec = importlib.util.spec_from_file_location("missing_guard_pairs_fold", TOOL)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class TestMissingGuardPairsFold(unittest.TestCase):
    def test_wired_into_audit_depth(self):
        text = MAKEFILE.read_text(encoding="utf-8")
        self.assertIn("tools/missing-guard-pairs-fold.py", text)
        # must appear before depth-certificate-build in the file (audit-depth ordering)
        fold_pos = text.index("tools/missing-guard-pairs-fold.py")
        cert_pos = text.index("tools/depth-certificate-build.py")
        self.assertLess(fold_pos, cert_pos,
                        "fold must run before depth-certificate-build")

    def test_fold_emits_asymmetry_candidates(self):
        mod = _load_module()
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            src = ws / "src"
            src.mkdir()
            # claim/finalize pair: the GUARDED arm (calls claim) lives in one
            # file; the UNGUARDED arm (touches finalize, no claim guard) lives in
            # a SEPARATE file - the enumerator is file-level, so the candidate
            # only surfaces when the unguarded site is its own file.
            (src / "Claimer.sol").write_text(
                "contract Claimer {\n"
                "  function doIt() public { claimRewards(); finalizeRewards(); }\n"
                "}\n",
                encoding="utf-8",
            )
            (src / "Finalizer.sol").write_text(
                "contract Finalizer {\n"
                "  function run() public { finalizeRewards(); }\n"
                "}\n",
                encoding="utf-8",
            )
            summary = mod.fold(ws, json_out=False)
            self.assertEqual(summary["pairs_checked"], 4)
            out = ws / ".auditooor" / "sibling_guard_asymmetries.jsonl"
            rows = []
            if out.is_file():
                for line in out.read_text(encoding="utf-8").splitlines():
                    line = line.strip()
                    if line:
                        rows.append(json.loads(line))
            # at least one folded candidate from the claim/finalize pair
            self.assertGreaterEqual(len(rows), 1, "no asymmetry candidate folded")
            self.assertTrue(all(
                r.get("verdict") == "asymmetry-candidate"
                and r.get("schema") == "auditooor.sibling_path_guard_diff.v1"
                for r in rows
            ))

            # idempotency: a second fold must not duplicate ids
            first_ids = {r["candidate_gap_id"] for r in rows}
            mod.fold(ws, json_out=False)
            rows2 = [
                json.loads(l) for l in out.read_text(encoding="utf-8").splitlines() if l.strip()
            ]
            ids2 = [r["candidate_gap_id"] for r in rows2]
            self.assertEqual(len(ids2), len(set(ids2)), "duplicate ids after re-run")
            self.assertEqual(set(ids2), first_ids, "re-run changed the id set")

    def test_cli_runs(self):
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            (ws / "src").mkdir()
            proc = subprocess.run(
                ["python3", str(TOOL), "--workspace", str(ws), "--json"],
                capture_output=True, text=True, timeout=120,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            data = json.loads(proc.stdout)
            self.assertEqual(data["schema"], "auditooor.missing_guard_pairs_fold.v1")


class TestSharedScopeExclusionWiring(unittest.TestCase):
    """Guard test for the single-source-of-truth OOS prune (step 5).

    Proves the fold drops an OOS (vendored / test-infra) asymmetry candidate via
    scope_exclusion.is_oos, while an in-scope sibling candidate still folds. This
    pins the wiring against a regression that would either:
      - re-introduce an ad-hoc exclusion table (drift), or
      - drop the helper and let a vendored @openzeppelin / *.t.sol arm seed a
        depth-cert input (a false-positive OOS asymmetry candidate).
    Generic: ecosystem-convention markers only (no workspace literal).
    """

    def test_shared_helper_loaded(self):
        mod = _load_module()
        # The wiring must actually pick up the shared helper; if it silently
        # failed to load, the OOS prune would be a no-op (fail-safe but untested).
        self.assertIsNotNone(
            mod._SCOPE_EXCL,
            "scope_exclusion helper not loaded - OOS prune would be a no-op",
        )

    def test_oos_surface_excluded_inscope_present(self):
        mod = _load_module()
        with tempfile.TemporaryDirectory() as td:
            ws = Path(td)
            src = ws / "src"
            src.mkdir()
            # In-scope claim/finalize pair: guarded claim arm + unguarded finalize
            # arm in its own file -> a legitimate in-scope asymmetry candidate.
            (src / "Claimer.sol").write_text(
                "contract Claimer {\n"
                "  function doIt() public { claimRewards(); finalizeRewards(); }\n"
                "}\n",
                encoding="utf-8",
            )
            (src / "Finalizer.sol").write_text(
                "contract Finalizer {\n"
                "  function run() public { finalizeRewards(); }\n"
                "}\n",
                encoding="utf-8",
            )
            # OOS arm #1: vendored OpenZeppelin copy (report-to-vendor OOS clause).
            oz = src / "vendor" / "@openzeppelin" / "contracts"
            oz.mkdir(parents=True)
            (oz / "OZFinal.sol").write_text(
                "contract OZFinal { function run() public { finalizeRewards(); } }\n",
                encoding="utf-8",
            )
            # OOS arm #2: a foundry test file (test infra, never protocol source).
            (src / "Finalizer.t.sol").write_text(
                "contract FinalizerTest { function run() public { finalizeRewards(); } }\n",
                encoding="utf-8",
            )

            mod.fold(ws, json_out=False)
            out = ws / ".auditooor" / "sibling_guard_asymmetries.jsonl"
            rows = []
            if out.is_file():
                rows = [
                    json.loads(l)
                    for l in out.read_text(encoding="utf-8").splitlines()
                    if l.strip()
                ]
            b_files = {str(r.get("path_b", {}).get("file", "")) for r in rows}

            # In-scope candidate survives.
            self.assertTrue(
                any(f.endswith("Finalizer.sol") for f in b_files),
                f"in-scope Finalizer.sol candidate missing: {sorted(b_files)}",
            )
            # OOS candidates are gone.
            self.assertFalse(
                any("@openzeppelin" in f for f in b_files),
                f"vendored @openzeppelin OOS candidate leaked: {sorted(b_files)}",
            )
            self.assertFalse(
                any(".t.sol" in f for f in b_files),
                f"test-infra .t.sol OOS candidate leaked: {sorted(b_files)}",
            )


if __name__ == "__main__":
    unittest.main()
