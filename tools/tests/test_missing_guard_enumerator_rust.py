"""
test_missing_guard_enumerator_rust.py
Tests for the --rust-trait-mode extension of
tools/missing-guard-callsite-enumerator.sh (L30 helper).

Scenario:
  - Trait `LeafGuard` with method `validate_not_exited`
  - 2 impls: for `Sender` and `Receiver`
  - 4 call sites consuming Sender/Receiver instances:
      site_safe_sender.rs    — calls validate_not_exited()  → SAFE
      site_safe_receiver.rs  — calls validate_not_exited()  → SAFE
      site_exposed_sender.rs — touches leaf_status, no guard → CANDIDATE
      site_exposed_receiver.rs — touches leaf_status, no guard → CANDIDATE

Test 1: --rust-trait-mode returns the 2 exposed sites.
Test 2: flat-grep default still works for non-trait plain-name guards.
Test 3: tool exits 0 with "No trait-dispatch" when all sites are guarded.
"""

import os
import stat
import subprocess
import sys
import tempfile
import textwrap
import unittest


SCRIPT = os.path.join(
    os.path.dirname(__file__), "..", "missing-guard-callsite-enumerator.sh"
)
SCRIPT = os.path.abspath(SCRIPT)


def _run(repo_root: str, guard: str, resource: str, extra_args=()) -> subprocess.CompletedProcess:
    cmd = [SCRIPT, repo_root, guard, resource, "--language", "rs"] + list(extra_args)
    return subprocess.run(cmd, capture_output=True, text=True)


def _build_crate(tmpdir: str) -> str:
    """
    Populate tmpdir with a minimal fake Rust crate for the 4-site scenario.
    Returns the tmpdir path (the repo-root argument to the script).
    """
    src = os.path.join(tmpdir, "src")
    os.makedirs(src, exist_ok=True)

    # trait definition + both impls in one file
    _write(os.path.join(src, "guard_trait.rs"), """\
        pub trait LeafGuard {
            fn validate_not_exited(&self);
        }

        pub struct Sender {
            pub leaf_status: u8,
        }

        pub struct Receiver {
            pub leaf_status: u8,
        }

        impl LeafGuard for Sender {
            fn validate_not_exited(&self) {
                assert_eq!(self.leaf_status, 0, "sender already exited");
            }
        }

        impl LeafGuard for Receiver {
            fn validate_not_exited(&self) {
                assert_eq!(self.leaf_status, 0, "receiver already exited");
            }
        }
    """)

    # SAFE: Sender site — calls validate_not_exited before using leaf_status
    _write(os.path.join(src, "site_safe_sender.rs"), """\
        use crate::guard_trait::{LeafGuard, Sender};

        pub fn process_sender(s: &Sender) {
            s.validate_not_exited();
            let _ = s.leaf_status;
        }
    """)

    # SAFE: Receiver site — calls validate_not_exited before using leaf_status
    _write(os.path.join(src, "site_safe_receiver.rs"), """\
        use crate::guard_trait::{LeafGuard, Receiver};

        pub fn process_receiver(r: &Receiver) {
            r.validate_not_exited();
            let _ = r.leaf_status;
        }
    """)

    # EXPOSED: Sender site — touches leaf_status, guard absent
    _write(os.path.join(src, "site_exposed_sender.rs"), """\
        use crate::guard_trait::Sender;

        pub fn finalize_sender(s: &Sender) {
            // Missing guard call!
            let status = s.leaf_status;
            println!("sender status: {}", status);
        }
    """)

    # EXPOSED: Receiver site — touches leaf_status, guard absent
    _write(os.path.join(src, "site_exposed_receiver.rs"), """\
        use crate::guard_trait::Receiver;

        pub fn finalize_receiver(r: &Receiver) {
            // Missing guard call!
            let status = r.leaf_status;
            println!("receiver status: {}", status);
        }
    """)

    # main.rs — uses both types, no resource pattern hit, no guard
    _write(os.path.join(src, "main.rs"), """\
        mod guard_trait;
        mod site_safe_sender;
        mod site_safe_receiver;
        mod site_exposed_sender;
        mod site_exposed_receiver;

        fn main() {}
    """)

    return tmpdir


def _build_all_guarded_crate(tmpdir: str) -> str:
    """
    Variant where ALL sites call validate_not_exited → no candidates.
    """
    src = os.path.join(tmpdir, "src")
    os.makedirs(src, exist_ok=True)

    _write(os.path.join(src, "guard_trait.rs"), """\
        pub trait LeafGuard {
            fn validate_not_exited(&self);
        }
        pub struct Sender { pub leaf_status: u8 }
        impl LeafGuard for Sender {
            fn validate_not_exited(&self) {}
        }
    """)

    _write(os.path.join(src, "site_a.rs"), """\
        use crate::guard_trait::{LeafGuard, Sender};
        pub fn run(s: &Sender) {
            s.validate_not_exited();
            let _ = s.leaf_status;
        }
    """)

    return tmpdir


def _write(path: str, content: str) -> None:
    with open(path, "w") as fh:
        fh.write(textwrap.dedent(content))


class TestMissingGuardEnumeratorRust(unittest.TestCase):

    def setUp(self):
        # Verify the script exists and is executable.
        self.assertTrue(os.path.isfile(SCRIPT), f"Script not found: {SCRIPT}")
        script_stat = os.stat(SCRIPT)
        self.assertTrue(
            script_stat.st_mode & stat.S_IXUSR,
            f"Script is not executable: {SCRIPT}",
        )

    # ------------------------------------------------------------------
    # Test 1: --rust-trait-mode surfaces the 2 exposed call sites
    # ------------------------------------------------------------------
    def test_trait_mode_finds_exposed_sites(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            repo = _build_crate(tmpdir)
            result = _run(
                repo,
                "LeafGuard::validate_not_exited",
                "leaf_status",
                extra_args=["--rust-trait-mode"],
            )

            out = result.stdout
            # Tool should exit 0
            self.assertEqual(
                result.returncode, 0,
                f"Expected exit 0.\nstdout:\n{out}\nstderr:\n{result.stderr}",
            )

            # Both exposed files must appear in output
            self.assertIn(
                "site_exposed_sender",
                out,
                "Expected site_exposed_sender.rs in CANDIDATE output",
            )
            self.assertIn(
                "site_exposed_receiver",
                out,
                "Expected site_exposed_receiver.rs in CANDIDATE output",
            )

            # Both SAFE files must NOT appear as candidates
            # (They're in guarded section possibly, but NOT in the MISSING-GUARD rows)
            missing_guard_lines = [
                ln for ln in out.splitlines() if "MISSING-GUARD" in ln
            ]
            candidate_files_in_mg = " ".join(missing_guard_lines)
            self.assertNotIn(
                "site_safe_sender",
                candidate_files_in_mg,
                "site_safe_sender.rs must not appear in MISSING-GUARD output",
            )
            self.assertNotIn(
                "site_safe_receiver",
                candidate_files_in_mg,
                "site_safe_receiver.rs must not appear in MISSING-GUARD output",
            )

            # MISSING-GUARD label must cite the full guard name
            for ln in missing_guard_lines:
                self.assertIn(
                    "LeafGuard::validate_not_exited",
                    ln,
                    "MISSING-GUARD lines must cite full guard name",
                )

    # ------------------------------------------------------------------
    # Test 1b: auto-activation when guard name contains "::"
    # (no --rust-trait-mode flag passed explicitly)
    # ------------------------------------------------------------------
    def test_auto_activate_on_double_colon_guard(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            repo = _build_crate(tmpdir)
            # Do NOT pass --rust-trait-mode; auto-activation should fire
            result = _run(
                repo,
                "LeafGuard::validate_not_exited",
                "leaf_status",
            )
            out = result.stdout
            self.assertEqual(
                result.returncode, 0,
                f"Expected exit 0 on auto-activation.\nstdout:\n{out}\nstderr:\n{result.stderr}",
            )
            # rust-trait-mode: 1 must appear in the header
            self.assertIn(
                "rust-trait-mode: 1",
                out,
                "Expected 'rust-trait-mode: 1' in output when auto-activated",
            )
            self.assertIn("site_exposed_sender", out)
            self.assertIn("site_exposed_receiver", out)

    # ------------------------------------------------------------------
    # Test 2: flat-grep default still works for non-trait plain-name guards
    # ------------------------------------------------------------------
    def test_flat_grep_default_non_trait_guard(self):
        """
        Without --rust-trait-mode and with a guard name that has no '::',
        the old flat-grep path executes and finds guarded + unguarded files.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            src = os.path.join(tmpdir, "src")
            os.makedirs(src, exist_ok=True)

            # file with guard call + resource
            _write(os.path.join(src, "safe.rs"), """\
                fn require_auth() {}
                fn spend_balance(bal: u64) {
                    require_auth();
                    let _ = bal;
                }
            """)

            # file with resource but no guard
            _write(os.path.join(src, "exposed.rs"), """\
                fn spend_balance_unguarded(bal: u64) {
                    // Missing require_auth()
                    let _ = bal;
                }
            """)

            result = _run(
                tmpdir,
                "require_auth",
                "spend_balance|bal",
            )
            out = result.stdout

            # Flat-grep path: guard found → exits without exit 4
            self.assertNotIn(
                "No callers of",
                out,
                "Flat-grep should find require_auth in safe.rs",
            )
            # GUARDED section must mention safe.rs
            self.assertIn("safe.rs", out, "safe.rs should appear in GUARDED section")
            # exposed.rs should appear as a CANDIDATE
            self.assertIn(
                "exposed.rs",
                out,
                "exposed.rs should appear as UNGUARDED CANDIDATE",
            )
            self.assertEqual(
                result.returncode, 0,
                f"Expected exit 0.\nstdout:\n{out}\nstderr:\n{result.stderr}",
            )

    # ------------------------------------------------------------------
    # Test 3: exit 0 with "No trait-dispatch" when all sites are guarded
    # ------------------------------------------------------------------
    def test_trait_mode_no_candidates_when_all_guarded(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            repo = _build_all_guarded_crate(tmpdir)
            result = _run(
                repo,
                "LeafGuard::validate_not_exited",
                "leaf_status",
                extra_args=["--rust-trait-mode"],
            )
            out = result.stdout
            self.assertEqual(
                result.returncode, 0,
                f"Expected exit 0.\nstdout:\n{out}\nstderr:\n{result.stderr}",
            )
            self.assertIn(
                "No trait-dispatch missing-guard candidates",
                out,
                "Expected 'No trait-dispatch' verdict when all sites guarded",
            )
            # No MISSING-GUARD lines expected
            missing_guard_lines = [ln for ln in out.splitlines() if "MISSING-GUARD" in ln]
            self.assertEqual(
                len(missing_guard_lines),
                0,
                f"Expected 0 MISSING-GUARD lines; got: {missing_guard_lines}",
            )


if __name__ == "__main__":
    unittest.main()
