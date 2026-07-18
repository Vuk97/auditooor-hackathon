"""Guard: wave-2 C2 - go-dynamic-engine-runner accepts --strict (was rc2 abort -> Go arm never ran)."""
import subprocess, unittest
from pathlib import Path
RUNNER = Path(__file__).resolve().parents[1] / "go-dynamic-engine-runner.sh"
class TestGoStrict(unittest.TestCase):
    def test_strict_not_unknown_option(self):
        p = subprocess.run(["bash", str(RUNNER), "/tmp", "--strict", "--dry-run"],
                           capture_output=True, text=True, timeout=60)
        self.assertNotIn("unknown option: --strict", p.stderr,
                         "C2: --strict must be accepted, not aborted")
        self.assertNotEqual(p.returncode, 2, "C2: runner must not abort rc2 on --strict")
if __name__ == "__main__":
    unittest.main()
