from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]
SCRIPT = REPO / "tools" / "auto-fix-draft.py"


def _load_auto_fix():
    spec = importlib.util.spec_from_file_location("auto_fix_draft_test_module", SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class AutoFixDraftTest(unittest.TestCase):
    def test_go_poc_reference_is_recognized(self) -> None:
        module = _load_auto_fix()
        text = """# Source-only Go DLT proof

## Proof of Concept

Run:

```bash
go test ./poc -run TestCoopExitChainWatcherBypass -count=1 -v
```

PoC path: `poc/coop_exit_chain_watcher_bypass_test.go.draft`

```go
func TestCoopExitChainWatcherBypass(t *testing.T) {
    t.Fatalf("fixture")
}
```
"""
        new_text, changed, warnings = module.fix_poc_reference(text)
        self.assertEqual(new_text, text)
        self.assertFalse(changed)
        self.assertEqual(warnings, [])

    def test_missing_polyglot_poc_reference_still_warns(self) -> None:
        module = _load_auto_fix()
        text = """# Draft without a runnable proof

## Proof of Concept

The issue is visible by inspection.
"""
        new_text, changed, warnings = module.fix_poc_reference(text)
        self.assertEqual(new_text, text)
        self.assertFalse(changed)
        self.assertEqual(len(warnings), 1)
        self.assertIn("Forge", warnings[0])
        self.assertIn("Rust", warnings[0])
        self.assertIn("Go", warnings[0])


if __name__ == "__main__":
    unittest.main()
