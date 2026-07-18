#!/usr/bin/env python3
"""Focused final-paste hygiene tests for non-Solidity PoC/report sections."""

from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOLS = ROOT / "tools"
RENDERER = TOOLS / "submission-render.py"

if str(TOOLS) not in sys.path:
    sys.path.insert(0, str(TOOLS))


def _load_renderer_module():
    spec = importlib.util.spec_from_file_location("_submission_render_under_test", RENDERER)
    assert spec is not None and spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


RENDER = _load_renderer_module()


def _section(text: str, heading: str) -> str:
    marker = f"## {heading}"
    start = text.find(marker)
    if start == -1:
        return ""
    rest = text[start + len(marker):]
    next_h2 = rest.find("\n## ")
    if next_h2 == -1:
        return rest
    return rest[:next_h2]


class SubmissionRenderFinalPasteHygieneTest(unittest.TestCase):
    def test_go_poc_section_preserves_inline_runnable_proof(self) -> None:
        raw = """### Draft 1 - Go refund tweak replay
#### Severity
- **Net severity:** High.

#### Likelihood Explanation
- **Likelihood:** High - deterministic state transition.

#### Impact Explanation
- **Impact:** High - validator refunds can be misdirected.

#### Proof of Concept
The local source is `pocs/refund_tweak_replay_test.go`, but the final paste must
carry the runnable proof inline.

```go
package keeper_test

import "testing"

func TestRefundTweakReplayFinalPaste(t *testing.T) {
    account := "victim"
    first := deriveRefundTweak(account, 7)
    second := deriveRefundTweak(account, 7)
    if first != second {
        t.Fatalf("expected reused tweak to collide")
    }
}
```

```text
$ go test ./x/refund/keeper -run TestRefundTweakReplayFinalPaste -count=1
--- PASS: TestRefundTweakReplayFinalPaste (0.00s)
PASS
```

#### Recommendation
Bind the tweak derivation to the spend nonce.
"""

        rendered = RENDER.render_draft(raw, "1", "Go refund tweak replay")
        poc = _section(rendered, "Proof of Concept")

        self.assertIn("<poc-dir>/refund_tweak_replay_test.go", poc)
        self.assertIn("```go", poc)
        self.assertIn("func TestRefundTweakReplayFinalPaste", poc)
        self.assertIn("go test ./x/refund/keeper", poc)
        self.assertIn("--- PASS: TestRefundTweakReplayFinalPaste", poc)
        self.assertIn("PASS", poc)

    def test_dlt_report_section_preserves_inline_evidence_not_only_path(self) -> None:
        raw = """### Draft 2 - DLT epoch finality report
#### Severity
- **Net severity:** Medium.

#### Impact Explanation
- **Impact:** Medium - slashable stake can be incorrectly finalized.

#### Finding Description
The Blockchain/DLT path accepts a stale epoch root after the validator set
rotates.

#### DLT validation report
Report artifact: `reports/dlt_epoch_finality.md`.

Inline report excerpt for final paste:

```text
Asset: Blockchain/DLT
Target: x/finality/keeper/msg_server.go:144
Command: go test ./x/finality/keeper -run TestStaleEpochRootFinalizes -count=1
Result: FAIL before patch, PASS after binding epoch root to validator-set hash
Observed: stale root finalized for epoch 42 after validator set 43 was active
```

#### Proof of Concept
```go
func TestStaleEpochRootFinalizes(t *testing.T) {
    keeper := newFinalityKeeper()
    keeper.SetValidatorSetHash(43, "new-set")
    stale := Header{Epoch: 42, Root: "old-root"}
    if err := keeper.Finalize(stale); err != nil {
        t.Fatalf("vulnerable path should accept stale root before fix: %v", err)
    }
}
```
"""

        rendered = RENDER.render_draft(raw, "2", "DLT epoch finality report")
        report = _section(rendered, "Finding")
        poc = _section(rendered, "Proof of Concept")

        self.assertIn("### DLT validation report", report)
        self.assertIn("Asset: Blockchain/DLT", report)
        self.assertIn("x/finality/keeper/msg_server.go:144", report)
        self.assertIn("go test ./x/finality/keeper", report)
        self.assertIn("Observed: stale root finalized", report)
        self.assertIn("```go", poc)
        self.assertIn("func TestStaleEpochRootFinalizes", poc)


if __name__ == "__main__":
    unittest.main()
