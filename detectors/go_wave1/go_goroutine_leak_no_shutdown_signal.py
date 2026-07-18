"""
go_goroutine_leak_no_shutdown_signal.py

Detects functions that spawn a long-lived background goroutine running an
unbounded loop (`go func() { for { ... } }()`) where the loop has NO
shutdown signal - no `select` on a `ctx.Done()` / quit / stop / done
channel - so the goroutine never exits.

In a cosmos-sdk node, coordinator service, or relayer, a spawned worker
loop that cannot observe a cancellation signal leaks on every restart and,
worse, blocks `Stop()` / graceful shutdown: the supervisor waits forever
for a goroutine that has no exit path -> the node hangs on SIGTERM and
must be SIGKILL-ed, risking unflushed-state corruption on the next start.

The safe shape always selects on a done channel or returns when the
context is cancelled:
    for {
        select {
        case <-ctx.Done(): return
        case <-ticker.C: doWork()
        }
    }

Bug class: HIGH (graceful-shutdown-deadlock / resource-leak-on-shutdown).
Attack-class anchor: zero-coverage classes `graceful-shutdown-deadlock`
("Node hangs on graceful shutdown due to goroutine deadlock") and
`resource-leak-on-shutdown`.
Platform: Go services - cosmos-sdk nodes, Spark coordinator, IBC relayers.
"""

from __future__ import annotations

import re

DETECTOR_ID = "go_wave1.go_goroutine_leak_no_shutdown_signal"

# A goroutine spawned with an inline closure: `go func(...) { ... }(...)`.
_GO_FUNC_RE = re.compile(r"\bgo\s+func\s*\(")

# The goroutine body contains an unbounded loop.
_UNBOUNDED_LOOP_RE = re.compile(
    r"\bfor\s*\{"                       # for {
    r"|\bfor\s+true\s*\{"               # for true {
    r"|\bfor\s*;\s*;\s*\{"              # for ;; {
)

# A shutdown / cancellation signal the loop can observe.
_SHUTDOWN_SIGNAL_RE = re.compile(
    r"(<-\s*ctx\.Done\s*\(\s*\)"
    r"|<-\s*[A-Za-z_][\w.]*\.Done\s*\(\s*\)"
    r"|<-\s*[A-Za-z_][\w.]*\.(quit|done|stop|stopCh|quitCh|doneCh"
    r"|shutdown|cancelCh)\b"
    r"|<-\s*(quit|done|stop|stopCh|quitCh|doneCh|shutdown|cancelCh)\b"
    r"|ctx\.Err\s*\(\s*\)\s*!=\s*nil"
    r"|case\s*<-\s*[A-Za-z_][\w.]*\s*:)"   # any select-on-channel case
)


def run(engine, filepath: str):
    hits = []
    for fn in engine.functions():
        name = engine.fn_name(fn)
        if not name or name == "?":
            continue
        body = engine.fn_body(fn)
        if body is None:
            continue
        body_text = engine.text(body)

        if not _GO_FUNC_RE.search(body_text):
            continue
        if not _UNBOUNDED_LOOP_RE.search(body_text):
            continue
        # If the function body has any shutdown-signal observation, treat
        # the goroutine as cancellable -> safe.
        if _SHUTDOWN_SIGNAL_RE.search(body_text):
            continue

        hits.append({
            "severity": "high",
            "line": engine.line(fn),
            "col": engine.col(fn),
            "snippet": engine.text(fn).splitlines()[0][:160],
            "message": (
                f"`{name}` spawns a background goroutine with an unbounded "
                f"`for {{}}` loop and no shutdown signal (no select on "
                f"ctx.Done() / quit channel). The goroutine never exits: it "
                f"leaks on restart and blocks graceful shutdown -> node "
                f"hangs on SIGTERM. Select on a done channel. "
                f"(class: graceful-shutdown-deadlock)"),
        })
    return hits
