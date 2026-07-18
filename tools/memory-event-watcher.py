#!/usr/bin/env python3
"""memory-event-watcher.py — Layer L1 of §M_ARCH memory architecture.

Event-driven filesystem watcher that auto-emits Obsidian vault notes for
relevant events.  Uses macOS fsevents via watchdog when available; falls back
to polling every 30 s on other platforms or when watchdog is absent.

Latency target: event → vault note < 5 min.

Usage:
  # Daemon mode (real fsevents / polling)
  python3 tools/memory-event-watcher.py [--config <cfg.yaml>] [--vault-dir obsidian-vault]

  # Self-test / CI mode — no real filesystem watching required
  python3 tools/memory-event-watcher.py --simulate-events <file.jsonl> \\
      [--vault-dir /tmp/test-vault] [--report-out reports/memory_event_watcher_self_test.json]

Watch paths (configurable via YAML):
  /private/tmp/auditooor-inventory/               — overnight loop logs
  <repo>/agent_outputs/                           — dispatch outputs
  <repo>/.git/refs/heads/                         — branch updates (commit proxy)
  <repo>/tools/calibration/                       — calibration log appends

Throttle: max 100 events/min written to vault.  Overflow is counted + surfaced.
Privacy filter: redacts clob_creds, .env, private_key, mnemonic, 0x[0-9a-f]{64}.

Constraints:
  - NEVER modifies source / watch-path files (read-only on those paths)
  - No LLM calls; pure local logic
  - Vault gitignored — these notes are never committed
"""
from __future__ import annotations

import argparse
import datetime as _dt
import hashlib
import json
import os
import re
import subprocess
import sys
import time
import uuid
from collections import deque
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Optional YAML support
# ---------------------------------------------------------------------------
try:
    import yaml as _yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False

# ---------------------------------------------------------------------------
# Optional watchdog
# ---------------------------------------------------------------------------
try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler, FileCreatedEvent, FileModifiedEvent
    HAS_WATCHDOG = True
except ImportError:
    HAS_WATCHDOG = False

# ---------------------------------------------------------------------------
# Repo layout
# ---------------------------------------------------------------------------
REPO_ROOT = Path(__file__).resolve().parent.parent
COMMIT_EMITTER = REPO_ROOT / "tools" / "memory-commits-emitter.py"

# ---------------------------------------------------------------------------
# Privacy filter
# ---------------------------------------------------------------------------
_PRIVACY_PATTERNS = [
    (re.compile(r'clob_creds', re.IGNORECASE), "[REDACTED:clob_creds]"),
    (re.compile(r'private[_\-]?key\s*[:=]\s*\S+', re.IGNORECASE), "private_key=[REDACTED]"),
    (re.compile(r'mnemonic\s*[:=]\s*\S+', re.IGNORECASE), "mnemonic=[REDACTED]"),
    (re.compile(r'0x[0-9a-fA-F]{64}'), "0x[REDACTED-64BYTE-SECRET]"),
    (re.compile(r'(?i)(?:password|passwd|secret|api[_\-]?key)\s*[:=]\s*\S+'),
     "[REDACTED:credential]"),
]


def redact(text: str) -> tuple[str, int]:
    """Apply privacy filters to text.  Returns (redacted_text, redaction_count)."""
    count = 0
    for pat, replacement in _PRIVACY_PATTERNS:
        new_text, n = pat.subn(replacement, text)
        count += n
        text = new_text
    return text, count


# ---------------------------------------------------------------------------
# Event classification
# ---------------------------------------------------------------------------
_EVENT_TYPE_RULES: list[tuple[re.Pattern, str]] = [
    (re.compile(r'\.git/refs/heads/'), "commit"),
    (re.compile(r'agent_outputs/'), "agent-dispatch"),
    (re.compile(r'calibration/.*\.jsonl'), "calibration-row"),
    (re.compile(r'auditooor-inventory/'), "log-line"),
]


def classify_event(path: str) -> str:
    for pat, etype in _EVENT_TYPE_RULES:
        if pat.search(path):
            return etype
    # Infer from extension
    ext = Path(path).suffix.lower()
    if ext in (".md", ".json", ".jsonl", ".log", ".txt"):
        return "output-file"
    return "output-file"


def summarise_event(event_type: str, src_path: str) -> str:
    """Return a 2-3 sentence human summary for the event."""
    fname = Path(src_path).name
    if event_type == "commit":
        branch = Path(src_path).name
        return (
            f"Branch reference updated: `{branch}`. "
            f"This signals a new commit landed on `{branch}`. "
            f"Check `git log {branch}` for the latest changes."
        )
    if event_type == "agent-dispatch":
        return (
            f"New agent dispatch output detected: `{fname}`. "
            f"An automated agent has written results to `agent_outputs/`. "
            f"Review the output for actionable findings or status updates."
        )
    if event_type == "calibration-row":
        return (
            f"Calibration log updated: `{fname}`. "
            f"A new calibration measurement was appended. "
            f"Run `make vault-sync` to surface the updated provider stats."
        )
    if event_type == "log-line":
        return (
            f"Overnight loop log updated: `{fname}`. "
            f"The overnight inventory pipeline produced new output. "
            f"Review `/private/tmp/auditooor-inventory/` for the latest run."
        )
    return (
        f"File event detected: `{fname}`. "
        f"A file was created or modified in a watched path. "
        f"Source path: `{src_path}`."
    )


# ---------------------------------------------------------------------------
# Throttle
# ---------------------------------------------------------------------------
class RateThrottle:
    """Allow at most max_per_min events per minute; honest drop counting."""

    def __init__(self, max_per_min: int = 100):
        self._max = max_per_min
        self._window: deque[float] = deque()
        self.total_dropped = 0

    def allow(self) -> bool:
        now = time.monotonic()
        cutoff = now - 60.0
        while self._window and self._window[0] < cutoff:
            self._window.popleft()
        if len(self._window) >= self._max:
            self.total_dropped += 1
            return False
        self._window.append(now)
        return True


# ---------------------------------------------------------------------------
# Vault note emitter
# ---------------------------------------------------------------------------
def emit_note(
    vault_dir: Path,
    event_type: str,
    src_path: str,
    raw_content: str = "",
    extra_meta: dict | None = None,
    *,
    throttle: RateThrottle,
) -> Path | None:
    """Emit a Markdown vault note.  Returns None if throttled/dropped."""
    if not throttle.allow():
        return None

    now = _dt.datetime.now(_dt.timezone.utc).replace(tzinfo=None)
    date_str = now.strftime("%Y-%m-%d")
    hour_str = now.strftime("%H")
    event_id = str(uuid.uuid4())[:8]
    fingerprint = hashlib.sha256(f"{src_path}:{now.isoformat()}".encode()).hexdigest()[:16]

    # Redact
    redacted_path, rc = redact(src_path)
    redacted_body, body_rc = redact(raw_content)
    total_rc = rc + body_rc

    summary = summarise_event(event_type, src_path)
    summary_r, _ = redact(summary)

    note_dir = vault_dir / "events" / date_str / hour_str
    note_dir.mkdir(parents=True, exist_ok=True)
    note_path = note_dir / f"{event_id}.md"

    meta = {
        "timestamp": now.isoformat() + "Z",
        "event_type": event_type,
        "source_path": redacted_path,
        "fingerprint": fingerprint,
        "redaction_count": total_rc,
        "dropped_events_so_far": throttle.total_dropped,
    }
    if extra_meta:
        meta.update(extra_meta)

    yaml_block = "\n".join(f"{k}: {json.dumps(v)}" for k, v in meta.items())
    body_section = f"\n\n---\n\n```\n{redacted_body[:2000]}\n```" if redacted_body.strip() else ""

    content = f"---\n{yaml_block}\n---\n\n## Event: {event_type}\n\n{summary_r}{body_section}\n"
    note_path.write_text(content, encoding="utf-8")
    return note_path


def emit_commit_note(vault_dir: Path, src_path: str) -> None:
    """Best-effort bridge from branch-ref updates into commits/<sha>.md notes."""
    if not COMMIT_EMITTER.is_file():
        print(f"[watcher] commit emitter missing: {COMMIT_EMITTER}")
        return
    try:
        proc = subprocess.run(
            [
                sys.executable,
                str(COMMIT_EMITTER),
                "--repo-root",
                str(REPO_ROOT),
                "--vault-dir",
                str(vault_dir),
                "--ref-path",
                src_path,
            ],
            text=True,
            capture_output=True,
            timeout=15,
            check=False,
        )
    except Exception as exc:  # pragma: no cover - defensive bridge logging
        print(f"[watcher] commit emitter bridge failed for {src_path}: {exc}")
        return
    if proc.returncode != 0:
        detail = proc.stderr.strip() or proc.stdout.strip() or "unknown error"
        print(f"[watcher] commit emitter error for {src_path}: {detail}")
        return
    for line in proc.stdout.splitlines():
        if line.strip():
            print(f"[watcher] {line}")


# ---------------------------------------------------------------------------
# Hourly rollup
# ---------------------------------------------------------------------------
def hourly_rollup(vault_dir: Path, date_str: str, hour_str: str) -> Path | None:
    """Summarise per-event notes in <date>/<hour>/ into HOURLY-<HH>.md."""
    hour_dir = vault_dir / "events" / date_str / hour_str
    if not hour_dir.exists():
        return None

    notes = sorted(hour_dir.glob("????????.md"))
    if not notes:
        return None

    counts: dict[str, int] = {}
    redaction_total = 0
    drop_total = 0

    for note in notes:
        text = note.read_text(encoding="utf-8")
        # Parse frontmatter event_type
        m = re.search(r'^event_type:\s*"([^"]+)"', text, re.MULTILINE)
        etype = m.group(1) if m else "unknown"
        counts[etype] = counts.get(etype, 0) + 1
        m2 = re.search(r'^redaction_count:\s*(\d+)', text, re.MULTILINE)
        if m2:
            redaction_total += int(m2.group(1))
        m3 = re.search(r'^dropped_events_so_far:\s*(\d+)', text, re.MULTILINE)
        if m3:
            drop_total = max(drop_total, int(m3.group(1)))

    rollup_path = vault_dir / "events" / date_str / f"HOURLY-{hour_str}.md"
    lines = [
        f"---",
        f'date: "{date_str}"',
        f'hour: "{hour_str}"',
        f"total_notes: {len(notes)}",
        f"redaction_total: {redaction_total}",
        f"drop_total: {drop_total}",
        f"---",
        f"",
        f"# Hourly Rollup — {date_str} {hour_str}:00 UTC",
        f"",
        f"| Event Type | Count |",
        f"|---|---|",
    ]
    for etype, cnt in sorted(counts.items()):
        lines.append(f"| {etype} | {cnt} |")
    lines += [
        f"",
        f"**Total events**: {len(notes)}  ",
        f"**Redactions applied**: {redaction_total}  ",
        f"**Throttle drops (cumulative)**: {drop_total}  ",
    ]
    rollup_path.write_text("\n".join(lines), encoding="utf-8")
    return rollup_path


# ---------------------------------------------------------------------------
# Simulate-events mode (self-test / CI)
# ---------------------------------------------------------------------------
def run_simulate(
    events_file: Path,
    vault_dir: Path,
    throttle: RateThrottle,
    report_out: Path | None,
) -> int:
    """Read JSONL of synthetic events, emit vault notes, save self-test report."""
    vault_dir.mkdir(parents=True, exist_ok=True)

    if not events_file.exists():
        print(f"[simulate] ERROR: events file not found: {events_file}", file=sys.stderr)
        return 2

    raw_events: list[dict] = []
    with open(events_file, encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            try:
                raw_events.append(json.loads(line))
            except json.JSONDecodeError as e:
                print(f"[simulate] WARN line {lineno}: {e}", file=sys.stderr)

    print(f"[simulate] Loaded {len(raw_events)} events from {events_file}")

    emitted_paths: list[Path] = []
    drop_events: list[dict] = []

    for ev in raw_events:
        src = ev.get("source_path", "/unknown")
        etype = ev.get("event_type") or classify_event(src)
        raw_content = ev.get("raw_content", "")

        note_path = emit_note(
            vault_dir=vault_dir,
            event_type=etype,
            src_path=src,
            raw_content=raw_content,
            extra_meta={"simulated": True},
            throttle=throttle,
        )
        if note_path is None:
            drop_events.append(ev)
        else:
            emitted_paths.append(note_path)

    # Spot-check 3 random notes
    import random
    sample_notes: list[dict] = []
    check_pool = emitted_paths[:] if len(emitted_paths) <= 3 else random.sample(emitted_paths, 3)
    for p in check_pool:
        text = p.read_text(encoding="utf-8")
        ts_m = re.search(r'^timestamp:\s*"([^"]+)"', text, re.MULTILINE)
        et_m = re.search(r'^event_type:\s*"([^"]+)"', text, re.MULTILINE)
        sp_m = re.search(r'^source_path:\s*"([^"]+)"', text, re.MULTILINE)
        sample_notes.append({
            "path": str(p),
            "timestamp_present": bool(ts_m),
            "event_type_present": bool(et_m),
            "source_path_present": bool(sp_m),
            "timestamp": ts_m.group(1) if ts_m else None,
            "event_type": et_m.group(1) if et_m else None,
            "source_path": sp_m.group(1) if sp_m else None,
        })

    # Privacy check: verify at least 1 redaction pattern works
    test_secret = "0x" + "a" * 64
    redacted_test, test_rc = redact(test_secret)
    privacy_filter_ok = test_rc >= 1 and "REDACTED" in redacted_test

    # Build hourly rollup for any hour buckets we wrote into
    hours_done: set[tuple[str, str]] = set()
    for p in emitted_paths:
        # path: vault/events/<date>/<hour>/<id>.md
        hour_str = p.parent.name
        date_str = p.parent.parent.name
        if (date_str, hour_str) not in hours_done:
            hourly_rollup(vault_dir, date_str, hour_str)
            hours_done.add((date_str, hour_str))

    report = {
        "run_timestamp": _dt.datetime.now(_dt.timezone.utc).replace(tzinfo=None).isoformat() + "Z",
        "input_events": len(raw_events),
        "emitted_notes": len(emitted_paths),
        "dropped_events": len(drop_events),
        "throttle_max_per_min": throttle._max,
        "privacy_filter_ok": privacy_filter_ok,
        "privacy_test_redaction_count": test_rc,
        "spot_check_notes": sample_notes,
        "vault_dir": str(vault_dir),
        "hourly_rollups_written": len(hours_done),
    }

    print(f"[simulate] Emitted: {len(emitted_paths)}  Dropped: {len(drop_events)}  "
          f"Privacy OK: {privacy_filter_ok}")
    print(f"[simulate] Spot-checked {len(sample_notes)} notes:")
    for sn in sample_notes:
        ts_ok = "OK" if sn["timestamp_present"] else "MISSING"
        et_ok = "OK" if sn["event_type_present"] else "MISSING"
        sp_ok = "OK" if sn["source_path_present"] else "MISSING"
        print(f"  {Path(sn['path']).name}: ts={ts_ok} type={et_ok} path={sp_ok}")

    if report_out:
        report_out = Path(report_out)
        report_out.parent.mkdir(parents=True, exist_ok=True)
        report_out.write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(f"[simulate] Report saved: {report_out}")

    # Exit code: 0 if all good, 1 if any spot-check failed
    all_spot_ok = all(
        sn["timestamp_present"] and sn["event_type_present"] and sn["source_path_present"]
        for sn in sample_notes
    )
    if not all_spot_ok:
        print("[simulate] FAIL: one or more spot-check fields missing", file=sys.stderr)
        return 1
    if not privacy_filter_ok:
        print("[simulate] FAIL: privacy filter did not fire on test secret", file=sys.stderr)
        return 1
    print("[simulate] PASS")
    return 0


# ---------------------------------------------------------------------------
# Load config
# ---------------------------------------------------------------------------
DEFAULT_WATCH_PATHS = [
    "/private/tmp/auditooor-inventory",
    str(REPO_ROOT / "agent_outputs"),
    str(REPO_ROOT / ".git" / "refs" / "heads"),
    str(REPO_ROOT / "tools" / "calibration"),
]


def load_config(cfg_path: Path | None) -> dict:
    """Load YAML config or return defaults."""
    defaults = {
        "watch_paths": DEFAULT_WATCH_PATHS,
        "vault_dir": str(REPO_ROOT / "obsidian-vault"),
        "poll_interval": 30,
        "max_events_per_min": 100,
    }
    if cfg_path is None or not cfg_path.exists():
        return defaults
    if not HAS_YAML:
        print("[config] WARN: PyYAML not available; using defaults", file=sys.stderr)
        return defaults
    with open(cfg_path, encoding="utf-8") as fh:
        data = _yaml.safe_load(fh) or {}
    defaults.update(data)
    return defaults


# ---------------------------------------------------------------------------
# Watchdog handler
# ---------------------------------------------------------------------------
class VaultEventHandler:
    """Wraps filesystem events and emits vault notes."""

    def __init__(self, vault_dir: Path, throttle: RateThrottle):
        self._vault = vault_dir
        self._throttle = throttle
        self.emitted = 0
        self.dropped = 0

    def handle(self, src_path: str, is_create: bool = True) -> None:
        etype = classify_event(src_path)
        if etype == "commit":
            emit_commit_note(self._vault, src_path)
        note = emit_note(
            vault_dir=self._vault,
            event_type=etype,
            src_path=src_path,
            throttle=self._throttle,
        )
        if note:
            self.emitted += 1
            print(f"[watcher] {etype} → {note.name}  (src: {Path(src_path).name})")
        else:
            self.dropped += 1
            print(f"[watcher] THROTTLED drop #{self._throttle.total_dropped} "
                  f"for {Path(src_path).name}")


# ---------------------------------------------------------------------------
# Watchdog observer mode
# ---------------------------------------------------------------------------
def run_watchdog(watch_paths: list[str], vault_dir: Path, throttle: RateThrottle) -> None:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler

    handler_obj = VaultEventHandler(vault_dir, throttle)

    class WDHandler(FileSystemEventHandler):
        def on_created(self, event):
            if not event.is_directory:
                handler_obj.handle(event.src_path, is_create=True)

        def on_modified(self, event):
            if not event.is_directory:
                handler_obj.handle(event.src_path, is_create=False)

    observer = Observer()
    for wp in watch_paths:
        p = Path(wp)
        if p.exists():
            observer.schedule(WDHandler(), str(p), recursive=True)
            print(f"[watcher] Watching (fsevents): {p}")
        else:
            print(f"[watcher] SKIP (not found): {p}")

    observer.start()
    print("[watcher] watchdog observer started (macOS fsevents / inotify)")
    try:
        while True:
            time.sleep(60)
    except KeyboardInterrupt:
        pass
    observer.stop()
    observer.join()


# ---------------------------------------------------------------------------
# Polling fallback mode
# ---------------------------------------------------------------------------
def run_polling(
    watch_paths: list[str],
    vault_dir: Path,
    throttle: RateThrottle,
    interval: int = 30,
) -> None:
    """Poll watch_paths every `interval` seconds; emit notes for new/changed files."""
    print(f"[watcher] watchdog unavailable — polling every {interval}s (fallback mode)")
    handler = VaultEventHandler(vault_dir, throttle)
    seen: dict[str, float] = {}

    while True:
        for wp in watch_paths:
            p = Path(wp)
            if not p.exists():
                continue
            candidates = list(p.rglob("*")) if p.is_dir() else [p]
            for fp in candidates:
                if fp.is_dir():
                    continue
                try:
                    mtime = fp.stat().st_mtime
                except OSError:
                    continue
                key = str(fp)
                if key not in seen or seen[key] < mtime:
                    seen[key] = mtime
                    if key in seen:  # only emit on subsequent visits (not first scan)
                        handler.handle(str(fp))
                    else:
                        seen[key] = mtime  # baseline without emitting
        time.sleep(interval)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="memory-event-watcher — Layer L1 §M_ARCH vault event emitter"
    )
    p.add_argument("--config", metavar="YAML",
                   help="Path to YAML config (default: none → use built-in defaults)")
    p.add_argument("--vault-dir", metavar="DIR",
                   help="Override vault directory (default: obsidian-vault/)")
    p.add_argument("--simulate-events", metavar="FILE",
                   help="JSONL file of synthetic events for self-test / CI mode")
    p.add_argument("--report-out", metavar="FILE",
                   help="Write self-test JSON report to this path")
    p.add_argument("--max-events-per-min", type=int, default=None,
                   help="Override throttle limit (default: 100)")
    p.add_argument("--poll-interval", type=int, default=None,
                   help="Polling fallback interval in seconds (default: 30)")
    p.add_argument("--hourly-rollup", metavar="DATE:HH",
                   help="Run hourly rollup for DATE (YYYY-MM-DD) and hour HH, then exit")
    return p


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    cfg = load_config(Path(args.config) if args.config else None)

    vault_dir = Path(args.vault_dir) if args.vault_dir else Path(cfg["vault_dir"])
    max_epm = args.max_events_per_min or cfg.get("max_events_per_min", 100)
    poll_interval = args.poll_interval or cfg.get("poll_interval", 30)
    watch_paths: list[str] = cfg.get("watch_paths", DEFAULT_WATCH_PATHS)

    throttle = RateThrottle(max_per_min=max_epm)

    # Hourly rollup mode
    if args.hourly_rollup:
        parts = args.hourly_rollup.split(":")
        if len(parts) != 2:
            print("ERROR: --hourly-rollup expects DATE:HH (e.g. 2026-05-04:13)", file=sys.stderr)
            return 2
        date_s, hour_s = parts
        result = hourly_rollup(vault_dir, date_s, hour_s)
        if result:
            print(f"[rollup] Written: {result}")
        else:
            print(f"[rollup] No notes found for {date_s}/{hour_s}")
        return 0

    # Simulate mode (self-test / CI)
    if args.simulate_events:
        report_out = Path(args.report_out) if args.report_out else None
        return run_simulate(
            events_file=Path(args.simulate_events),
            vault_dir=vault_dir,
            throttle=throttle,
            report_out=report_out,
        )

    # Daemon mode
    vault_dir.mkdir(parents=True, exist_ok=True)
    print(f"[watcher] Vault dir: {vault_dir}")
    print(f"[watcher] Throttle: {max_epm} events/min")
    if not HAS_WATCHDOG:
        print("[watcher] watchdog not installed — using polling fallback")
        print("[watcher] To get fsevents: pip install watchdog")
        run_polling(watch_paths, vault_dir, throttle, interval=poll_interval)
    else:
        run_watchdog(watch_paths, vault_dir, throttle)
    return 0


if __name__ == "__main__":
    sys.exit(main())
