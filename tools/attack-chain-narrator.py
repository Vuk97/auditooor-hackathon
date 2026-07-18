#!/usr/bin/env python3
"""attack-chain-narrator.py — human-readable attack-chain story.

Shells out to `tools/exploit-chain-correlator.py --chain --export-json`,
then composes a narrative suitable for a PR comment, audit report, Slack
message, or terminal readout.

Usage:
    tools/attack-chain-narrator.py --exploit <url-or-file>
    tools/attack-chain-narrator.py --exploit <...> --format markdown
    tools/attack-chain-narrator.py --exploit <...> --format slack
    tools/attack-chain-narrator.py --exploit <...> --format screen

Stdlib only. The correlator does all pattern work; this tool is pure
presentation. See docs/archive/ATTACK_CHAIN_NARRATOR.md.
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
CORRELATOR = REPO / "tools" / "exploit-chain-correlator.py"

# ANSI for --format screen
C_RESET = "\033[0m"
C_BOLD = "\033[1m"
C_DIM = "\033[2m"
C_RED = "\033[31m"
C_GREEN = "\033[32m"
C_YELLOW = "\033[33m"
C_BLUE = "\033[34m"
C_MAGENTA = "\033[35m"
C_CYAN = "\033[36m"


# ─── Correlator invocation ────────────────────────────────────────────────

def run_correlator(exploit: str, top: int = 20) -> dict:
    """Shell out to the correlator, return the parsed JSON report."""
    cmd = [
        sys.executable, str(CORRELATOR), exploit,
        "--chain", "--gap-surface", "--export-json",
        "--top", str(top),
    ]
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=120, check=False,
        )
    except subprocess.TimeoutExpired:
        sys.stderr.write("[narrator] correlator timed out after 120s\n")
        sys.exit(3)
    if proc.returncode != 0:
        sys.stderr.write(f"[narrator] correlator failed (rc={proc.returncode})\n")
        sys.stderr.write(proc.stderr)
        sys.exit(proc.returncode or 3)
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError as e:
        sys.stderr.write(f"[narrator] correlator stdout not JSON: {e}\n")
        sys.stderr.write(proc.stdout[:400] + "\n")
        sys.exit(3)


# ─── BUG_CLASSES (for root-cause prose) ───────────────────────────────────

def load_bug_classes() -> dict:
    """Reuse correlator's loader to avoid re-implementing it."""
    sys.path.insert(0, str(REPO / "tools"))
    try:
        import importlib.util
        spec = importlib.util.spec_from_file_location("corr", CORRELATOR)
        if spec is None or spec.loader is None:
            return {}
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod.load_bug_classes()
    except Exception as e:
        sys.stderr.write(f"[narrator] warn: couldn't load BUG_CLASSES: {e}\n")
        return {}


def confidence_bucket(cos: float) -> str:
    if cos >= 0.35:
        return "high"
    if cos >= 0.20:
        return "med"
    return "low"


# ─── Narrative composition ────────────────────────────────────────────────

def clean_phrase(phrase: str) -> str:
    """Drop leading bullet markers / whitespace, normalise whitespace."""
    p = re.sub(r"^[\-\*\>\s]+", "", phrase).strip()
    p = re.sub(r"\s+", " ", p)
    if p and not p.endswith((".", "!", "?")):
        p += "."
    return p


def step_sentences(chain: list[dict], classes: dict) -> list[dict]:
    """Produce a rendered dict per chain step."""
    out: list[dict] = []
    for st in chain:
        cos = float(st.get("confidence", 0.0) or 0.0)
        conf = confidence_bucket(cos)
        cls = st.get("detector", "")
        meta = classes.get(cls, {})
        desc = (meta.get("description") or "").strip()
        out.append({
            "n": st.get("step"),
            "detector": cls,
            "confidence": conf,
            "cosine": cos,
            "phrase": clean_phrase(st.get("phrase", "")),
            "root_cause": desc,
        })
    return out


def primitives(chain: list[dict]) -> list[str]:
    """Deduped ordered primitives (detector class names)."""
    seen: set[str] = set()
    out: list[str] = []
    for st in chain:
        d = st.get("detector")
        if d and d not in seen:
            seen.add(d)
            out.append(d)
    return out


def coverage_summary(rep: dict) -> tuple[int, int, list[str]]:
    """(covered, total, missing_phrases). total = covered + missing."""
    missing = [g["phrase"] for g in rep.get("gap_surface", [])]
    # "total primitives" = distinct detector classes in chain + uncovered bug phrases
    covered = len(primitives(rep.get("attack_chain", [])))
    total = covered + len(missing)
    return covered, total, missing


# ─── Renderers ────────────────────────────────────────────────────────────

def render_markdown(rep: dict, steps: list[dict], prims: list[str],
                    covered: int, total: int, missing: list[str]) -> str:
    lines: list[str] = []
    src = rep.get("source") or "(stdin)"
    lines.append(f"# Attack-chain narrative — `{src}`")
    lines.append("")
    if prims:
        lines.append(
            f"**TL;DR:** This exploit chains {len(prims)} "
            f"{'primitive' if len(prims) == 1 else 'primitives'}: "
            + ", ".join(f"`{p}`" for p in prims) + "."
        )
    else:
        lines.append("**TL;DR:** No attack-chain primitives reconstructed.")
    lines.append("")
    lines.append("## Walkthrough")
    lines.append("")
    if not steps:
        lines.append("_No steps scored above threshold._")
    for st in steps:
        lines.append(
            f"- **Step {st['n']}:** {st['phrase']} "
            f"This matches detector `{st['detector']}` "
            f"(confidence: {st['confidence']}, cos={st['cosine']:.3f})."
        )
        if st["root_cause"]:
            lines.append(f"  - _Root cause:_ {st['root_cause']}")
    lines.append("")
    lines.append("## Coverage")
    lines.append("")
    pct = (100.0 * covered / total) if total else 0.0
    lines.append(
        f"**{covered} of {total} primitives** "
        f"({pct:.0f}%) have detector coverage in this repo."
    )
    if missing:
        lines.append("")
        lines.append("Missing (bug-shaped phrases with no detector match):")
        for m in missing:
            lines.append(f"- `{m}`")
    lines.append("")
    return "\n".join(lines)


def render_slack(rep: dict, steps: list[dict], prims: list[str],
                 covered: int, total: int, missing: list[str]) -> str:
    lines: list[str] = []
    src = rep.get("source") or "(stdin)"
    lines.append(f"*Attack-chain narrative* — `{src}`")
    if prims:
        lines.append(
            f"TL;DR: chains {len(prims)} primitives: "
            + ", ".join(f"`{p}`" for p in prims)
        )
    for st in steps:
        lines.append(
            f"• *Step {st['n']}*: {st['phrase']} "
            f"→ `{st['detector']}` _(conf: {st['confidence']})_"
        )
    pct = (100.0 * covered / total) if total else 0.0
    lines.append(f"Coverage: *{covered}/{total}* ({pct:.0f}%)")
    if missing:
        lines.append("Missing: " + ", ".join(f"`{m}`" for m in missing))
    return "\n".join(lines)


def render_screen(rep: dict, steps: list[dict], prims: list[str],
                  covered: int, total: int, missing: list[str]) -> str:
    lines: list[str] = []
    src = rep.get("source") or "(stdin)"
    bar = "═" * 70
    lines.append(f"{C_BOLD}{C_CYAN}{bar}{C_RESET}")
    lines.append(f"{C_BOLD}{C_CYAN}Attack-chain narrative{C_RESET} — {C_DIM}{src}{C_RESET}")
    lines.append(f"{C_BOLD}{C_CYAN}{bar}{C_RESET}")
    if prims:
        lines.append(
            f"{C_BOLD}TL;DR:{C_RESET} chains {C_YELLOW}{len(prims)}{C_RESET} primitives: "
            + ", ".join(f"{C_MAGENTA}{p}{C_RESET}" for p in prims)
        )
    else:
        lines.append(f"{C_BOLD}TL;DR:{C_RESET} no primitives reconstructed.")
    lines.append("")
    for st in steps:
        conf_colour = {
            "high": C_GREEN, "med": C_YELLOW, "low": C_RED,
        }.get(st["confidence"], C_DIM)
        lines.append(
            f"  {C_BOLD}Step {st['n']:>2}{C_RESET}  "
            f"[{conf_colour}{st['confidence']:>4}{C_RESET}  "
            f"cos={st['cosine']:.3f}]  "
            f"{C_MAGENTA}{st['detector']}{C_RESET}"
        )
        lines.append(f"      {C_DIM}phrase:{C_RESET} {st['phrase']}")
        if st["root_cause"]:
            lines.append(f"      {C_DIM}cause:{C_RESET}  {st['root_cause']}")
        lines.append("")
    pct = (100.0 * covered / total) if total else 0.0
    colour = C_GREEN if pct >= 75 else C_YELLOW if pct >= 40 else C_RED
    lines.append(
        f"{C_BOLD}Coverage:{C_RESET} {colour}{covered}/{total} "
        f"({pct:.0f}%){C_RESET}"
    )
    if missing:
        lines.append(f"{C_DIM}Missing:{C_RESET}")
        for m in missing:
            lines.append(f"  {C_RED}•{C_RESET} {m}")
    lines.append("")
    return "\n".join(lines)


# ─── CLI ────────────────────────────────────────────────────────────────────

def main() -> int:
    ap = argparse.ArgumentParser(
        description="Render an exploit attack-chain as a human narrative.",
    )
    ap.add_argument("--exploit", required=True,
                    help="URL or file path to an exploit postmortem")
    ap.add_argument("--format", choices=["markdown", "slack", "screen"],
                    default="markdown", help="Output format (default: markdown)")
    ap.add_argument("--top", type=int, default=20,
                    help="Top-N classes to request from correlator")
    args = ap.parse_args()

    if not CORRELATOR.exists():
        sys.stderr.write(f"[narrator] missing correlator: {CORRELATOR}\n")
        return 2

    rep = run_correlator(args.exploit, top=args.top)
    classes = load_bug_classes()
    chain = rep.get("attack_chain", [])
    steps = step_sentences(chain, classes)
    prims = primitives(chain)
    covered, total, missing = coverage_summary(rep)

    if args.format == "markdown":
        out = render_markdown(rep, steps, prims, covered, total, missing)
    elif args.format == "slack":
        out = render_slack(rep, steps, prims, covered, total, missing)
    else:
        out = render_screen(rep, steps, prims, covered, total, missing)
    print(out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
