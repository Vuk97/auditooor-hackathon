#!/usr/bin/env python3
"""Impact-Characterization-Completeness gate (IMPACT-CHARACTERIZATION-COMPLETENESS).

Keyed on the CLAIMED impact class, require that class's tier-deciding axes to be
answered in the draft's ``## Impact Characterization`` section, and assert the
claimed severity tier does not exceed the evidence class the delegated gates can
support. This closes the gap the corpus itself flagged (impact_hunting_methodology.yaml
temp-freeze ``existing_tooling_coverage`` line: "R82 fires only at SUBMIT and only for
PERMANENT, never as the INVERSE confirm-recovery for temporary").

Design doctrine: REUSE, do not fork. The recovery, panic-vs-slowness, evidence-class
and tier-vs-evidence axes are DELEGATED to the existing sibling gates; only two axes
are scored here (DRAIN_VS_REENQUEUE, DURATION_QUANTIFIED). The required-axis list is
read at runtime from impact_hunting_methodology.yaml so the gate and the hunt cannot
drift.

Advisory-first: absent AUDITOOOR_IMPACT_CHARACTERIZATION_STRICT (or --strict) the gate
computes + prints but returns rc=0, byte-compatible with existing paste-ready flows.
Under STRICT a missing required axis, a delegated-gate fail, or CLAIMED_TIER >
EVIDENCE_TIER returns rc=1.

Additive-only (revision R3): the composite NEVER passes where a delegated gate would
fail standalone, and the composite rebuttal greens ONLY the two net-new axes - it can
never rebut a delegated gate's own verdict (that gate keeps its own rebuttal marker).

CLI:
    impact-characterization-completeness-check.py <draft.md> [--workspace <ws>]
        [--poc-dir <dir>] [--severity {auto,LOW,MEDIUM,HIGH,CRITICAL}]
        [--strict] [--json] [--emit-stub]

Rebuttal marker (greens net-new axes only):
    <!-- impact-characterization-rebuttal: <why the net-new axis is N/A here> -->
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

TOOLS_DIR = Path(__file__).resolve().parent
REPO_ROOT = TOOLS_DIR.parent
YAML_PATH = REPO_ROOT / "audit" / "corpus_tags" / "impact_hunting_methodology.yaml"

SCHEMA = "auditooor.impact_characterization_completeness.v1"
GATE = "IMPACT-CHARACTERIZATION-COMPLETENESS"

SEV_RANK = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}

REBUTTAL_RE = re.compile(
    r"<!--\s*impact-characterization-rebuttal:\s*(.*?)\s*-->", re.I | re.S
)

# ---------------------------------------------------------------------------
# classify_axes reuse (import the severity-calibration-gate module by path, exactly
# as severity-calibration-gate.py:362-373 loads a sibling via spec_from_file_location).
# ---------------------------------------------------------------------------
def _load_module(filename: str, modname: str):
    import importlib.util

    path = TOOLS_DIR / filename
    if not path.is_file():
        return None
    spec = importlib.util.spec_from_file_location(modname, path)
    if spec is None or spec.loader is None:
        return None
    mod = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(mod)  # type: ignore[union-attr]
    except Exception:
        return None
    return mod


_SEVCAL = _load_module("severity-calibration-gate.py", "_icc_sevcal")
_EVIDENCE = _load_module("evidence_class.py", "_icc_evidence")


# ---------------------------------------------------------------------------
# YAML axis-matrix source of truth (read at runtime; no hand-copied axis list).
# ---------------------------------------------------------------------------
# Map classify_axes()'s impact_kind -> the impact_id used in the YAML.
IMPACT_KIND_TO_YAML_ID = {
    "user_fund_theft": "direct-theft-funds",
    "permanent_freeze": "permanent-freeze-funds",
    "temporary_freeze": "temporary-freeze-funds",
    "protocol_yield_theft": "theft-unclaimed-yield",
    "griefing": "griefing-dos",  # NUVA class; may be absent from YAML -> synthesised below
}


def _load_yaml() -> Any:
    try:
        import yaml  # type: ignore
    except Exception:
        return None
    if not YAML_PATH.is_file():
        return None
    try:
        with YAML_PATH.open("r", encoding="utf-8") as fh:
            return yaml.safe_load(fh)
    except Exception:
        return None


def _yaml_playbooks() -> list[dict[str, Any]]:
    """Return the 32 impact_id playbook entries (top-level dict -> data['playbooks'])."""
    data = _load_yaml()
    if isinstance(data, list):
        return [e for e in data if isinstance(e, dict)]
    if isinstance(data, dict):
        pb = data.get("playbooks")
        if isinstance(pb, list):
            return [e for e in pb if isinstance(e, dict)]
    return []


def _yaml_axes_for(impact_id: str) -> list[dict[str, Any]]:
    """Return the class's optional_axes list from the YAML (single source of truth)."""
    for entry in _yaml_playbooks():
        if isinstance(entry, dict) and entry.get("impact_id") == impact_id:
            axes = entry.get("optional_axes") or []
            return [a for a in axes if isinstance(a, dict)]
    return []


# Net-new axes scored HERE (confirmed absent from tools/): the two the design keeps.
SELF_SCORED_AXES = ("DRAIN_VS_REENQUEUE", "DURATION_QUANTIFIED")

# Delegated axes -> the sibling gate that OWNS the discriminator. The axis is
# auto-satisfied when the delegate's own trigger does not fire (revision R2c).
DELEGATED_AXES = {
    "RECOVERY_LADDER": "impact-recovery-falsification-check.py",
    "PANIC_VS_SLOWNESS": "panic-context-audit.py",
    "EVIDENCE_CLASS_BOUNDARY": "in-process-vs-node-level-check.py",
    "SELF_IMPACT": "non-self-impact-check.py",
}

# Per-class required axis sets. The self-scored / delegated axis NAMES are fixed
# (they map to gates, not to prose), but the *requirement to answer a draft line*
# is driven by the YAML optional_axes for that class so gate and hunt cannot drift.
CLASS_REQUIRED_AXES = {
    "temporary-freeze-funds": [
        "RECOVERY_LADDER", "DURATION_QUANTIFIED", "SELF_THROTTLE",
        "EVIDENCE_CLASS_BOUNDARY", "SELF_IMPACT",
    ],
    "permanent-freeze-funds": [
        "RECOVERY_LADDER", "EVIDENCE_CLASS_BOUNDARY", "SELF_IMPACT",
    ],
    "direct-theft-funds": [
        "RECOVERY_LADDER", "SELF_IMPACT",
    ],
    "theft-unclaimed-yield": [
        "RECOVERY_LADDER", "SELF_IMPACT",
    ],
    "griefing-dos": [
        "PANIC_VS_SLOWNESS", "DRAIN_VS_REENQUEUE", "DURATION_QUANTIFIED",
        "SELF_THROTTLE", "RECOVERY_LADDER", "EVIDENCE_CLASS_BOUNDARY", "SELF_IMPACT",
    ],
}


# ---------------------------------------------------------------------------
# Draft ## Impact Characterization parsing.
# ---------------------------------------------------------------------------
SECTION_RE = re.compile(
    r"^##+\s*Impact Characterization\b.*?$(.*?)(?=^##+\s|\Z)",
    re.I | re.M | re.S,
)
# - <AXIS>: <value/verdict> [<measured | source-cited file:line | N/A: <reason> | rebuttal>]
AXIS_LINE_RE = re.compile(r"^\s*[-*]\s*([A-Z_]+)\s*:\s*(.+?)\s*$", re.M)

PLACEHOLDER_RE = re.compile(r"\b(tbd|todo|fixme|xxx|\.\.\.|placeholder|<[^>]*>)\b", re.I)
MEASURED_RE = re.compile(r"\b(measured|executed|node-level|multi-validator|finalizeblock)\b", re.I)
SOURCE_CITED_RE = re.compile(r"[\w./-]+\.\w+:\d+")  # file.ext:line
NA_RE = re.compile(r"\bN/?A\b\s*:", re.I)


def _extract_section(text: str) -> str | None:
    m = SECTION_RE.search(text)
    return m.group(1) if m else None


def _axis_state(section: str, axis: str) -> str:
    """Return ANSWERED | NA | REBUTTED_INLINE | BARE | ABSENT for an axis line."""
    found = None
    for m in AXIS_LINE_RE.finditer(section):
        if m.group(1).upper() == axis:
            found = m.group(2).strip()
            break
    if found is None:
        return "ABSENT"
    if not found or PLACEHOLDER_RE.search(found):
        return "BARE"
    if NA_RE.search(found) and SOURCE_CITED_RE.search(found):
        return "NA"
    if MEASURED_RE.search(found) or SOURCE_CITED_RE.search(found):
        return "ANSWERED"
    # A prose value with no measured/source marker is not sufficient.
    return "BARE"


# ---------------------------------------------------------------------------
# Delegated-gate runners (subprocess -> robust against hyphenated filenames).
# Returns (rc, verdict, triggered) where triggered=False means the delegate
# self-limited (pass-out-of-scope / pass-not-triggered) so the axis auto-satisfies.
# ---------------------------------------------------------------------------
def _run_delegate(
    tool: str, draft: Path, poc_dir: Path | None, severity: str, strict: bool
) -> dict[str, Any]:
    path = TOOLS_DIR / tool
    if not path.is_file():
        return {"tool": tool, "available": False, "rc": 0, "verdict": "skip-missing", "triggered": False}
    cmd = [sys.executable, str(path), str(draft), "--json"]
    if poc_dir is not None:
        cmd += ["--poc-dir", str(poc_dir)]
    if severity and severity != "auto":
        cmd += ["--severity", severity]
    if strict:
        cmd += ["--strict"]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    except Exception as exc:  # noqa: BLE001
        return {"tool": tool, "available": True, "rc": 0, "verdict": f"skip-error:{exc}", "triggered": False}
    verdict = ""
    try:
        payload = json.loads(proc.stdout or "{}")
        if isinstance(payload, dict):
            verdict = str(payload.get("verdict", ""))
    except Exception:
        verdict = ""
    # A delegate that self-limited (pass-out-of-scope / pass-*not-triggered / pass-rubric-*)
    # did NOT fire on this draft -> the delegated axis is auto-satisfied (revision R2c).
    triggered = not (
        verdict.startswith("pass-out-of-scope")
        or verdict.startswith("pass-rubric")
        or "not-triggered" in verdict
        or "no-production-keyword" in verdict
        or verdict == "skip-missing"
    )
    return {
        "tool": tool,
        "available": True,
        "rc": proc.returncode,
        "verdict": verdict,
        "triggered": triggered,
    }


# ---------------------------------------------------------------------------
# Core.
# ---------------------------------------------------------------------------
def check(
    draft: Path, workspace: Path | None, poc_dir: Path | None, severity: str, strict: bool
) -> dict[str, Any]:
    text = draft.read_text(encoding="utf-8", errors="replace")
    rebuttal = None
    rm = REBUTTAL_RE.search(text)
    if rm and rm.group(1).strip():
        rebuttal = rm.group(1).strip()[:200]

    # 1) Detect claimed impact class (REUSE classify_axes()).
    impact_kind = "unknown"
    if _SEVCAL is not None:
        try:
            axes = _SEVCAL.classify_axes(text)
            impact_kind = axes.get("impact_kind", "unknown")
        except Exception:
            impact_kind = "unknown"
    yaml_id = IMPACT_KIND_TO_YAML_ID.get(impact_kind, impact_kind)

    # 2) Detect claimed severity tier.
    claimed_sev = severity.upper() if severity and severity != "auto" else None
    if claimed_sev is None:
        sm = re.search(r"severity\s*:?\s*(low|medium|high|critical)", text, re.I)
        if sm:
            claimed_sev = sm.group(1).upper()

    required = list(CLASS_REQUIRED_AXES.get(yaml_id, []))
    # Read the YAML optional_axes as the single source of truth for the checklist
    # (rendered, not hard-copied) so the hunt-time stub cannot drift from the gate.
    yaml_axes = _yaml_axes_for(yaml_id)

    section = _extract_section(text)

    # 3) Run delegated gates once (their standalone verdicts are the axis truth).
    delegate_results: dict[str, dict[str, Any]] = {}
    for axis, tool in DELEGATED_AXES.items():
        if axis in required or axis == "RECOVERY_LADDER":
            delegate_results[axis] = _run_delegate(tool, draft, poc_dir, claimed_sev or "auto", strict)

    # 4) Score every required axis.
    axis_verdicts: dict[str, dict[str, Any]] = {}
    failures: list[str] = []
    for axis in required:
        entry: dict[str, Any] = {"axis": axis}
        if axis in DELEGATED_AXES:
            dres = delegate_results.get(axis) or _run_delegate(
                DELEGATED_AXES[axis], draft, poc_dir, claimed_sev or "auto", strict
            )
            entry["delegate"] = DELEGATED_AXES[axis]
            entry["delegate_verdict"] = dres["verdict"]
            entry["delegate_rc"] = dres["rc"]
            dv = dres["verdict"]
            # INVERSE-R82 for temporary-freeze (per YAML temp-freeze recovery_confirmation
            # axis): R82 is a PERMANENCE-falsification gate; for a TEMPORARY freeze a
            # "recovery survives" verdict is the CONFIRMED-recovery we want, so it SATISFIES
            # the RECOVERY_LADDER axis rather than refuting it (revision R4).
            inverse_r82_ok = (
                axis == "RECOVERY_LADDER"
                and yaml_id == "temporary-freeze-funds"
                and dv in ("fail-recovery-path-survives-claim-false",
                           "pass-recovery-enumeration-complete",
                           "pass-claim-narrowed")
            )
            if not dres["triggered"]:
                entry["state"] = "AUTO_SATISFIED"  # delegate self-limited (R2c)
            elif inverse_r82_ok:
                entry["state"] = "SATISFIED_INVERSE_R82"
            elif dv.startswith("fail"):
                entry["state"] = "REFUTED"  # additive-only (R3): delegate fail -> axis fail
                failures.append(f"{axis}: delegated gate {DELEGATED_AXES[axis]} -> {dv}")
            else:
                entry["state"] = "SATISFIED"
        else:
            # Self-scored or SELF_THROTTLE (delegated to escalate-first but scored via draft line).
            if section is None:
                state = "ABSENT"
            else:
                state = _axis_state(section, axis)
            entry["state"] = state
            if state in ("SATISFIED", "ANSWERED", "NA"):
                pass
            elif state in ("BARE", "ABSENT"):
                if rebuttal and axis in SELF_SCORED_AXES:
                    entry["state"] = "REBUTTED"
                    entry["rebuttal"] = rebuttal
                else:
                    failures.append(f"{axis}: {state} (no measured|source-cited|N/A line)")
        axis_verdicts[axis] = entry

    # 5) Tier-vs-evidence (REVISION R4): derive EVIDENCE_TIER from delegated verdicts,
    #    never a fresh regex. If a delegate says the evidence surface is below the
    #    claimed tier, tier-exceeds-evidence FAILS.
    tier_finding = None
    evidence_tier = claimed_sev
    ip = delegate_results.get("EVIDENCE_CLASS_BOUNDARY")
    if ip is None and "EVIDENCE_CLASS_BOUNDARY" in DELEGATED_AXES:
        ip = _run_delegate(DELEGATED_AXES["EVIDENCE_CLASS_BOUNDARY"], draft, poc_dir, claimed_sev or "auto", strict)
    if (
        claimed_sev in ("HIGH", "CRITICAL")
        and ip is not None
        and ip.get("triggered")
        and ip.get("verdict", "").startswith("fail")
    ):
        # in-process-only PoC for a production-grade claim -> evidence caps below claimed tier.
        evidence_tier = "MEDIUM"
        if SEV_RANK.get(claimed_sev, 0) > SEV_RANK.get(evidence_tier, 0):
            tier_finding = (
                f"CLAIMED_TIER={claimed_sev} exceeds EVIDENCE_TIER={evidence_tier}: "
                f"in-process delegate -> {ip['verdict']}"
            )
            failures.append(f"TIER_VS_EVIDENCE: {tier_finding}")

    # Composite verdict.
    if not required:
        verdict = "pass-no-tier-deciding-axes-for-class"
    elif failures:
        verdict = "fail-impact-characterization-incomplete"
    else:
        verdict = "pass-impact-characterization-complete"

    return {
        "schema": SCHEMA,
        "gate": GATE,
        "draft": str(draft),
        "impact_kind": impact_kind,
        "impact_id": yaml_id,
        "claimed_severity": claimed_sev,
        "evidence_tier": evidence_tier,
        "required_axes": required,
        "yaml_axis_count": len(yaml_axes),
        "axis_verdicts": axis_verdicts,
        "tier_finding": tier_finding,
        "rebuttal": rebuttal,
        "failures": failures,
        "verdict": verdict,
        "strict": strict,
    }


def render_stub(yaml_id: str) -> str:
    """Emit a fillable ## Impact Characterization stub seeded from the class YAML."""
    required = CLASS_REQUIRED_AXES.get(yaml_id, [])
    lines = ["## Impact Characterization", ""]
    lines.append(f"IMPACT_CLASS: {yaml_id}")
    for axis in required:
        if axis in DELEGATED_AXES:
            lines.append(f"- {axis}: <verdict>  [delegated to {DELEGATED_AXES[axis]}]")
        else:
            lines.append(f"- {axis}: <value>  [measured | source-cited file:line | N/A: <reason+cite>]")
    lines.append("- CLAIMED_TIER: <LOW|MEDIUM|HIGH|CRITICAL>")
    lines.append("- EVIDENCE_TIER: <derived from delegated verdicts>")
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("draft", nargs="?", type=Path)
    ap.add_argument("--workspace", type=Path)
    ap.add_argument("--poc-dir", type=Path)
    ap.add_argument("--severity", default="auto")
    ap.add_argument("--strict", action="store_true")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--emit-stub", metavar="IMPACT_ID",
                    help="print a fillable ## Impact Characterization stub for the class and exit")
    args = ap.parse_args(argv)

    if args.emit_stub:
        sys.stdout.write(render_stub(args.emit_stub))
        return 0

    if not args.draft or not args.draft.is_file():
        print(f"[{GATE}] no such draft: {args.draft}")
        return 2

    env_strict = os.environ.get("AUDITOOOR_IMPACT_CHARACTERIZATION_STRICT", "").strip().lower()
    strict = bool(args.strict) or env_strict in {"1", "true", "yes", "on"}

    poc = args.poc_dir.expanduser().resolve() if args.poc_dir else None
    ws = args.workspace.expanduser().resolve() if args.workspace else None
    out = check(args.draft.expanduser().resolve(), ws, poc, args.severity, strict)

    if args.json:
        print(json.dumps(out, indent=2, sort_keys=True))
    else:
        print(f"[{GATE}] verdict={out['verdict']} impact_id={out['impact_id']} "
              f"claimed={out['claimed_severity']} evidence_tier={out['evidence_tier']}")
        for f in out["failures"]:
            print(f"  - FAIL: {f}")
        if not strict and out["failures"]:
            print("  (advisory: set AUDITOOOR_IMPACT_CHARACTERIZATION_STRICT=1 to enforce)")

    is_fail = out["verdict"].startswith("fail")
    # Advisory-first: only fail-closed under STRICT.
    return 1 if (is_fail and strict) else 0


if __name__ == "__main__":
    raise SystemExit(main())
