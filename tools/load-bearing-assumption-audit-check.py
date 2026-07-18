#!/usr/bin/env python3
"""Rule 78 load-bearing-assumption-audit-required gate (umbrella meta-gate).

For HIGH+ findings, the impact chain almost always rests on one or more
LOAD-BEARING ASSUMPTIONS - facts the agent believed without verifying. The
existing assumption-verification gates each cover ONE narrow class:

  - R76 (Check #125)  workspace source-EXISTENCE of a cited code excerpt
  - R77 (Check #129)  external-DEPENDENCY runtime BEHAVIOR claim
  - R42 (Check #89)   deployed/CONFIGURED-component impact trace
  - R46 (Check #95)   TRUSTED-INFRASTRUCTURE compromise tabulation

R78 is the UMBRELLA. It does NOT re-verify each assumption's source (that is
the sibling gates' job). It enforces the one discipline none of them enforce:
that a "Load-Bearing Assumption Ledger" EXISTS and is COMPLETE, so every
load-bearing assumption is named and each carries a verification method. It
fails closed when a load-bearing claim rests on an UNVERIFIED assumption -
specifically the four out-of-direct-tree classes the narrow gates miss when
the agent never recognised the claim as an assumption at all:

  (i)   external-dependency runtime behavior  (delegates depth to R77)
  (ii)  external-library DEFAULTS             (e.g. a config default not
                                               overridden - jsonrpsee
                                               max_connections=100)
  (iii) deployment / config assumptions       (delegates depth to R42)
  (iv)  protocol-version / external-chain semantics

A row PASSES when it is anchored to one of:
  - an in-tree source path (file.rs:line)
  - an external-dependency source path (~/.cargo/registry/.../x.rs:line)
  - measured / executed numbers (a test transcript line)
  - a config / spec citation
OR carries a bounded inline rebuttal `r78-unverified-rebuttal: <reason>`.

Empirical anchor (zebra batch over-claim, 2026-06-02): a HIGH zebra finding's
amplification rested on TWO unverified assumptions - (a) jsonrpsee processes a
JSON-RPC batch CONCURRENTLY (it does not - it loops sequentially), and (b) the
batch size is UNBOUNDED by default (it is not - the server defaults bound
connections/batch). Neither was recognised as an assumption, so neither was
written down. R76 passed (workspace source existed), R42/R46 did not fire (no
config/trusted-infra language). R77 caught (a) reactively, but the discipline
that would have surfaced BOTH at brief time is the ledger this gate requires.
The corrected finding cites jsonrpsee-server-0.24.10/src/server.rs:1318 (the
sequential batch loop) and the max_connections=100 default = PASS.

Composition contract (delegate, do NOT duplicate):
  R78 forces the agent to ENUMERATE assumptions (breadth, shallow).
  R76/R77/R42/R46 then VERIFY specific classes (narrow, deep).
  A draft can list every assumption in the R78 ledger and still fail R77
  (R77's dep-cache-path requirement is stricter than the ledger's free-form
  source column). Conversely a draft that passes R77/R42/R46 but omits the
  ledger fails R78, because enumeration is the discipline, not just
  per-category verification.

Verdict vocabulary:
  pass-out-of-scope                          severity below HIGH (or missing)
  pass-assumption-ledger-complete            ledger present, every load-bearing
                                             row anchored (no UNVERIFIED)
  pass-assumption-ledger-unverified-rebuttaled
                                             ledger present; each UNVERIFIED row
                                             carries an inline r78-unverified-
                                             rebuttal
  ok-rebuttal                                <!-- r78-rebuttal: <reason> -->
  fail-no-assumption-ledger                  HIGH+ draft has no Load-Bearing
                                             Assumption Ledger section
  fail-unverified-load-bearing-assumption    ledger present but >=1 row is
                                             UNVERIFIED with no inline rebuttal
  error                                      input error

Env extension hooks (newline-separated regex lists appended to defaults):
  AUDITOOOR_R78_LEDGER_HEADING_PATTERNS   extra ledger-heading regexes
  AUDITOOOR_R78_UNVERIFIED_PATTERNS       extra UNVERIFIED-marker regexes

CLI: <draft.md> [--severity {auto,LOW,MEDIUM,HIGH,CRITICAL}] [--strict] [--json]

Exit codes: 0 = pass / out-of-scope / accepted rebuttal, 1 = violation, 2 = error.
"""
from __future__ import annotations

import argparse
import json
import os
import re
from pathlib import Path
from typing import Any

SCHEMA_VERSION = "auditooor.r78_load_bearing_assumption_audit.v1"
GATE = "R78-LOAD-BEARING-ASSUMPTION-AUDIT"

SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}

# The section heading that declares the ledger. Accept a few synonyms so the
# gate does not depend on exact title wording.
LEDGER_HEADING_DEFAULTS = (
    r"Load[- ]Bearing\s+Assumption\s+(?:Ledger|Audit)",
    r"Assumption\s+Ledger",
    r"Load[- ]Bearing\s+Assumptions?",
)

# Tokens that mark a ledger row as not-yet-verified. A row containing one of
# these (in its verification column) is unverified.
UNVERIFIED_DEFAULTS = (
    r"UNVERIFIED",
    r"NOT\s+VERIFIED",
    r"ASSUMED",
    r"TODO",
    r"TBD",
    r"unchecked",
)

# Draft-level rebuttal (silences the whole gate).
REBUTTAL_RE = re.compile(r"<!--\s*r78-rebuttal:\s*(.{1,200}?)\s*-->",
                         re.IGNORECASE | re.DOTALL)

# Inline per-row rebuttal: tolerated next to an UNVERIFIED cell. Bounded.
INLINE_REBUTTAL_RE = re.compile(
    r"r78-unverified-rebuttal:\s*(.{1,200}?)(?:\s*-->|\s*\||$)",
    re.IGNORECASE,
)


def _env_patterns(var: str) -> list[str]:
    raw = os.environ.get(var, "")
    return [ln.strip() for ln in raw.splitlines() if ln.strip()]


def _ledger_heading_re() -> re.Pattern[str]:
    pats = list(LEDGER_HEADING_DEFAULTS) + _env_patterns(
        "AUDITOOOR_R78_LEDGER_HEADING_PATTERNS")
    return re.compile(r"^\s*#{1,6}.*(?:" + "|".join(pats) + r")",
                      re.IGNORECASE)


def _unverified_re() -> re.Pattern[str]:
    pats = list(UNVERIFIED_DEFAULTS) + _env_patterns(
        "AUDITOOOR_R78_UNVERIFIED_PATTERNS")
    return re.compile(r"\b(?:" + "|".join(pats) + r")\b", re.IGNORECASE)


def _read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def _severity(text: str, path: Path, override: str | None) -> tuple[str | None, str]:
    if override and override.lower() != "auto":
        normalized = override.strip().lower()
        if normalized in SEVERITY_RANK:
            return normalized, "cli"
    sev = r"\**\s*(Critical|High|Medium|Low)\b\**"
    for pattern, source in (
        (rf"(?im)^\s*\**\s*Severity\s*:\**\s*{sev}", "severity-header"),
        (rf"(?im)^\s*severity_implied\s*:\s*{sev}", "program-impact-mapping"),
        (rf"(?im)^\s*severity_tier\s*:\s*{sev}", "impact-contract"),
        (rf"(?im)^\s*selected_severity\s*:\s*{sev}", "selected-severity"),
    ):
        m = re.search(pattern, text)
        if m:
            return m.group(1).lower(), source
    name = path.name.lower()
    for severity in ("critical", "high", "medium", "low"):
        if re.search(rf"(?:^|[-_]){severity}(?:[-_.]|$)", name):
            return severity, "filename"
    return None, "missing"


def _is_table_row(line: str) -> bool:
    """A markdown table data row: starts with | and has >=2 column separators."""
    s = line.strip()
    if not s.startswith("|"):
        return False
    # separator rows like |---|---| are not data rows
    if re.fullmatch(r"\|[\s:|-]+\|?", s):
        return False
    return s.count("|") >= 2


def run(draft: Path, *, severity_override: str | None = None,
        strict: bool = False) -> tuple[int, dict[str, Any]]:
    try:
        text = _read_text(draft)
    except Exception as exc:
        return 2, {
            "schema_version": SCHEMA_VERSION, "gate": GATE, "file": str(draft),
            "verdict": "error", "error": f"cannot read draft: {exc}",
        }

    severity, severity_source = _severity(text, draft, severity_override)
    payload: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION, "gate": GATE, "file": str(draft),
        "severity": severity, "severity_source": severity_source, "strict": strict,
        "evidence": {},
        "composes_with": {
            "R76": "workspace source-existence of cited code excerpt (Check #125)",
            "R77": "external-dependency runtime behavior claim (Check #129)",
            "R42": "deployed/configured-component impact trace (Check #89)",
            "R46": "trusted-infrastructure compromise tabulation (Check #95)",
            "note": "R78 enforces the ledger EXISTS + is complete; the sibling "
                    "gates verify specific assumption classes. Delegate, do not "
                    "duplicate.",
        },
        "remediation_options": [
            "Add a 'Load-Bearing Assumption Ledger' section: a table with one "
            "row per load-bearing assumption (assumption | class | how verified "
            "| source). Classes: in-tree-source / external-dep-source / "
            "measured-executed / config-cited / accepted-as-OOS / UNVERIFIED.",
            "For each row, anchor it to a source path, measured numbers, or a "
            "config/spec citation. Pay special attention to the four "
            "out-of-tree classes: external-dependency behavior (-> R77), "
            "external-library DEFAULTS, deployment/config (-> R42), and "
            "protocol-version / external-chain semantics.",
            "If a row is genuinely UNVERIFIED and you accept the risk, add an "
            "inline 'r78-unverified-rebuttal: <reason>' in that row's verify "
            "cell (<=200 chars).",
            "Use <!-- r78-rebuttal: reason --> only to silence the whole gate "
            "for a bounded, justified exception.",
        ],
    }

    # Below HIGH -> out of scope.
    if severity is None or SEVERITY_RANK.get(severity, 0) < SEVERITY_RANK["high"]:
        payload["verdict"] = "pass-out-of-scope"
        payload["reason"] = "severity below HIGH or missing"
        return 0, payload

    rebuttal = REBUTTAL_RE.search(text)
    if rebuttal and rebuttal.group(1).strip():
        payload["verdict"] = "ok-rebuttal"
        payload["reason"] = f"r78-rebuttal accepted: {rebuttal.group(1).strip()[:200]}"
        return 0, payload

    heading_re = _ledger_heading_re()
    lines = text.splitlines()
    heading_idx = None
    for idx, line in enumerate(lines):
        if heading_re.search(line):
            heading_idx = idx
            break

    if heading_idx is None:
        payload["verdict"] = "fail-no-assumption-ledger"
        payload["reason"] = (
            "HIGH+ draft has no 'Load-Bearing Assumption Ledger' section. Every "
            "HIGH+ impact chain rests on load-bearing assumptions; enumerate "
            "them and state how each is verified (source / measurement / config)."
        )
        return 1, payload

    payload["evidence"]["ledger_heading_line"] = heading_idx + 1

    # Collect ledger data rows: table rows after the heading, until the next
    # top-level (## or #) heading.
    unverified_re = _unverified_re()
    data_rows: list[dict[str, Any]] = []
    unverified_rows: list[dict[str, Any]] = []
    for j in range(heading_idx + 1, len(lines)):
        ln = lines[j]
        if re.match(r"^\s*#{1,2}\s", ln) and j != heading_idx:
            break
        if not _is_table_row(ln):
            continue
        # Skip a header row that contains the literal column name "assumption".
        low = ln.lower()
        is_header = ("assumption" in low and ("class" in low or "verif" in low
                                              or "how" in low or "source" in low))
        row = {"line": j + 1, "text": ln.strip()[:240]}
        if is_header:
            continue
        data_rows.append(row)
        if unverified_re.search(ln):
            # Tolerated if an inline per-row rebuttal is present in the row.
            if INLINE_REBUTTAL_RE.search(ln):
                row["unverified_rebuttaled"] = True
            else:
                unverified_rows.append(row)

    payload["evidence"]["data_row_count"] = len(data_rows)
    payload["evidence"]["unverified_rows"] = unverified_rows[:16]

    if not data_rows:
        payload["verdict"] = "fail-no-assumption-ledger"
        payload["reason"] = (
            "A 'Load-Bearing Assumption Ledger' heading is present but has no "
            "data rows. Enumerate each load-bearing assumption as a table row."
        )
        return 1, payload

    if unverified_rows:
        payload["verdict"] = "fail-unverified-load-bearing-assumption"
        payload["reason"] = (
            f"{len(unverified_rows)} ledger row(s) are UNVERIFIED with no inline "
            "rebuttal. A load-bearing claim that rests on an unverified "
            "assumption (esp. external-dependency behavior, library defaults, "
            "deployment/config, or protocol-version semantics) must be anchored "
            "to source / measurement / config, or carry "
            "'r78-unverified-rebuttal: <reason>' in the row. First offending "
            f"row at line {unverified_rows[0]['line']}."
        )
        return 1, payload

    # Did any rows carry an inline rebuttal rather than a real anchor?
    rebuttaled = any(r.get("unverified_rebuttaled") for r in data_rows)
    if rebuttaled:
        payload["verdict"] = "pass-assumption-ledger-unverified-rebuttaled"
        payload["reason"] = (
            "Assumption ledger present; every UNVERIFIED row carries an inline "
            "r78-unverified-rebuttal."
        )
        return 0, payload

    payload["verdict"] = "pass-assumption-ledger-complete"
    payload["reason"] = (
        f"Assumption ledger present with {len(data_rows)} row(s); no UNVERIFIED "
        "load-bearing assumption."
    )
    return 0, payload


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("draft", type=Path)
    parser.add_argument("--severity", default="auto",
                        choices=["auto", "LOW", "MEDIUM", "HIGH", "CRITICAL",
                                 "low", "medium", "high", "critical"])
    parser.add_argument("--strict", action="store_true")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)

    rc, payload = run(args.draft, severity_override=args.severity, strict=args.strict)
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(f"[R78] {payload['verdict']}: "
              f"{payload.get('reason', payload.get('error', ''))}")
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
