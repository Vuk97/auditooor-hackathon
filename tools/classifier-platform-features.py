#!/usr/bin/env python3
"""
classifier-platform-features.py — R73 B3: per-platform feature extraction
for the rejection classifier.

Motivation: the existing classifier (rejection-classifier.py) was trained on
mixed Solodit data and treats all triage outcomes the same. In reality,
different platforms reject with systematically different biases:

    Cantina     — tight-duplicate heuristic; admin-error often dismissed
    Sherlock    — 'loss of yield' alone usually rejected as LOW; strict rules
    Code4rena   — judge rotation; spec-deviation-without-loss often downgraded
    Hackenproof — stable payouts but strict novel-vector clause
    Immunefi    — critical requires PoC; 'theoretical' → low

This module computes per-platform feature flags from a finding draft + the
target platform, returning a dense feature-vector extension that the main
classifier can concatenate to its Solodit-derived features. Over time, the
platform-specific features should move from hardcoded heuristics to
per-platform classifier heads trained on feedback logs.

Usage (Python import):
    from classifier_platform_features import platform_features
    feats = platform_features(
        finding_text=draft_md,
        platform='cantina',
        claimed_severity='HIGH',
        submission_meta={'workspace': 'kiln-v1', 'detector': 'ec-rate-limit-bypass'},
    )
    # feats is a dict of {feature_name: float}

CLI usage (for inspection):
    python3 tools/classifier-platform-features.py --platform cantina \\
        --severity HIGH --finding examples/draft.md
"""

import argparse
import json
import pathlib
import re
import sys
from typing import Dict

ROOT = pathlib.Path(__file__).resolve().parent.parent
HEURISTIC_YAML = ROOT / "reference" / "platform_heuristics.yaml"

# ── Default heuristic config — bootstrapped from past rejection patterns ──
DEFAULT_HEURISTICS = {
    "cantina": {
        "dupe_tight": True,
        "admin_error_lowered": True,
        "novel_vector_bonus": 0.15,
        "pass_requires_poc": True,
        "kill_phrases_body": [
            r"admin\s+misconfig",
            r"if\s+the\s+admin",
            r"governance\s+could",
        ],
        "kill_phrases_title": [
            r"best\s+practice",
            r"gas\s+optimi",
            r"natspec|typo",
        ],
    },
    "sherlock": {
        "dupe_tight": False,
        "yield_loss_alone_rejected": True,
        "novel_vector_bonus": 0.10,
        "pass_requires_poc": True,
        "kill_phrases_body": [
            r"potential\s+loss",
            r"theoretical",
            r"worst\s+case",
            r"unlikely\s+to\s+trigger",
        ],
        "kill_phrases_title": [
            r"view\s+function|pure\s+function",
            r"out\s+of\s+scope|oos",
        ],
    },
    "code4rena": {
        "dupe_tight": True,
        "spec_deviation_downgrade": True,
        "novel_vector_bonus": 0.20,
        "pass_requires_poc": False,
        "kill_phrases_body": [
            r"as\s+intended",
            r"documentation\s+issue",
            r"informational",
        ],
        "kill_phrases_title": [
            r"qa\s+report",
            r"analysis",
        ],
    },
    "hackenproof": {
        "dupe_tight": False,
        "requires_strict_novel_vector": True,
        "novel_vector_bonus": 0.25,
        "pass_requires_poc": True,
        "kill_phrases_body": [
            r"theoretical\s+only",
            r"no\s+PoC",
        ],
        "kill_phrases_title": [],
    },
    "immunefi": {
        "dupe_tight": True,
        "critical_requires_live_exploit": True,
        "novel_vector_bonus": 0.10,
        "pass_requires_poc": True,
        "kill_phrases_body": [
            r"hypothetical",
            r"edge\s+case\s+only",
        ],
        "kill_phrases_title": [
            r"info:",
            r"low:",
        ],
    },
}

def _load_heuristics():
    """Load platform heuristics; fall back to defaults."""
    try:
        import yaml
        if HEURISTIC_YAML.exists():
            return yaml.safe_load(HEURISTIC_YAML.read_text()) or DEFAULT_HEURISTICS
    except Exception:
        pass
    return DEFAULT_HEURISTICS


def platform_features(
    finding_text: str,
    platform: str,
    claimed_severity: str = "MEDIUM",
    submission_meta: Dict | None = None,
) -> Dict[str, float]:
    """
    Return a dense feature dict {feature_name: float} that augments the
    Solodit-derived features consumed by rejection-classifier.py.

    All features live under the `platform_` prefix so the main classifier
    can enable/disable the whole group with one flag.
    """
    H = _load_heuristics()
    p = platform.lower().strip()
    cfg = H.get(p, {})
    submission_meta = submission_meta or {}
    txt = (finding_text or "").lower()
    title = re.search(r'^#+\s*(.+)$', finding_text or "", flags=re.M)
    title = (title.group(1) if title else "")[:300].lower()

    feats: Dict[str, float] = {
        "platform_is_known": 1.0 if cfg else 0.0,
        "platform_id_hash": hash(p) % 997 / 997.0,  # cheap embedding
        "platform_cantina": 1.0 if p == "cantina" else 0.0,
        "platform_sherlock": 1.0 if p == "sherlock" else 0.0,
        "platform_code4rena": 1.0 if p == "code4rena" else 0.0,
        "platform_hackenproof": 1.0 if p == "hackenproof" else 0.0,
        "platform_immunefi": 1.0 if p == "immunefi" else 0.0,
    }

    # Rule-derived quality signals
    feats["platform_dupe_tight"] = float(cfg.get("dupe_tight", False))
    feats["platform_pass_requires_poc"] = float(cfg.get("pass_requires_poc", False))
    feats["platform_novel_vector_bonus"] = float(cfg.get("novel_vector_bonus", 0.0))

    # Kill-phrase hits — these are known triage-reject patterns
    body_kill = 0
    for pat in cfg.get("kill_phrases_body", []):
        if re.search(pat, txt):
            body_kill += 1
    title_kill = 0
    for pat in cfg.get("kill_phrases_title", []):
        if re.search(pat, title):
            title_kill += 1
    feats["platform_kill_body_count"] = float(body_kill)
    feats["platform_kill_title_count"] = float(title_kill)
    feats["platform_any_kill_hit"] = 1.0 if (body_kill or title_kill) else 0.0

    # Severity-specific gates
    sev = claimed_severity.upper().strip()
    feats["platform_claim_high_or_crit"] = 1.0 if sev in ("HIGH", "CRITICAL") else 0.0

    # Sherlock: yield-loss alone → penalty
    if cfg.get("yield_loss_alone_rejected") and "loss of yield" in txt and "loss of funds" not in txt:
        feats["platform_sherlock_yield_only"] = 1.0
    else:
        feats["platform_sherlock_yield_only"] = 0.0

    # Cantina: admin-error → penalty
    if cfg.get("admin_error_lowered"):
        m = re.search(r'admin\s+(error|misconfig|mistake|could)', txt)
        feats["platform_cantina_admin_excuse"] = 1.0 if m else 0.0
    else:
        feats["platform_cantina_admin_excuse"] = 0.0

    # Code4rena: spec-deviation-without-loss → downgrade
    if cfg.get("spec_deviation_downgrade"):
        m = re.search(r'(deviates?|does not match)\s+(the\s+)?spec', txt)
        no_loss = ("loss of funds" not in txt) and ("loss of user funds" not in txt)
        feats["platform_c4_spec_only"] = 1.0 if (m and no_loss) else 0.0
    else:
        feats["platform_c4_spec_only"] = 0.0

    # Hackenproof: novel-vector clause
    if cfg.get("requires_strict_novel_vector"):
        m = re.search(r'(novel|new|previously unknown|first-seen)', txt)
        feats["platform_hp_novel_claim"] = 1.0 if m else 0.0
    else:
        feats["platform_hp_novel_claim"] = 0.0

    # Immunefi: critical needs live-exploit evidence
    if cfg.get("critical_requires_live_exploit") and sev == "CRITICAL":
        m = re.search(r'(fork-test|live poc|mainnet fork|reproduces on mainnet)', txt)
        feats["platform_imm_crit_has_live"] = 1.0 if m else 0.0
    else:
        feats["platform_imm_crit_has_live"] = 0.0

    # Prior-workspace outcome signal (if in meta)
    ws = submission_meta.get("workspace", "")
    feats["platform_meta_has_workspace"] = 1.0 if ws else 0.0

    # PoC presence — ubiquitous signal across platforms
    has_poc_link = bool(re.search(r'\.t\.sol|forge test|proof of concept', txt))
    feats["platform_has_poc_hint"] = 1.0 if has_poc_link else 0.0

    return feats


def _main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--platform", choices=list(DEFAULT_HEURISTICS.keys()))
    ap.add_argument("--severity", default="MEDIUM")
    ap.add_argument("--finding", help="path to finding.md")
    ap.add_argument("--workspace", default="")
    ap.add_argument("--detector", default="")
    ap.add_argument("--write-default-heuristics", action="store_true",
                    help="write DEFAULT_HEURISTICS to reference/platform_heuristics.yaml")
    args = ap.parse_args()

    if args.write_default_heuristics:
        try:
            import yaml
        except ImportError:
            print("[err] PyYAML required", file=sys.stderr); sys.exit(1)
        HEURISTIC_YAML.parent.mkdir(parents=True, exist_ok=True)
        HEURISTIC_YAML.write_text(yaml.safe_dump(DEFAULT_HEURISTICS, sort_keys=False, default_flow_style=False))
        print(f"[ok] wrote {HEURISTIC_YAML}")
        return

    txt = pathlib.Path(args.finding).read_text()
    meta = {"workspace": args.workspace, "detector": args.detector}
    feats = platform_features(txt, args.platform, args.severity, meta)
    print(json.dumps(feats, indent=2))


if __name__ == "__main__":
    _main()
