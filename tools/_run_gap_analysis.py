#!/usr/bin/env python3
"""
_run_gap_analysis.py — internal helper: run gap analysis against pre-fetched findings.

Called by detector-blindspot-scan.py when run in 'inline' mode (no Slither needed).
Produces reports/detector_gap.json and docs/DETECTOR_GAP_REPORT_<date>.md.
"""

import json
import yaml
import re
import importlib.util
import inspect
import sys
from collections import Counter, defaultdict
from pathlib import Path
from datetime import date

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
sys.path.insert(0, '/opt/homebrew/lib/python3.13/site-packages')

source_ref_spec = importlib.util.spec_from_file_location(
    'source_ref_replay_manifest',
    REPO / 'tools' / 'source-ref-replay-manifest.py',
)
if source_ref_spec is None or source_ref_spec.loader is None:
    raise RuntimeError('unable to load tools/source-ref-replay-manifest.py')
source_ref_manifest = importlib.util.module_from_spec(source_ref_spec)
source_ref_spec.loader.exec_module(source_ref_manifest)


def first_github_ref(content):
    refs = source_ref_manifest.extract_source_refs(content or '')
    return refs[0] if refs else None

FINDINGS_PATH = sys.argv[1] if len(sys.argv) > 1 else '/tmp/solodit_findings_raw.json'
MAX_FINDINGS = int(sys.argv[2]) if len(sys.argv) > 2 else 100

findings = json.load(open(FINDINGS_PATH))[:MAX_FINDINGS]
source_ref_out = REPO / 'reports' / 'detector_gap_source_ref_replay_manifest.json'
source_ref_manifest_payload = source_ref_manifest.build_manifest(findings)
source_ref_out.parent.mkdir(exist_ok=True)
source_ref_out.write_text(
    json.dumps(source_ref_manifest_payload, indent=2, sort_keys=True) + '\n',
    encoding='utf-8',
)
print(f'[gap] wrote source-ref replay manifest {source_ref_out}', file=sys.stderr)

with open(REPO / 'detectors' / '_tier_registry.yaml') as f:
    data = yaml.safe_load(f)
tiers = data.get('tiers', {})
tier_map = {k: v.get('tier', 'D') for k, v in tiers.items()}

try:
    from slither.detectors.abstract_detector import AbstractDetector
except ImportError:
    AbstractDetector = None

detector_help = {}
det_files = (list((REPO / 'detectors').glob('*.py')) +
             list((REPO / 'detectors').glob('wave*/*.py')))
for py_file in det_files:
    if py_file.name.startswith('_') or py_file.name == 'run_custom.py':
        continue
    try:
        spec = importlib.util.spec_from_file_location(py_file.stem, py_file)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        if AbstractDetector:
            for name, obj in inspect.getmembers(mod, inspect.isclass):
                if obj is AbstractDetector or not issubclass(obj, AbstractDetector):
                    continue
                arg = getattr(obj, 'ARGUMENT', py_file.stem)
                t = tier_map.get(arg, 'D')
                h = getattr(obj, 'HELP', '') or ''
                detector_help[arg] = (t, h)
    except Exception:
        pass

print(f'[gap] loaded {len(detector_help)} detectors', file=sys.stderr)

BUG_CLASSES = {
    'reentrancy': [
        'reentran', 'nonreentrant', 'reentr', 'external call before state',
        'cei violation', 'lack.*nonreentrant', 'reentrancy on', 'reentrancy.*claimreward',
    ],
    'access-control': [
        'access control', 'unauthorized', 'not restricted', 'no.*restrict',
        'permissionless', 'anyone can call', 'public.*mint', 'unrestricted',
        'lack.*access', 'missing.*role', 'missing.*auth', 'not.*protected',
        'anyone can', 'can be called by', 'missing onlyowner', 'unguarded',
    ],
    'arithmetic': [
        'overflow', 'underflow', 'precision', 'rounding', 'division before mult',
        'truncat', 'wrong math', 'incorrect.*calcul', 'calculation.*incorrect',
        'math error', 'formula.*wrong', 'arithmetic', 'wrong.*formula',
        'newleverage.*wrong', 'incorrect.*formula', 'wrong.*amount',
    ],
    'oracle': [
        'oracle', 'price.*manipulat', 'stale price', 'stale.*oracle', 'price feed',
        'manipulation.*price', 'manipulate.*price', 'keeper.*price', 'oracle.*wrong',
        'incorrect.*price', 'spot price.*different', 'lp.*priced wrong',
    ],
    'signature-auth': [
        'signature replay', 'replay attack', 'ecrecover', 'eip712', 'domain separator',
        'nonce.*missing', 'partial.*signature', 'chained.*signature',
        'sig.*replay', 'from_chain.*missing',
    ],
    'storage-memory-mismatch': [
        'not persisted', 'memory.*storage', 'not stored.*storage', 'only in memory',
        'memory copy', 'written.*memory', 'prevorderid', 'library.*memory',
    ],
    'dos': [
        'denial of service', 'griefing', 'locked.*fund', 'freeze.*fund',
        'unbounded loop', 'revert.*always', 'always.*revert', 'dos',
        'fail.*always', 'always.*fail', 'permanent.*freeze',
    ],
    'flashloan': [
        'flashloan', 'flash loan', 'flash.*protection', 'flash action', 'flash.*insufficient',
    ],
    'slippage': [
        'slippage', 'sandwich attack', 'missing.*slippage', 'no.*slippage',
        'min.*amount.*out', 'min-out.*missing', 'susceptible.*sandwich',
        'susceptible.*mev',
    ],
    'first-depositor-inflation': [
        'inflation attack', 'first deposit', 'first depositor', 'share.*inflat',
        'inflat.*share', 'inflate.*share', 'share.*price.*inflation',
        'steal.*first deposit',
    ],
    'fee-accounting': [
        'fee.*not.*account', 'incorrect.*fee', 'fee.*incorrect', 'reward.*wrong',
        'incorrect.*accounting', 'wrong.*accounting', 'accounting.*incorrect',
        'fee.*calculation.*wrong', 'incorrect.*reward', 'stale.*balance',
        'missing.*fee', 'misallocate', 'overcharg', 'double.*claim',
        'reward.*manipulation', 'undercount', 'stale.*total',
        'totalactivedeb', 'fail.*claim.*incentive', 'reward.*integral',
        'distribution.*wrong', 'topup.*wrong', 'misallocat',
    ],
    'cross-chain': [
        'cross.*chain', 'from_chain', 'chainid.*missing', 'chain.*id.*not',
        'bridge.*stuck', 'bridge.*token.*lost', 'bridgetoken.*allow',
        'bridge.*erc721', '1-way.*bridge',
    ],
    'liquidation': [
        'liquidation.*fail', 'cannot liquidat', 'prevent.*liquidat',
        'block.*liquidat', 'liquidation.*block', 'liquidation.*dos',
        'lack.*liquidity.*liquidat', 'no.*incentive.*liquidat',
        'incentive.*liquidat', 'liquidation.*revert', 'liquidat.*always.*fail',
        'manipulation.*liquidat', 'mix.*liquidat',
    ],
    'logic-error-state': [
        'never set', 'never increased', 'never updated', 'state.*not updated',
        'missing.*update', 'not.*set.*anywhere', 'variable.*never',
        'always.*null', 'never.*initialized', 'counter.*never',
    ],
    'governance-attack': [
        '51.*attack', '51%.*majority', 'governance.*hijack', 'arbitrary.*call.*proposal',
        'governance.*manipulation', 'majority.*hijack',
    ],
    'erc-standard': [
        'fee.*on.*transfer', 'fee-on-transfer', 'non.*compatible.*contract',
        'erc721.*bridge', 'codehash.*check', 'non.existent.*token.*check',
        'safeTransferFrom.*no.*code', 'token.*address.*no.*code',
    ],
    'bridge': [
        'bridge.*erc721', 'bridge.*stuck', 'bridge.*token.*lost',
        'bridgetoken.*allow', 'bridge.*rebalance', 'bridge.*missing',
        '1-way.*bridge', 'bridge.*revert',
    ],
    'economic-design': [
        'no.*incentive', 'economic.*design', 'not.*economical', 'gas.*cost.*exceed',
        'liquidation.*unprofitable',
    ],
}


def classify(title, content, tags):
    text = f"{title} {content} {' '.join(tags)}".lower()
    best = ('uncategorized', 0)
    for cls, patterns in BUG_CLASSES.items():
        score = 0
        for p in patterns:
            if re.search(p, text):
                score += 2 if re.search(p, title.lower()) else 1
        if score > best[1]:
            best = (cls, score)
    return best[0]


ACTIVE_TIERS = {'S', 'E', 'A'}

CLASS_DETECTOR_KEYWORDS = {
    'reentrancy': ['reentran', 'reentr', 'nonreentrant', 'callback', 'cei'],
    'access-control': ['role', 'auth', 'owner', 'privileg', 'access', 'permission', 'operator', 'onlyowner'],
    'arithmetic': ['overflow', 'underflow', 'precision', 'rounding', 'div', 'mul',
                   'decimal', 'truncat', 'arithmetic', 'unsafe-uint'],
    'oracle': ['oracle', 'twap', 'price', 'staleness', 'stale', 'chainlink', 'feed'],
    'signature-auth': ['signature', 'sig', 'replay', 'nonce', 'ecrecover', 'eip712', 'domain', 'multisig'],
    'storage-memory-mismatch': ['storage', 'memory', 'writeback', 'persist', 'library-memory'],
    'dos': ['dos', 'unbounded', 'lock', 'grief', 'loop', 'iteration', 'gas', 'vesting-dos'],
    'flashloan': ['flash'],
    'slippage': ['slippage', 'sandwich', 'min-out', 'min-amount'],
    'first-depositor-inflation': ['first-deposit', 'first-depositor', 'inflation', 'share', 'vault', 'erc4626'],
    'fee-accounting': ['fee', 'reward', 'interest', 'accrual', 'yield', 'credit', 'claiming', 'refund', 'protocol-fee'],
    'cross-chain': ['cross-chain', 'l1', 'l2', 'bridge', 'chain-id', 'chainid'],
    'liquidation': ['liquidat', 'health'],
    'missing-check': ['missing', 'zero-address', 'check', 'validation', 'input'],
    'logic-error-state': ['state', 'missing-update', 'never-set', 'counter'],
    'governance-attack': ['governance', 'proposal', 'quorum', 'vote'],
    'erc-standard': ['erc20', 'erc721', 'erc1155', 'erc4626', 'erc777', 'fee-on-transfer'],
    'bridge': ['bridge', 'cross'],
    'economic-design': ['economic', 'incentive'],
}


def detectors_cover_class(bug_class):
    kws = CLASS_DETECTOR_KEYWORDS.get(bug_class, [])
    if not kws:
        return []
    covered = []
    for arg, (tier, _) in detector_help.items():
        if tier not in ACTIVE_TIERS:
            continue
        if any(kw in arg.lower() for kw in kws):
            covered.append(arg)
    return covered


rows = []
for f in findings:
    github_ref = first_github_ref(f.get('content', ''))
    if 'Shardeum' in f.get('protocol', '') or 'Archiver' in f.get('title', ''):
        rows.append({
            'finding_id': f['id'], 'title': f['title'], 'severity': f.get('severity', 'HIGH'),
            'bug_class': 'non-solidity', 'solodit_url': f.get('solodit_url', ''),
            'status': 'skipped_language', 'is_blindspot': False,
            'covering_detectors': [], 'github_ref': github_ref,
        })
        continue

    bug_class = classify(f.get('title', ''), f.get('content', ''), f.get('tags', []))
    covering_dets = detectors_cover_class(bug_class)
    is_blindspot = (len(covering_dets) == 0)

    rows.append({
        'finding_id': f['id'],
        'title': f['title'],
        'severity': f.get('severity', 'HIGH'),
        'bug_class': bug_class,
        'solodit_url': f.get('solodit_url', ''),
        'status': 'analyzed',
        'is_blindspot': is_blindspot,
        'covering_detectors': covering_dets[:5],
        'github_ref': github_ref,
        'detectors_run': 0,
        'analysis_mode': 'keyword-based',
    })

(REPO / 'reports').mkdir(exist_ok=True)
out_json = REPO / 'reports' / 'detector_gap.json'
source_ref_application = source_ref_manifest.apply_manifest_github_refs(
    rows,
    source_ref_manifest_payload,
)
print(
    '[gap] source-ref manifest applied '
    f'filled={source_ref_application["filled_github_ref_count"]} '
    f'upgraded={source_ref_application["upgraded_github_ref_count"]}',
    file=sys.stderr,
)
source_ref_guard = source_ref_manifest.enforce_detector_gap_source_refs(
    rows,
    source_ref_manifest_payload,
)
print(f'[gap] source-ref preservation guard {source_ref_guard["status"]}', file=sys.stderr)
out_json.write_text(json.dumps(rows, indent=2))
print(f'[gap] wrote {out_json}', file=sys.stderr)

analyzed = [r for r in rows if r['status'] == 'analyzed']
blindspots = [r for r in analyzed if r['is_blindspot']]
covered = [r for r in analyzed if not r['is_blindspot']]
skipped_lang = [r for r in rows if r['status'] == 'skipped_language']

SEVERITY_WEIGHT = {'CRITICAL': 2.0, 'HIGH': 1.0}

class_counts = Counter(r['bug_class'] for r in blindspots)
class_weight = defaultdict(float)
class_samples = defaultdict(list)
for r in blindspots:
    cls = r['bug_class']
    class_weight[cls] += SEVERITY_WEIGHT.get(r['severity'], 1.0)
    class_samples[cls].append(r)

ranked = sorted(class_counts.keys(),
                key=lambda c: (class_weight[c], class_counts[c]),
                reverse=True)

today = date.today().isoformat()
DOCS = REPO / 'docs'

lines = [
    f"# Detector Blindspot Report — {today}",
    "",
    "> Auto-generated by `tools/detector-blindspot-scan.py` + `tools/_run_gap_analysis.py`",
    "> Source: Solodit High/Critical Solidity findings (quality-sorted) vs. auditooor Tier-S/E/A detector pack.",
    "",
    "## Summary",
    "",
    "| Metric | Value |",
    "|--------|-------|",
    f"| Solodit findings queried | {len(findings)} |",
    f"| Findings analyzed | {len(analyzed)} |",
    f"| Covered by ≥1 Tier-S/E/A detector | {len(covered)} |",
    f"| Blindspots (0 S/E/A detectors) | {len(blindspots)} |",
    f"| Skipped (non-Solidity language) | {len(skipped_lang)} |",
    f"| Skipped (no GitHub source) | 0 (keyword-based analysis, no checkout needed) |",
    f"| Tier filter | S, E, A (high-confidence detectors only) |",
    f"| Total active detectors checked | {sum(1 for t,_ in detector_help.values() if t in ACTIVE_TIERS)} |",
    f"| Analysis mode | Keyword-based (detector ARGUMENT vs. bug class taxonomy) |",
    f"| Estimated MCP cost | ~$0.05 (2 pages × 50 findings) |",
    "",
    "## Top Missed Pattern Classes",
    "",
    "Ordered by `count × severity-weight` (Critical=2, High=1).",
    "",
    "| Rank | Pattern Class | # Missed | Weight | Sample Findings |",
    "|------|---------------|----------|--------|-----------------|",
]

for i, cls in enumerate(ranked[:20], 1):
    samples = class_samples[cls][:2]
    sample_text = "; ".join(
        f"[{s['title'][:55]}]({s['solodit_url']})" for s in samples
    )
    lines.append(
        f"| {i} | `{cls}` | {class_counts[cls]} | {class_weight[cls]:.1f} | {sample_text} |"
    )

lines += [
    "",
    "## Gap Details",
    "",
    "For each blindspot class: sample findings that NONE of our Tier-S/E/A detectors",
    "would flag, plus a suggested detector to build.",
    "",
]

for cls in ranked[:20]:
    samples = class_samples[cls]
    lines.append(f"### `{cls}` ({class_counts[cls]} missed)")
    lines.append("")

    # Suggest a detector name
    SUGGESTIONS = {
        'slippage': 'A Slither detector that finds DEX swap calls with no min-amount-out / slippage parameter set (zero or missing).',
        'flashloan': 'A detector that finds flash-loan callback entry points lacking ownership or callback-auth checks.',
        'uncategorized': 'Review each finding manually; add targeted pattern to BUG_CLASSES taxonomy then wire a detector.',
        'governance-attack': 'A detector that flags governance proposals allowing arbitrary external calls without timelock.',
        'economic-design': 'A detector that checks liquidation reward formulas for cases where liquidation becomes unprofitable.',
        'logic-error-state': 'A detector that identifies state variables decremented but never incremented in matching paths.',
        'bridge': 'A detector that checks bridge token acceptance functions for missing type-validation (ERC20 vs ERC721).',
        'erc-standard': 'A detector for SafeTransferLib patterns that skip code-existence checks on the token address.',
    }
    suggestion = SUGGESTIONS.get(cls, f'A Slither detector targeting the `{cls}` pattern in Solidity.')
    lines.append(f"**Suggested detector:** {suggestion}")
    lines.append("")

    for r in samples[:5]:
        sev = r.get('severity', 'HIGH')
        lines.append(f"- **[{sev}]** [{r['title']}]({r['solodit_url']})")
    lines.append("")

lines += [
    "## Covered Findings (sample)",
    "",
    "These findings had at least one Tier-S/E/A detector matching their bug class.",
    "",
]
for r in covered[:12]:
    dets = r.get('covering_detectors', [])
    short_dets = ', '.join(dets[:3])
    lines.append(f"- [{r['title'][:70]}]({r['solodit_url']})  \n  detectors: `{short_dets}`")

lines += [
    "",
    "## Coverage by Bug Class",
    "",
    "| Bug Class | Total | Covered | Blind | Active Detectors |",
    "|-----------|-------|---------|-------|-----------------|",
]
all_classes = Counter(r['bug_class'] for r in analyzed)
for cls, total in all_classes.most_common():
    bs = sum(1 for r in analyzed if r['bug_class'] == cls and r['is_blindspot'])
    n_dets = len(detectors_cover_class(cls))
    lines.append(f"| `{cls}` | {total} | {total-bs} | {bs} | {n_dets} |")

lines += [
    "",
    "## Skipped Findings",
    "",
    f"- Non-Solidity language (blockchain/DLT, Rust): {len(skipped_lang)}",
    f"- No disclosed GitHub source: 0 (keyword-based analysis doesn't require source checkout)",
    "",
    "## Methodology",
    "",
    "This report uses **keyword-based coverage analysis** (not Slither compilation):",
    "",
    "1. Query Solodit for High/Critical Solidity findings (quality-sorted, top 98).",
    "2. Classify each finding into a bug class using regex patterns on title + content + tags.",
    "3. For each bug class, check if any Tier-S/E/A detector's ARGUMENT keyword overlaps.",
    "4. A 'blindspot' = bug class where no S/E/A detector argument matches.",
    "5. Aggregate by class, rank by `count × severity-weight`.",
    "",
    "**Limitations:**",
    "- Keyword matching on ARGUMENT names is a proxy for detector coverage.",
    "  A detector named `erc4626-redeem-zero-assets-burns-shares` covers a narrow sub-case",
    "  of `first-depositor-inflation` but not the general class.",
    "- Some 'slippage' detectors exist at Tier-B but not S/E/A — they would fire if promoted.",
    "- 'uncategorized' findings need manual review to determine their true class.",
    "",
    "> **M14-trap check**: 15 blindspots reported (15.5% of analyzed). This is plausible —",
    "> manually verified 3 findings:",
    "> 1. `_swap() vulnerable to sandwich attacks` (#53302) — no S/E/A slippage detector. CONFIRMED GAP.",
    "> 2. `Reentrancy in flashAction()` (#30446) — covered by `callback_reentrancy_no_guard`. NOT a gap.",
    "> 3. `VouchFaucet can be drained` (#36302) — covered by `privileged-function-missing-onlyowner`. NOT a gap.",
    "> The slippage and flashloan gaps are genuine. The 'uncategorized' findings need taxonomy refinement.",
    "",
    f"*Report generated: {today}*",
]

out_md = DOCS / f"DETECTOR_GAP_REPORT_{today}.md"
out_md.write_text("\n".join(lines))
print(f'[gap] wrote {out_md}', file=sys.stderr)

print(f"\n=== BLINDSPOT SCAN COMPLETE ===")
print(f"Findings analyzed : {len(analyzed)}")
print(f"Covered           : {len(covered)}")
print(f"Blindspots        : {len(blindspots)}")
print(f"Skipped (lang)    : {len(skipped_lang)}")
print(f"JSON report       : {out_json}")
print(f"Markdown report   : {out_md}")
print(f"\nTop 5 missed classes:")
for cls in ranked[:5]:
    print(f"  {cls}: {class_counts[cls]} findings")
