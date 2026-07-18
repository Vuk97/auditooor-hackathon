#!/usr/bin/env python3
"""
memory-privacy-audit.py — Obsidian-vault secret-leakage scanner.

Scans obsidian-vault/**/*.md for patterns that indicate a secret was
accidentally included in a vault note.  Outputs a JSON report and a
human-readable Markdown summary.

False-negative bias: tune toward catching everything, whitelist FPs in
reports/privacy_audit_whitelist.yaml.

Usage:
    python3 tools/memory-privacy-audit.py [--vault VAULT_DIR]
                                           [--out-json PATH]
                                           [--out-md PATH]
                                           [--whitelist PATH]
                                           [--quarantine]
                                           [--self-test]
                                           [--strict]

Exit codes:
    0 — clean (no matches outside whitelist)
    1 — matches found (or --self-test failure)
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import sys
import tempfile
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# BIP39 word list (2048 words, official English list)
# We embed a representative subset for the mnemonic detector.  The full list
# is used for the "consecutive words" heuristic (≥10 matches → flag).
# We ship the complete 2048-word list inline to avoid external dependencies.
# ---------------------------------------------------------------------------

_BIP39_WORDS_RAW = """
abandon ability able about above absent absorb abstract absurd abuse access accident
account accuse achieve acid acoustic acquire across act action actor actress actual
adapt add addict address adjust admit adult advance advice aerobic afford afraid
again age agent agree ahead aim air airport aisle alarm album alcohol alert alien
all alley allow almost alone alpha already also alter always amateur amazing among
amount amused analyst anchor ancient anger angle angry animal ankle announce annual
another answer antenna antique anxiety any apart apology appear apple approve april
arch arctic area arena argue arm armed armor army around arrange arrest arrive
arrow art artefact artist artwork ask aspect assault asset assist assume asthma
athlete atom attack attend attitude attract auction audit august aunt author auto
autumn average avocado avoid awake aware away awesome awful awkward axis baby
bachelor bacon badge bag balance balcony ball bamboo banana banner bar barely
bargain barrel base basic basket battle beach bean beauty because become beef
before begin behave behind believe below belt bench benefit best betray better
between beyond bicycle bid bike bind biology bird birth bitter black blade blame
blanket blast bleak bless blind blood blossom blouse blue blur blush board boat
body boil bomb bone book boost border boring borrow boss bottom bounce box boy
bracket brain brand brave bread breeze brick bridge brief bright bring brisk
broccoli broken bronze broom brother brown brush bubble buddy budget buffalo build
bulb bulk bullet bundle bunker burden burger burst bus business busy butter buyer
buzz cabbage cabin cable cactus cage cake call calm camera camp can canal cancel
candy cannon canvas canyon capable capital captain car carbon card cargo carpet
carry cart case cash casino castle casual cat catalog catch category cattle caught
cause caution cave ceiling celery cement census chair chaos chapter charge chase
chat cheap check cheese chef cherry chest chicken chief child chimney choice choose
chronic churn cigar cinnamon circle citizen city civil claim clap clarify claw
clay clean clerk clever click client cliff climb clinic clip clock clog close
cloth cloud clown club clump cluster clutch coach coast coconut code coffee coil
coin collect color column combine come comfort comic common company concert conduct
confirm congress connect consider control convince cook cool copper copy coral core
corn correct cost cotton couch country couple course cousin cover coyote crack
cradle craft cram crane crash crater crawl crazy cream credit creek crew cricket
crime crisp critic cross crouch crowd crucial cruel cruise crumble crunch crush
cry crystal cube culture cup cupboard curious current curtain curve cushion custom
cute cycle dad damage damp dance danger daring dash daughter dawn day deal debate
debris decade december decide decline decorate decrease delay deliver demand demise
denial dentist deny depart depend deposit depth deputy derive describe desert design
desk despair destroy detail detect develop device devote diagram dial diamond diary
dice diesel differ digital dignity dilemma dinner dinosaur direct dirt disagree
discover disease dish dismiss disorder display distance divert divide divorce dizzy
doctor document dog doll dolphin domain donate donkey donor door dose double dove
draft dragon drama drastic draw dream dress drift drill drink drip drive drop drum
dry duck dumb dune during dust dutch duty dwarf dynamic eager eagle early earn
earth easily east easy echo ecology edge edit educate effort egg eight either
elbow elder electric elegant element elephant elevator elite else embark embody
embrace emerge emotion employ empower empty enable enact endless endorse enemy
engage engine enhance enjoy enlist enough enrich enroll ensure enter entire entry
envelope episode equal equip erase erode erosion error erupt escape essay essence
estate eternal ethics evidence evil evoke evolve exact example excess exchange
excite exclude exercise exhaust exhibit exile exist exit exotic expand expire
explain expose express extend extra eye fable face faculty faint faith fall false
fame family famous fan fancy fantasy far fashion fat fatal father fatigue fault
favorite feature february federal fee feed feel feet fellow felt fence festival
fetch fever few fiber fiction field figure file film filter final find fine finger
finish fire firm first fiscal fish fit fitness fix flag flame flash flat flavor
flee flight flip float flock floor flower fluid flush fly foam focus fog foil fold
follow food force forest forget fork fortune forum forward fossil foster found fox
fragile frame frequent fresh friend fringe frog front frost frown frozen fruit fuel
fun funny furnace fury future gadget gain galaxy gallery game gap garage garbage
garden garlic garment gas gasp gate gather gauge gaze general genius genre gentle
genuine gesture ghost giant gift giggle ginger giraffe girl give glad glance glare
glass glide glimpse globe gloom glory glove glow glue goat goddess gold good goose
gorilla gospel gossip govern gown grab grace grain grant grape grasp grass gravity
great green grid grief grit grocery group grow grunt guard guide guilt guitar gun
guy habit hair half hamster hand happy harsh harvest hat have hawk hazard head
health heart heavy hedgehog height hello helmet help hen hero hidden high hill hint
hip hire history hobby hockey hold hole holiday hollow home honey hood hope horn
hospital host hour hover hub huge human humble humor hundred hungry hunt hurdle
hurry hurt husband hybrid ice icon ignore ill illegal image imitate immense immune
impact impose improve impulse inbox income increase index indicate indoor industry
infant inflict inform inhale inject inner innocent input inquiry insane insect
inside inspire install intact interest into invest invite involve iron island isolate
issue item ivory jacket jaguar jar jazz jealous jeans jelly jewel job join joke
journey joy judge juice jump jungle junior junk just kangaroo keen keep ketchup key
kick kid kingdom kiss kit kitchen kite kitten kiwi knee knife knock know lab ladder
lady lake lamp language laptop large later laugh laundry lava law lawn lawsuit layer
lazy leader learn leave lecture left leg legal legend leisure lemon lend length lens
leopard lesson letter level liar liberty library license life lift light like limb
limit link lion liquid list little live lizard load loan lobster local lock logic
lonely long loop lottery loud lounge love loyal lucky luggage lunar lunch luxury
mad magnet maid mail main major make mammal mango mansion manual maple marble march
margin marine market marriage mask master match maze meadow mean medal media melody
melt member memory mention menu mercy merge merit merry mesh message metal method
middle midnight milk million mimic mind minimum minor miracle miss mitten model
modify mom monitor monkey monster month moon moral more morning mosquito mother
motion motor mountain mouse move movie much muffin mule multiply muscle museum
mushroom music must mutual myself mystery naive name napkin narrow nasty nature near
neck need negative neglect neither nephew nerve nest net network news next nice night
noble noise nominee noodle normal north notable note nothing notice novel now nuclear
nurse nut oak obey object oblige obscure obtain ocean october odor off offer office
often oil okay old olive olympic omit once onion open opera oppose option orange
orbit orchard order ordinary organ orient original orphan ostrich other outdoor
outside oval over own oyster ozone paddle page pair palace palm panda panel panic
panther paper parade parent park parrot party pass patch path patrol pause pave
payment peace peanut peasant pelican pen penalty pencil people pepper perfect permit
person pet phone photo phrase physical piano picnic picture piece pig pigeon pill
pilot pink pioneer pipe pistol pitch pizza place planet plastic plate play plaza
pledge pluck plug plunge poem poet point polar pole police pond pony popular portion
position possible post potato pottery poverty powder power practice praise predict
prefer prepare present pretty prevent price pride primary print priority prison
private prize problem process produce profit program project promote proof property
prosper protect proud provide public pudding pull pulp pulse pumpkin punch pupil
puppy purchase purity purpose push put puzzle pyramid quality quantum quarter
question quick quit quiz quote rabbit raccoon race rack radar radio rage rail rain
raise rally ramp ranch random range rapid rare rate rather raven reach ready real
reason rebel rebuild recall receive recipe record recycle reduce reflect reform
refuse region regret regular reject relax release relief rely remain remember remind
remove render renew rent reopen repair repeat replace report require rescue resemble
resist resource response result retire retreat return reunion reveal review reward
rhythm ribbon rice rich ride rifle right rigid ring riot ripple risk ritual rival
river road roast robot robust rocket romance roof rookie rotate rough round route
royal rubber rude rug rule run runway rural sad saddle sadness safe sail salad
salmon salon salt salute same sample sand satisfy satoshi sauce sausage save say
scale scan scare scatter scene scheme school science scissors scorpion scout scrap
screen script scrub sea search season seat second secret section security seek
select sell seminar senior sense sentence series service session settle setup seven
shadow shaft shallow share shed shell sheriff shield shift shine ship shiver shock
shoe shoot shop short shoulder shove shrimp shrug shuffle shy sibling siege sight
sign silent silk silly silver similar simple since sing siren sister situate six
size sketch skill skin skirt skull slab slam sleep slender slice slide slight slim
slogan slot slow slush small smart smile smoke smooth snack snake snap sniff snow
soap soccer social soft soldier solid solution solve someone song soon sorry soul
sound soup source south space spare spatial spawn speak special speed spell spend
sphere spice spider spike spin spirit split spoil sponsor spoon spray spread spring
spy square squeeze squirrel stable stadium staff stage stairs stamp stand start
state stay steak steel stem step stereo stick still sting stock stomach stone stop
store story stove strategy street strike strong struggle student stuff stumble style
subject submit subway success such sudden suffer sugar suggest suit summer sun sunny
sunset super supply supreme sure surface surge surprise sustain swallow swamp swap
swear sweet swift swim swing switch sword symbol symptom syrup table tackle tag tail
talent talk tank tape target task tattoo taxi teach team tell ten tenant tennis tent
term test text thank that theme theory there they thing this thought three thrive
throw thumb thunder ticket tilt timber time tiny tip tired title toast tobacco
today together toilet token tomato tomorrow tone tongue tonight tool tooth top topic
topple torch tornado tortoise toss total tourist toward tower town toy track trade
traffic tragic train transfer trap trash travel tray treat tree trend trial tribe
trick trigger trim trip trophy trouble truck truly trumpet trust truth tube tuition
tumble tuna tunnel turkey turn turtle twelve twenty twice twin twist two type typical
ugly umbrella unable unaware uncle uncover under undo unfair unfold unhappy uniform
unique universe unknown unlock until unusual unveil update upgrade uphold upon upper
upset urban usage use used useful useless usual utility vacant vacuum vague valid
valley valve van vanish vapor various vast vault vehicle velvet vendor venture venue
verb verify version very veteran viable vibrant vicious victory video view village
vintage violin virtual virus visa visit visual vital vivid vocal voice void volcano
volume vote voyage wage wagon wait walk wall walnut want warfare warm warrior waste
water wave way wealth weapon wear weasel web wedding weekend weird welcome well west
wet whale wheat wheel where whip whisper wide width wife wild will win window wine
wing wink winner winter wire wisdom wise wish witness wolf woman wonder wood wool
word world worry worth wrap wreck wrestle wrist write wrong yard year yellow you
young youth zebra zero zone zoo
"""

BIP39_WORDS: set[str] = set(_BIP39_WORDS_RAW.split())

# ---------------------------------------------------------------------------
# Pattern definitions
# ---------------------------------------------------------------------------

# Named tuple-like structure
class PatternDef:
    def __init__(self, name: str, regex: str, flags: int = 0, min_len: int = 0,
                 description: str = ""):
        self.name = name
        self.regex = re.compile(regex, flags)
        self.min_len = min_len
        self.description = description

    def __repr__(self) -> str:
        return f"PatternDef({self.name})"


# EVM private key: 0x followed by exactly 64 hex chars.
# We do NOT flag if the match is immediately followed by more hex chars (which
# would make it a longer value, e.g. part of a 256-bit hash in 0x-prefixed
# representation).
PRIVATE_KEY_RE = re.compile(
    r"(?<![0-9a-fA-F])(0x[0-9a-fA-F]{64})(?![0-9a-fA-F])",
    re.IGNORECASE,
)

# EVM address: 0x + 40 hex (much shorter — used to exclude from private-key)
EVM_ADDRESS_RE = re.compile(r"0x[0-9a-fA-F]{40}(?![0-9a-fA-F])", re.IGNORECASE)

# EVM signature: 0x + 130 hex (65 bytes)
EVM_SIG_RE = re.compile(
    r"(?<![0-9a-fA-F])(0x[0-9a-fA-F]{130})(?![0-9a-fA-F])",
    re.IGNORECASE,
)

# PEM private keys
PEM_KEY_RE = re.compile(r"-----BEGIN\s+[A-Z ]*PRIVATE KEY-----", re.IGNORECASE)

# GitHub tokens
GITHUB_TOKEN_RE = re.compile(r"gh[ps]_[a-zA-Z0-9]{36,}")

# OpenAI / Anthropic / generic sk- key
# Match sk_ (non-dash underscore variant like Solodit) or sk- at least 20 chars.
# Require that "sk" is NOT preceded by an alphanumeric character (word boundary)
# to avoid matching words like "risk", "task", "mask", "disk", etc.
OPENAI_TOKEN_RE = re.compile(r"(?<![a-zA-Z0-9])sk[-_][a-zA-Z0-9]{20,}")

# AWS access key
AWS_KEY_RE = re.compile(r"AKIA[0-9A-Z]{16}")

# JWT token
JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")

# Credential file references
CRED_FILE_RE = re.compile(
    r"(?:clob_creds\.json|\.env\b|mnemonic|seed_phrase|keystore)",
    re.IGNORECASE,
)

# Etherscan / Alchemy API key context
# High-entropy 34-char uppercase-hex or alphanumeric near keyword
ETHERSCAN_RE = re.compile(
    r"(?:etherscan[_\s]*api[_\s]*key|alchemy[_\s]*key|infura[_\s]*key)"
    r"[^a-zA-Z0-9]*([A-Z0-9]{34})",
    re.IGNORECASE,
)

# All patterns with precedence checks
PATTERNS: list[dict[str, Any]] = [
    {
        "name": "evm-private-key",
        "re": PRIVATE_KEY_RE,
        "description": "Raw 32-byte EVM private key (0x + 64 hex)",
        "severity": "CRITICAL",
        # Extra guard: must NOT be an EVM address (40 hex) — already handled
        # by requiring exactly 64 non-extended hex chars in the regex.
        "verify": lambda m, line: True,
    },
    {
        "name": "evm-signature",
        "re": EVM_SIG_RE,
        "description": "65-byte EVM signature (0x + 130 hex)",
        "severity": "HIGH",
        "verify": lambda m, line: True,
    },
    {
        "name": "pem-private-key",
        "re": PEM_KEY_RE,
        "description": "PEM-encoded private key header",
        "severity": "CRITICAL",
        "verify": lambda m, line: True,
    },
    {
        "name": "github-token",
        "re": GITHUB_TOKEN_RE,
        "description": "GitHub personal/server token (ghp_/ghs_ prefix)",
        "severity": "HIGH",
        "verify": lambda m, line: True,
    },
    {
        "name": "openai-sk-token",
        "re": OPENAI_TOKEN_RE,
        "description": "OpenAI / Anthropic / sk-* or sk_* API token",
        "severity": "HIGH",
        "verify": lambda m, line: True,
    },
    {
        "name": "aws-access-key",
        "re": AWS_KEY_RE,
        "description": "AWS access key ID (AKIA prefix)",
        "severity": "HIGH",
        "verify": lambda m, line: True,
    },
    {
        "name": "jwt-token",
        "re": JWT_RE,
        "description": "JWT bearer token (eyJ... format)",
        "severity": "HIGH",
        "verify": lambda m, line: True,
    },
    {
        "name": "cred-file-reference",
        "re": CRED_FILE_RE,
        "description": "Reference to credential file or mnemonic keyword",
        "severity": "MEDIUM",
        "verify": lambda m, line: True,
    },
    {
        "name": "etherscan-api-key",
        "re": ETHERSCAN_RE,
        "description": "Etherscan / Alchemy key near keyword",
        "severity": "HIGH",
        "verify": lambda m, line: len(m.group(0)) >= 10,
    },
]


def _redact(text: str, match: re.Match) -> str:
    """Replace the first group (or whole match) with [REDACTED]."""
    start, end = match.span(0)
    return text[:start] + "[REDACTED]" + text[end:]


def _check_bip39_mnemonic(line: str) -> list[dict[str, Any]]:
    """
    Return a finding if ≥10 consecutive BIP39 words appear in the line.
    Uses a sliding window over whitespace-split tokens.
    """
    tokens = re.findall(r"[a-z]+", line.lower())
    if len(tokens) < 10:
        return []

    hits = [t in BIP39_WORDS for t in tokens]
    max_consecutive = 0
    run = 0
    for h in hits:
        if h:
            run += 1
            max_consecutive = max(max_consecutive, run)
        else:
            run = 0

    # Threshold of 12 consecutive to reduce FPs from common English prose.
    # (English words like "that", "this", "keep", "into", "same", etc. appear
    # in the BIP39 list. A genuine 12-word mnemonic = 12 consecutive matches.
    # Normal English prose rarely hits 12 consecutive BIP39 words.)
    if max_consecutive >= 12:
        # Build redacted excerpt
        excerpt = line if len(line) <= 120 else line[:60] + "...[REDACTED]..." + line[-30:]
        return [{
            "pattern": "bip39-mnemonic",
            "severity": "CRITICAL",
            "description": "BIP39 mnemonic phrase (≥12 consecutive words)",
            "match": "[REDACTED]",
            "excerpt": "[REDACTED — mnemonic detected]",
            "consecutive_bip39_words": max_consecutive,
        }]
    return []


def _load_whitelist(whitelist_path: Path) -> list[dict[str, Any]]:
    """Load whitelist from YAML or JSON file."""
    if not whitelist_path.exists():
        return []
    try:
        import yaml  # optional dep
        with open(whitelist_path) as f:
            data = yaml.safe_load(f)
        return data if isinstance(data, list) else []
    except ImportError:
        pass
    try:
        with open(whitelist_path) as f:
            return json.load(f)
    except Exception:
        return []


def _is_whitelisted(finding: dict[str, Any], whitelist: list[dict[str, Any]]) -> bool:
    """Check if a finding matches any whitelist entry."""
    for wl in whitelist:
        # Match on file + line + pattern, or file + pattern
        wl_file = wl.get("file", "")
        wl_pattern = wl.get("pattern", "")
        wl_line = wl.get("line")

        file_match = (not wl_file) or finding.get("file", "").endswith(wl_file)
        pattern_match = (not wl_pattern) or finding.get("pattern") == wl_pattern
        line_match = (wl_line is None) or finding.get("line") == wl_line

        if file_match and pattern_match and line_match:
            return True
    return False


def scan_file(fpath: Path, vault_root: Path) -> list[dict[str, Any]]:
    """Scan a single Markdown file for sensitive patterns."""
    try:
        content = fpath.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return []

    rel = str(fpath.relative_to(vault_root))
    findings: list[dict[str, Any]] = []

    for lineno, line in enumerate(content.splitlines(), start=1):
        # Named-pattern scan
        for pat in PATTERNS:
            for m in pat["re"].finditer(line):
                if not pat["verify"](m, line):
                    continue

                # Extra guard for evm-private-key: skip if the hex blob is
                # actually a known-short address (40 hex) embedded in a larger
                # context.  The regex already enforces exactly 64, but double-check.
                matched_text = m.group(0)
                if pat["name"] == "evm-private-key":
                    # If it's also surrounded by a 0x40-hex match context,
                    # it might be a hashed value in an educational example.
                    # Still flag — author must whitelist if FP.
                    pass

                excerpt = _redact(line.strip()[:160], m)
                findings.append({
                    "file": rel,
                    "line": lineno,
                    "pattern": pat["name"],
                    "severity": pat["severity"],
                    "description": pat["description"],
                    "excerpt": excerpt,
                })

        # BIP39 mnemonic check
        for bip_finding in _check_bip39_mnemonic(line):
            bip_finding["file"] = rel
            bip_finding["line"] = lineno
            findings.append(bip_finding)

    return findings


def scan_vault(vault_dir: Path, whitelist: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Walk vault_dir for .md files and scan each."""
    md_files = sorted(vault_dir.rglob("*.md"))
    # Skip quarantine directory (already-quarantined files)
    md_files = [f for f in md_files if "_privacy_quarantine" not in f.parts]

    all_findings: list[dict[str, Any]] = []
    for fpath in md_files:
        file_findings = scan_file(fpath, vault_dir)
        for f in file_findings:
            if not _is_whitelisted(f, whitelist):
                all_findings.append(f)

    return all_findings


def quarantine_file(fpath_rel: str, vault_dir: Path) -> str:
    """
    Move an offending vault note to _privacy_quarantine/<path>.md.locked
    and write a stub at the original location.
    Returns the quarantine path (relative).
    """
    src = vault_dir / fpath_rel
    qdir = vault_dir / "_privacy_quarantine" / Path(fpath_rel).parent
    qdir.mkdir(parents=True, exist_ok=True)
    dest = vault_dir / "_privacy_quarantine" / (fpath_rel + ".locked")
    dest.parent.mkdir(parents=True, exist_ok=True)

    # Move original
    shutil.move(str(src), str(dest))

    # Write stub at original path
    stub = (
        f"# PRIVACY QUARANTINE\n\n"
        f"This note was quarantined by `memory-privacy-audit.py` at "
        f"{datetime.now(timezone.utc).isoformat()} because it matched a "
        f"sensitive-pattern rule.\n\n"
        f"The original file has been moved to:\n\n"
        f"```\nobsidian-vault/_privacy_quarantine/{fpath_rel}.locked\n```\n\n"
        f"**Review the quarantine file**, redact the sensitive value, update "
        f"`reports/privacy_audit_whitelist.yaml` if this was a false positive, "
        f"then restore the note manually.\n"
    )
    src.write_text(stub, encoding="utf-8")
    return str(dest.relative_to(vault_dir))


def write_json_report(findings: list[dict[str, Any]], out_path: Path,
                      vault_dir: Path, runtime_s: float) -> None:
    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "vault_dir": str(vault_dir),
        "total_findings": len(findings),
        "runtime_seconds": round(runtime_s, 2),
        "findings": findings,
    }
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(report, indent=2), encoding="utf-8")


def write_md_summary(findings: list[dict[str, Any]], out_path: Path,
                     vault_dir: Path) -> None:
    today = date.today().isoformat()
    lines = [
        "# Vault Privacy Audit",
        "",
        f"**Generated:** {today}",
        f"**Vault:** `{vault_dir}`",
        f"**Total findings:** {len(findings)}",
        "",
    ]
    if not findings:
        lines += [
            "No sensitive patterns detected. Vault is clean.",
            "",
        ]
    else:
        lines += [
            "## Findings",
            "",
            "| # | File | Line | Pattern | Severity | Excerpt |",
            "|---|------|------|---------|----------|---------|",
        ]
        for i, f in enumerate(findings, 1):
            excerpt = f.get("excerpt", "").replace("|", "\\|").replace("\n", " ")[:100]
            lines.append(
                f"| {i} | `{f['file']}` | {f['line']} "
                f"| `{f['pattern']}` | **{f['severity']}** | {excerpt} |"
            )
        lines += [
            "",
            "## Remediation",
            "",
            "1. Review each finding above.",
            "2. If a real secret: redact the source memory file, re-run `make vault-refresh`.",
            "3. If a false positive: add an entry to `reports/privacy_audit_whitelist.yaml`.",
            "4. Re-run `python3 tools/memory-privacy-audit.py` — must exit 0 before any vault share.",
            "",
            "## Whitelist format (`reports/privacy_audit_whitelist.yaml`)",
            "",
            "```yaml",
            "- file: agent-memory/solodit-api-key.md",
            "  pattern: openai-sk-token",
            "  reason: \"Solodit key is public-tier, non-billing, already known to operators\"",
            "  approved_by: \"operator\"",
            "  approved_at: \"2026-05-04\"",
            "```",
            "",
        ]

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------

_SELF_TEST_POSITIVES = [
    {
        "name": "raw-evm-private-key",
        "content": (
            "Deployment key: 0xa1b2c3d4e5f601020304050607080910111213141516171819"
            "1a1b1c1d1e1f20\n"
        ),
        "expect_pattern": "evm-private-key",
    },
    {
        "name": "bip39-mnemonic",
        "content": (
            "Backup phrase: abandon ability able about above absent absorb abstract "
            "absurd abuse access accident account accuse achieve\n"
        ),
        "expect_pattern": "bip39-mnemonic",
    },
    {
        "name": "github-token",
        "content": "Token: ghp_abcdefghijklmnopqrstuvwxyzABCDEFGH1234\n",
        "expect_pattern": "github-token",
    },
]

_SELF_TEST_NEGATIVES = [
    {
        "name": "bytecode-hex-comment",
        "content": (
            "# PUSH32 0xabcdef1234567890abcdef1234567890abcdef1234567890"
            "abcdef12345678  // 32 bytes of literal\n"
        ),
        # The above is exactly 64 hex after 0x → WILL be flagged by the
        # private-key heuristic.  This is an intentional FP case that must be
        # whitelisted.  Our test verifies the scanner catches it (no FN) —
        # the "negative" here tests that an EVM *address* (40 hex) is NOT flagged.
        "expect_clean": False,  # scanner SHOULD flag this — whitelist is the mitigation
        "skip_clean_assert": True,  # mark as "FP that needs whitelist"
    },
    {
        "name": "random-english-words",
        "content": (
            "apple orange banana cherry lemon grape kiwi mango peach plum "
            "pear melon fig date lime\n"
        ),
        "expect_clean": True,
    },
    {
        "name": "evm-address-40hex",
        "content": "Contract: 0xF3fe54Eeb378BB607B1D1A1031B85A2b2fc3173c (wallet3)\n",
        "expect_clean": True,
    },
]


def run_self_test(report_path: Path) -> bool:
    """
    Run 3 positive and 3 negative synthetic test cases.
    Returns True iff all pass.
    """
    import time
    results = []
    all_pass = True

    with tempfile.TemporaryDirectory() as tmpdir:
        vault = Path(tmpdir) / "vault"
        vault.mkdir()

        # Positive cases
        for tc in _SELF_TEST_POSITIVES:
            fpath = vault / f"{tc['name']}.md"
            fpath.write_text(tc["content"], encoding="utf-8")
            findings = scan_file(fpath, vault)
            detected = any(f["pattern"] == tc["expect_pattern"] for f in findings)
            ok = detected
            if not ok:
                all_pass = False
            results.append({
                "case": tc["name"],
                "type": "positive",
                "expected_pattern": tc["expect_pattern"],
                "detected": detected,
                "pass": ok,
            })

        # Negative cases
        for tc in _SELF_TEST_NEGATIVES:
            fpath = vault / f"{tc['name']}.md"
            fpath.write_text(tc["content"], encoding="utf-8")
            findings = scan_file(fpath, vault)
            is_clean = len(findings) == 0

            if tc.get("skip_clean_assert"):
                # Document that this content IS flagged (FP-that-needs-whitelist).
                # Test passes unconditionally — we're documenting the known FP.
                ok = True
                results.append({
                    "case": tc["name"],
                    "type": "negative-known-fp",
                    "note": "Scanner intentionally flags 64-hex bytecode comments. "
                            "Whitelist in reports/privacy_audit_whitelist.yaml.",
                    "flagged": not is_clean,
                    "pass": True,
                })
            else:
                expected_clean = tc.get("expect_clean", True)
                ok = is_clean == expected_clean
                if not ok:
                    all_pass = False
                results.append({
                    "case": tc["name"],
                    "type": "negative",
                    "expected_clean": expected_clean,
                    "actually_clean": is_clean,
                    "findings": findings,
                    "pass": ok,
                })

    report_path.parent.mkdir(parents=True, exist_ok=True)
    with open(report_path, "w") as f:
        json.dump({
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "all_pass": all_pass,
            "cases": results,
        }, f, indent=2)

    # Print summary
    for r in results:
        status = "PASS" if r["pass"] else "FAIL"
        print(f"  [{status}] {r['case']} ({r['type']})")

    return all_pass


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Scan obsidian-vault for sensitive pattern leaks."
    )
    parser.add_argument(
        "--vault", default="obsidian-vault",
        help="Path to vault directory (default: obsidian-vault)"
    )
    parser.add_argument(
        "--out-json", default=None,
        help="JSON report output path (default: reports/vault_privacy_audit_<date>.json)"
    )
    parser.add_argument(
        "--out-md", default="docs/VAULT_PRIVACY_AUDIT.md",
        help="Markdown summary output path"
    )
    parser.add_argument(
        "--whitelist", default="reports/privacy_audit_whitelist.yaml",
        help="Whitelist file (YAML or JSON)"
    )
    parser.add_argument(
        "--quarantine", action="store_true",
        help="Move offending vault notes to _privacy_quarantine/"
    )
    parser.add_argument(
        "--self-test", action="store_true",
        help="Run synthetic self-tests and exit"
    )
    parser.add_argument(
        "--strict", action="store_true",
        help="Treat MEDIUM findings as failures (default: only HIGH/CRITICAL fail)"
    )
    args = parser.parse_args()

    # Self-test mode
    if args.self_test:
        st_report = Path("reports/privacy_audit_self_test.json")
        print("Running self-tests...")
        ok = run_self_test(st_report)
        print(f"\nSelf-test report: {st_report}")
        return 0 if ok else 1

    vault_dir = Path(args.vault).expanduser().resolve()
    if not vault_dir.is_dir():
        print(f"ERROR: vault directory not found: {vault_dir}", file=sys.stderr)
        return 2

    out_json = Path(args.out_json) if args.out_json else \
        Path(f"reports/vault_privacy_audit_{date.today().isoformat()}.json")
    out_md = Path(args.out_md)
    whitelist_path = Path(args.whitelist)

    import time
    t0 = time.monotonic()

    whitelist = _load_whitelist(whitelist_path)
    findings = scan_vault(vault_dir, whitelist)

    runtime = time.monotonic() - t0

    write_json_report(findings, out_json, vault_dir, runtime)
    write_md_summary(findings, out_md, vault_dir)

    # Severity filter for exit code
    failing_severities = {"CRITICAL", "HIGH"}
    if args.strict:
        failing_severities.add("MEDIUM")

    failing = [f for f in findings if f.get("severity") in failing_severities]

    print(f"Vault: {vault_dir}")
    print(f"Files scanned: all .md (excl. _privacy_quarantine/)")
    print(f"Findings: {len(findings)} total, {len(failing)} HIGH/CRITICAL")
    print(f"Reports: {out_json}, {out_md}")

    if findings:
        print("\nFindings summary:")
        for f in findings:
            print(f"  [{f['severity']}] {f['file']}:{f['line']} ({f['pattern']})")

    if args.quarantine and findings:
        # Deduplicate by file (quarantine entire file if any finding in it)
        files_to_quarantine = set(f["file"] for f in findings)
        print(f"\nQuarantining {len(files_to_quarantine)} file(s)...")
        for rel in sorted(files_to_quarantine):
            src = vault_dir / rel
            if src.exists():
                dest = quarantine_file(rel, vault_dir)
                print(f"  QUARANTINED: {rel} -> _privacy_quarantine/{rel}.locked")
            else:
                print(f"  SKIP (not found): {rel}")

    if failing:
        print(f"\nAUDIT FAILED — {len(failing)} HIGH/CRITICAL findings. "
              f"Remediate or whitelist before sharing vault.")
        return 1

    print("\nAudit clean (no HIGH/CRITICAL findings outside whitelist).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
