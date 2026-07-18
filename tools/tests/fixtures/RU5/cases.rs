// RU5 fixtures. One file, several enums/structs exercising each predicate arm.

// --- resolvable structs for field_overlap ---
#[derive(Deserialize)]
pub struct OnlyOptional {
    #[serde(default)]
    pub a: Option<u64>,
    #[serde(default)]
    pub b: Option<String>,
}

#[derive(Deserialize)]
pub struct Superset {
    pub a: u64,
    pub c: String,
    pub d: bool,
}

#[derive(Deserialize)]
pub struct Left {
    pub x: u64,
}

#[derive(Deserialize)]
pub struct Right {
    pub y: String,
    pub z: bool,
}

// (1) net-new serde: 2 struct variants, earlier all-optional -> field_overlap true.
#[serde(untagged)]
#[derive(Deserialize)]
pub enum PayloadOverlap {
    Loose(OnlyOptional),
    Strict(Superset),
}

// (2) net-new serde: disjoint required fields -> fires, field_overlap false.
#[serde(untagged)]
#[derive(Deserialize)]
pub enum PayloadDisjoint {
    A(Left),
    B(Right),
}

// (3) base-narrow: Yolo variant on a Swap-named enum -> covered_by base, deduped out.
#[serde(untagged)]
#[derive(Deserialize)]
pub enum SwapRequest {
    Yolo { to: Option<String> },
    Min(Superset),
}

// (4) benign: a TAGGED json enum (no untagged) -> must NOT fire.
#[derive(Deserialize)]
pub enum TaggedFine {
    A(Left),
    B(Right),
}

// (5) FP-guard: untagged but deny_unknown_fields -> shadow risk removed, no fire.
#[serde(untagged, deny_unknown_fields)]
#[derive(Deserialize)]
pub enum GuardedUntagged {
    A(Left),
    B(Right),
}

// (6) borsh persisted/versioned enum -> reorder-discriminant axis fires.
#[near(serializers = [borsh])]
pub enum VersionedThing {
    V0(Left),
    Latest(Right),
}

// (7) FP-guard: borsh enum in a non-persisted message context -> no borsh fire.
#[near(serializers = [borsh])]
pub enum WireMessage {
    Ping(Left),
    Pong(Right),
}
