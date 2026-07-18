// Pattern 1 — POSITIVE fixture for
//   rust.frost.dkg.self_identifier_in_round_packages
//
// part2 builds a round-2 package map keyed by Identifier but iterates
// over ALL participants without skipping `self.identifier`. The self
// entry then leaks into the broadcast set, exposing the originator's
// own private share material to themselves on the next round and
// allowing protocol-step skipping in the broader DKG flow.
//
// Mirrors the bug class fixed by `ff5ec8d` in lightsparkdev/frost.

use std::collections::BTreeMap;

pub struct Identifier(u16);

pub mod dkg {
    pub mod round1 {
        pub struct Package {
            pub commitment: Vec<u8>,
        }
    }
    pub mod round2 {
        pub struct Package {
            pub share: Vec<u8>,
        }
    }
}

pub struct SecretPackage {
    pub identifier: Identifier,
    pub coefficients: Vec<u8>,
}

impl SecretPackage {
    // BUG: builds the round-2 package map without skipping self.identifier.
    pub fn part2(
        &self,
        round1_packages: &BTreeMap<Identifier, dkg::round1::Package>,
    ) -> BTreeMap<Identifier, dkg::round2::Package> {
        let mut round2_packages: BTreeMap<Identifier, dkg::round2::Package> = BTreeMap::new();
        for (identifier, _r1) in round1_packages.iter() {
            // No `if identifier == self.identifier { continue; }` here —
            // self entry pollutes the broadcast.
            let pkg = dkg::round2::Package {
                share: self.coefficients.clone(),
            };
            round2_packages.insert(identifier, pkg);
        }
        round2_packages
    }
}
