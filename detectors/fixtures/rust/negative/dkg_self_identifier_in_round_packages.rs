// Pattern 1 — NEGATIVE fixture for
//   rust.frost.dkg.self_identifier_in_round_packages
//
// part2 builds the round-2 package map but DOES skip self.identifier
// via an explicit `!=` guard + `continue;`. Detector should NOT fire.

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
    pub fn part2(
        &self,
        round1_packages: &BTreeMap<Identifier, dkg::round1::Package>,
    ) -> BTreeMap<Identifier, dkg::round2::Package> {
        let mut round2_packages: BTreeMap<Identifier, dkg::round2::Package> = BTreeMap::new();
        for (identifier, _r1) in round1_packages.iter() {
            // FIXED: self.identifier explicitly excluded.
            if identifier == self.identifier {
                continue;
            }
            let pkg = dkg::round2::Package {
                share: self.coefficients.clone(),
            };
            round2_packages.insert(identifier, pkg);
        }
        round2_packages
    }
}
