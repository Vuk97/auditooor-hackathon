use alloy_primitives::U256;

struct ProposalVotes {
    against_votes: U256,
    for_votes: U256,
    abstain_votes: U256,
}

struct Governance {
    quorum_numerator: U256,
    quorum_denominator: U256,
    total_supply: U256,
}

impl Governance {
    fn quorum(&self) -> U256 {
        (self.total_supply * self.quorum_numerator) / self.quorum_denominator
    }

    fn quorum_reached(&self, proposal: &ProposalVotes) -> bool {
        // BUG: quorum counts AGAINST votes + ABSTAIN votes instead of FOR + ABSTAIN
        // This inverts quorum logic: more opposition makes quorum EASIER to reach
        let participation = proposal.against_votes + proposal.abstain_votes;
        participation >= self.quorum()
    }

    fn state(&self, proposal: &ProposalVotes) -> ProposalState {
        if self.quorum_reached(proposal) {
            if proposal.for_votes > proposal.against_votes {
                ProposalState::Succeeded
            } else {
                ProposalState::Defeated
            }
        } else {
            ProposalState::Active
        }
    }
}

#[derive(Debug, PartialEq)]
enum ProposalState {
    Active,
    Succeeded,
    Defeated,
}

fn main() {
    let gov = Governance {
        quorum_numerator: U256::from(3),
        quorum_denominator: U256::from(10),
        total_supply: U256::from(1000),
    };
    // With 400 against + 100 abstain = 500, bug makes quorum easy to reach
    // even with zero for votes
    let malicious_proposal = ProposalVotes {
        against_votes: U256::from(400),
        for_votes: U256::from(0),
        abstain_votes: U256::from(100),
    };
    assert!(gov.quorum_reached(&malicious_proposal)); // BUG: reaches quorum via opposition!
}