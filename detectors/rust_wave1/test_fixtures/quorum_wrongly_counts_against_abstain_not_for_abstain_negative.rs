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
        // CORRECT: quorum counts FOR votes + ABSTAIN votes toward participation
        let participation = proposal.for_votes + proposal.abstain_votes;
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
    let proposal = ProposalVotes {
        against_votes: U256::from(100),
        for_votes: U256::from(250),
        abstain_votes: U256::from(50),
    };
    assert!(gov.quorum_reached(&proposal));
    assert_eq!(gov.state(&proposal), ProposalState::Succeeded);
}