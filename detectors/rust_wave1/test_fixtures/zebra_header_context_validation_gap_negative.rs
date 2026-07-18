// NEGATIVE: acceptance path binds header checks to recent-chain context
// before producing a verified block.

struct Header {
    previous_block_hash: u64,
}

struct Block {
    header: Header,
}

struct Hash;
struct Height;
struct Network;
struct AdjustedDifficulty;
struct ContextuallyVerifiedBlock;

fn difficulty_is_valid(
    _header: &Header,
    _network: &Network,
    _height: &Height,
    _hash: &Hash,
) -> Result<(), ()> {
    Ok(())
}

fn median_time_past(_chain: &[Block]) -> u64 {
    100
}

impl AdjustedDifficulty {
    fn new_from_header_time(
        _candidate_time: u64,
        _previous_height: &Height,
        _network: &Network,
        _context: &[Block],
    ) -> Self {
        Self
    }

    fn expected_difficulty_threshold(&self) -> u32 {
        42
    }
}

impl ContextuallyVerifiedBlock {
    fn new(_block: Block) -> Self {
        Self
    }
}

fn commit_contextually_verified_block(
    block: Block,
    network: &Network,
    height: &Height,
    hash: &Hash,
    relevant_chain: &[Block],
) -> Result<ContextuallyVerifiedBlock, ()> {
    difficulty_is_valid(&block.header, network, height, hash)?;

    let _parent = block.header.previous_block_hash;
    let _median = median_time_past(relevant_chain);
    let adjustment =
        AdjustedDifficulty::new_from_header_time(123, height, network, relevant_chain);
    let _expected = adjustment.expected_difficulty_threshold();

    Ok(ContextuallyVerifiedBlock::new(block))
}
