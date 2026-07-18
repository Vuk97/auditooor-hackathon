// POSITIVE: checkpoint-style acceptance path uses only local header checks,
// then materializes a verified block without any recent-chain binders.

struct Header;
struct Block;
struct Hash;
struct Height;
struct Network;
struct CheckpointVerifiedBlock;

fn difficulty_is_valid(
    _header: &Header,
    _network: &Network,
    _height: &Height,
    _hash: &Hash,
) -> Result<(), ()> {
    Ok(())
}

fn merkle_root_validity(_network: &Network, _block: &Block) -> Result<(), ()> {
    Ok(())
}

impl CheckpointVerifiedBlock {
    fn new(_block: Block, _hash: Hash) -> Self {
        Self
    }
}

fn check_block_checkpoint(
    block: Block,
    header: &Header,
    network: &Network,
    height: &Height,
    hash: &Hash,
) -> Result<CheckpointVerifiedBlock, ()> {
    difficulty_is_valid(header, network, height, hash)?;
    merkle_root_validity(network, &block)?;

    let verified = CheckpointVerifiedBlock::new(block, Hash);
    Ok(verified)
}
