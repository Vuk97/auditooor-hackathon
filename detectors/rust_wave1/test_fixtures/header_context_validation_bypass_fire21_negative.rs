// NEGATIVE: header validation remains present, but the accepted header is
// explicitly bound to network, height, branch, checkpoint, and trusted root.

#[derive(Clone)]
struct Header {
    previous_block_hash: u64,
    timestamp: u64,
    difficulty: u32,
}

impl Header {
    fn hash(&self) -> u64 {
        self.previous_block_hash ^ self.timestamp
    }
}

struct HeaderStore {
    headers: Vec<Header>,
}

struct HeaderContext;
struct Checkpoint;
struct AcceptedHeader;

impl HeaderContext {
    fn require_network(&self, _network: u32) -> Result<(), ()> {
        Ok(())
    }

    fn require_height(&self, _height: u64) -> Result<(), ()> {
        Ok(())
    }

    fn require_branch_membership(
        &self,
        _parent_hash: u64,
        _height: u64,
    ) -> Result<(), ()> {
        Ok(())
    }
}

impl Checkpoint {
    fn require_trusted_root(&self, _trusted_root: u64) -> Result<(), ()> {
        Ok(())
    }
}

impl AcceptedHeader {
    fn new(_header: Header) -> Self {
        Self
    }
}

fn validate_header_hash(_header_hash: u64) -> Result<(), ()> {
    Ok(())
}

fn validate_work(_difficulty: u32, _header_hash: u64) -> Result<(), ()> {
    Ok(())
}

fn ensure_parent_hash_matches(_parent_hash: u64) -> Result<(), ()> {
    Ok(())
}

fn validate_timestamp(_timestamp: u64) -> Result<(), ()> {
    Ok(())
}

fn accept_header_with_chain_context(
    store: &mut HeaderStore,
    header: Header,
    network: u32,
    height: u64,
    trusted_root: u64,
    context: &HeaderContext,
    checkpoint: &Checkpoint,
) -> Result<AcceptedHeader, ()> {
    let header_hash = header.hash();

    validate_header_hash(header_hash)?;
    validate_work(header.difficulty, header_hash)?;
    ensure_parent_hash_matches(header.previous_block_hash)?;
    validate_timestamp(header.timestamp)?;

    context.require_network(network)?;
    context.require_height(height)?;
    context.require_branch_membership(header.previous_block_hash, height)?;
    checkpoint.require_trusted_root(trusted_root)?;

    store.headers.push(header.clone());
    Ok(AcceptedHeader::new(header))
}
