// POSITIVE: local header checks cover hash, work, parent, and timestamp,
// then the header is accepted without network, height, branch, checkpoint,
// or trusted-root binding.

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

struct AcceptedHeader;

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

fn accept_header_without_chain_context(
    store: &mut HeaderStore,
    header: Header,
) -> Result<AcceptedHeader, ()> {
    let header_hash = header.hash();

    validate_header_hash(header_hash)?;
    validate_work(header.difficulty, header_hash)?;
    ensure_parent_hash_matches(header.previous_block_hash)?;
    validate_timestamp(header.timestamp)?;

    store.headers.push(header.clone());
    Ok(AcceptedHeader::new(header))
}
