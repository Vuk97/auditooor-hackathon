// clean.rs — should NOT fire: same shape but with a cap guard before the loop.

const MAX_GENERATE: u32 = 100;

struct RpcServer;
struct Hash;
struct Error;
type Result<T> = std::result::Result<T, Error>;

impl RpcServer {
    // SAFE: has `if num_blocks > MAX_GENERATE { return Err }` guard
    async fn generate(&self, num_blocks: u32) -> Result<Vec<Hash>> {
        if num_blocks > MAX_GENERATE {
            return Err(Error);
        }
        let mut block_hashes = Vec::new();
        for _ in 0..num_blocks {
            let template = self.get_block_template().await?;
            block_hashes.push(template);
        }
        Ok(block_hashes)
    }

    async fn get_block_template(&self) -> Result<Hash> {
        Ok(Hash)
    }
}
