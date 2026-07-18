// positive.rs — should fire: async fn with u32 param, bare for _ in 0..param loop,
// .await + .push( inside loop, no cap guard.
// Mirrors the real zebra generate() shape.

struct RpcServer;
struct Hash;
struct Error;
type Result<T> = std::result::Result<T, Error>;

impl RpcServer {
    async fn generate(&self, num_blocks: u32) -> Result<Vec<Hash>> {
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
