pub struct OpEngineValidator;

impl OpEngineValidator {
    pub fn validate_block_post_execution_with_hashed_state(
        &self,
        state_updates: &HashedPostState,
        block: &RecoveredBlock,
    ) -> Result<(), ConsensusError> {
        if self.chain_spec().is_isthmus_active_at_timestamp(block.timestamp()) {
            let Ok(state) = self.provider.state_by_block_hash(block.parent_hash()) else {
                // Parent is not canonical yet, but this silently skips the
                // Base-specific L2ToL1MessagePasser storage-root check.
                return Ok(());
            };
            let predeploy_storage_updates = state_updates
                .storages
                .get(&self.hashed_addr_l2tol1_msg_passer)
                .cloned()
                .unwrap_or_default();
            isthmus::verify_withdrawals_root_prehashed(
                predeploy_storage_updates,
                state,
                block.header(),
            )?;
        }

        Ok(())
    }
}
