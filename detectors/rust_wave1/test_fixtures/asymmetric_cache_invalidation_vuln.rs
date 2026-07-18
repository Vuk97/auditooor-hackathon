// FIXTURE (positive) - reproduces the Feb-2026 Aptos Move-VM struct-hijack shape.
// Path A invalidates the full cache set via the aggregate flush_all_caches();
// Path B enumerates individual flushes but OMITS ty_tag_cache -> partial flush.
// Detector must flag the Path-B arm (signal B: aggregate coexists in file).

impl CodeCacheGlobalManager {
    fn check_ready(&self, runtime_environment: &RuntimeEnvironment, config: &Config) {
        if self.struct_name_index_map_size > config.max_struct_name_index_map_num_entries {
            // Path A (correct): aggregate flush covers ty_tag_cache too.
            runtime_environment.flush_all_caches();
            self.module_cache.flush();
        } else if self.num_interned_module_ids > config.max_interned_module_ids {
            // Path B (VULNERABLE): enumerated flush, ty_tag_cache OMITTED.
            runtime_environment.module_id_pool().flush();
            runtime_environment.struct_name_index_map().flush();
            self.module_cache.flush();
        }
    }
}
