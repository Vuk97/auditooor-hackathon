// FIXTURE (negative) - the PATCHED Aptos shape: both paths converge on the
// aggregate flush_all_caches(), so no cache is omitted. Detector must NOT flag.

impl CodeCacheGlobalManager {
    fn check_ready(&self, runtime_environment: &RuntimeEnvironment, config: &Config) {
        if self.struct_name_index_map_size > config.max_struct_name_index_map_num_entries {
            runtime_environment.flush_all_caches();
            self.module_cache.flush();
        } else if self.num_interned_module_ids > config.max_interned_module_ids {
            // Patched: use the aggregate here too -> no individual enumeration.
            runtime_environment.flush_all_caches();
            self.module_cache.flush();
        }
    }
}

// A totally unrelated fn that flushes a single buffer - not a multi-cache flush,
// must not trip the >=2-member floor.
fn write_page(buf: &Buffer) {
    buf.flush();
}
