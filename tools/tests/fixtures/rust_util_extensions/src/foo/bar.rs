// Fixture for fn_module_path "foo::bar" edge-case (src/foo/bar.rs -> foo::bar)
pub fn deep_fn(val: i64) -> i64 {
    val * 2
}

pub async fn async_deep_fn<T: Clone>(item: T) -> T
where
    T: Send + Sync,
{
    item.clone()
}
