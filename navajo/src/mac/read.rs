cfg_if! {
    if #[cfg(feature="std")] {
        pub struct ComputeRead<R> {
            reader: R,
            hasher: Hasher,
        }

        impl<R> ComputeRead<R>
        where
            R: std::io::Read,
        {
            pub(super) fn new(reader: R, primary_key: Arc<Key>, keys: Vec<Arc<Key>>) -> Self {
                let hasher = Hasher::new(primary_key, keys);
                Self { reader, hasher }
            }
        }

    }
}
