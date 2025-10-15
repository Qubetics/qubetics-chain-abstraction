#[macro_export]
macro_rules! define_storage_adapter {
	($adapter_name:ident, $key_type:ty, $value_type:ty, $prefix:expr) => {
		#[derive(Clone)]
		pub struct $adapter_name;

		impl crate::database::traits::StorageAdapter for $adapter_name {
			type Key = $key_type;
			type Value = $value_type;
			const PREFIX: &'static [u8] = $prefix;
		}
	};
}
