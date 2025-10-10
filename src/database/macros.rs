/// Macro for generating database storage structs with common CRUD operations.
/// 
/// This macro creates a storage struct that implements the `DBKey` trait for the key type
/// and provides standard database operations like put, get, delete, and get_all.
/// 
/// # Parameters
/// - `$struct_meta`: Optional metadata attributes for the struct
/// - `$struct_name`: Name of the generated storage struct
/// - `$key_type`: Type implementing `DBKey` trait for database keys
/// - `$value_type`: Type of values stored (must implement `Serialize` and `Deserialize`)
/// - `$prefix`: Byte prefix for database keys
/// 
/// # Generated Methods
/// - `new(db: Database) -> Self`: Creates a new storage instance
/// - `put(key, value)`: Stores a key-value pair
/// - `get(key)`: Retrieves a value by key
/// - `delete(key)`: Removes a key-value pair
/// - `get_by_key(key_bytes)`: Retrieves by raw key bytes
/// - `get_all_by_key()`: Gets all key-value pairs as HashMap<Vec<u8>, Value>
/// - `get_all()`: Gets all key-value pairs as HashMap<Vec<u8>, Value>
/// 
/// # Example
/// ```rust
/// define_storage!(
///     #[derive(Debug)]
///     UserStorage,
///     UserKey,
///     User,
///     b"user:"
/// );
/// ```
#[macro_export]
macro_rules! define_storage {

    (
        $(#[$struct_meta:meta])*
        $struct_name:ident,
        $key_type:ty,
        $value_type:ty,
        $prefix:expr
    ) => {
        impl crate::database::traits::DBKey for $key_type {
            fn prefix(&self) -> &'static [u8] {
                $prefix
            }
            fn key_bytes(&self) -> Vec<u8> {
                format!("{:?}", self).into_bytes()
            }
            fn as_db_key(&self) -> Vec<u8> {
                [self.prefix(), &self.key_bytes()].concat()
            }
        }




        $(#[$struct_meta])*
        #[derive(Clone)]
        pub struct $struct_name {
            db: Database,
        }

        impl $struct_name {
            /// Creates a new storage instance with the given database.
            /// 
            /// # Arguments
            /// * `db` - The database instance to use for storage operations
            /// 
            /// # Returns
            /// A new storage instance
            pub fn new(db: Database) -> Self {
                Self { db }
            }

            /// Stores a key-value pair in the database.
            /// 
            /// # Arguments
            /// * `key` - The key to store the value under
            /// * `value` - The value to store
            /// 
            /// # Returns
            /// * `Ok(())` if the operation succeeds
            /// * `Err` if serialization or database operation fails
            pub fn put(&self, key: $key_type, value: &$value_type) -> anyhow::Result<()> {
                let key_bytes = crate::database::traits::DBKey::as_db_key(&key);
                let value_bytes = bincode::serialize(value)?;
                self.db.db().put(key_bytes, value_bytes)?;
                Ok(())
            }

            /// Retrieves a value by key from the database.
            /// 
            /// # Arguments
            /// * `key` - The key to look up
            /// 
            /// # Returns
            /// * `Ok(Some(value))` if the key exists
            /// * `Ok(None)` if the key doesn't exist
            /// * `Err` if deserialization or database operation fails
            pub fn get(&self, key: $key_type) -> anyhow::Result<Option<$value_type>> {
                let key_bytes = crate::database::traits::DBKey::as_db_key(&key);
                match self.db.db().get(key_bytes)? {
                    Some(bytes) => Ok(Some(bincode::deserialize(&bytes)?)),
                    None => Ok(None),
                }
            }

            /// Removes a key-value pair from the database.
            /// 
            /// # Arguments
            /// * `key` - The key to remove
            /// 
            /// # Returns
            /// * `Ok(())` if the operation succeeds
            /// * `Err` if the database operation fails
            pub fn delete(&self, key: $key_type) -> anyhow::Result<()> {
                let key_bytes = crate::database::traits::DBKey::as_db_key(&key);
                self.db.db().delete(key_bytes)?;
                Ok(())
            }

            /// Retrieves a value by raw key bytes.
            /// 
            /// This method is useful when you have raw key bytes (e.g., from prefix iteration)
            /// and want to retrieve the corresponding value without constructing a typed key.
            /// 
            /// # Arguments
            /// * `key_bytes` - Raw key bytes to look up
            /// 
            /// # Returns
            /// * `Ok(Some(value))` if the key exists
            /// * `Ok(None)` if the key doesn't exist
            /// * `Err` if deserialization or database operation fails
            pub fn get_by_key(&self, key_bytes: &[u8]) -> anyhow::Result<Option<$value_type>> {
                match self.db.db().get(key_bytes)? {
                    Some(bytes) => Ok(Some(bincode::deserialize(&bytes)?)),
                    None => Ok(None),
                }
            }

            /// Retrieves all key-value pairs with the storage prefix.
            /// 
            /// This method performs a prefix scan to get all entries that match
            /// the storage prefix and returns them as a HashMap.
            /// 
            /// # Returns
            /// * `Ok(HashMap<Vec<u8>, ValueType>)` containing all key-value pairs
            /// * `Err` if database operation or deserialization fails
            pub fn get_all_by_key(&self) -> anyhow::Result<std::collections::HashMap<Vec<u8>, $value_type>> {
                let mut map = std::collections::HashMap::new();
                let iter = self.db.db().prefix_iterator($prefix);
                for item in iter {
                    let (key, value) = item?;
                    if let Ok(deserialized_value) = bincode::deserialize(&value) {
                        map.insert(key.to_vec(), deserialized_value);
                    }
                }
                Ok(map)
            }

            /// Retrieves all key-value pairs with the storage prefix.
            /// 
            /// This is an alias for `get_all_by_key()` for backward compatibility.
            /// 
            /// # Returns
            /// * `Ok(HashMap<Vec<u8>, ValueType>)` containing all key-value pairs
            /// * `Err` if database operation or deserialization fails
            pub fn get_all(&self) -> anyhow::Result<std::collections::HashMap<Vec<u8>, $value_type>> {
                let mut map = std::collections::HashMap::new();
                let iter = self.db.db().prefix_iterator($prefix);
                for item in iter {
                    let (key, value) = item?;
                    if let Ok(deserialized_value) = bincode::deserialize(&value) {
                        map.insert(key.to_vec(), deserialized_value);
                    }
                }
                Ok(map)
            }
        }
    };
}
