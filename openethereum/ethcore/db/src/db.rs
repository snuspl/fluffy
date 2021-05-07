// Copyright 2015-2020 Parity Technologies (UK) Ltd.
// This file is part of Open Ethereum.

// Open Ethereum is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Open Ethereum is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Open Ethereum.  If not, see <http://www.gnu.org/licenses/>.

//! Database utilities and definitions.

use std::convert::AsRef;
use std::hash::Hash;
use std::collections::HashMap;
use parking_lot::RwLock;
use kvdb::{DBTransaction, KeyValueDB};

use rlp;

// Database column indexes.
/// Column for State
pub const COL_STATE: u32 = 0;
/// Column for Block headers
pub const COL_HEADERS: u32 = 1;
/// Column for Block bodies
pub const COL_BODIES: u32 = 2;
/// Column for Extras
pub const COL_EXTRA: u32 = 3;
/// Column for Traces
pub const COL_TRACE: u32 = 4;
/// Column for the accounts existence bloom filter.
#[deprecated(since = "3.0.0", note = "Accounts bloom column is deprecated")]
pub const COL_ACCOUNT_BLOOM: u32 = 5;
/// Column for general information from the local node which can persist.
pub const COL_NODE_INFO: u32 = 6;
/// Column for the light client chain.
pub const COL_LIGHT_CHAIN: u32 = 7;
/// Column for the private transactions state.
pub const COL_PRIVATE_TRANSACTIONS_STATE: u32 = 8;
/// Number of columns in DB
pub const NUM_COLUMNS: u32 = 9;

/// Modes for updating caches.
#[derive(Clone, Copy)]
pub enum CacheUpdatePolicy {
	/// Overwrite entries.
	Overwrite,
	/// Remove entries.
	Remove,
}

/// A cache for arbitrary key-value pairs.
pub trait Cache<K, V> {
	/// Insert an entry into the cache and get the old value.
	fn insert(&mut self, k: K, v: V) -> Option<V>;

	/// Remove an entry from the cache, getting the old value if it existed.
	fn remove(&mut self, k: &K) -> Option<V>;

	/// Query the cache for a key's associated value.
	fn get(&self, k: &K) -> Option<&V>;
}

impl<K, V> Cache<K, V> for HashMap<K, V> where K: Hash + Eq {
	fn insert(&mut self, k: K, v: V) -> Option<V> {
		HashMap::insert(self, k, v)
	}

	fn remove(&mut self, k: &K) -> Option<V> {
		HashMap::remove(self, k)
	}

	fn get(&self, k: &K) -> Option<&V> {
		HashMap::get(self, k)
	}
}

/// Should be used to get database key associated with given value.
pub trait Key<T> {
	/// The db key associated with this value.
	type Target: AsRef<[u8]>;

	/// Returns db key.
	fn key(&self) -> Self::Target;
}

/// Should be used to write value into database.
pub trait Writable {
	/// Writes the value into the database.
	fn write<T, R>(&mut self, col: u32, key: &dyn Key<T, Target = R>, value: &T) where T: rlp::Encodable, R: AsRef<[u8]>;

	/// Deletes key from the database.
	fn delete<T, R>(&mut self, col: u32, key: &dyn Key<T, Target = R>) where T: rlp::Encodable, R: AsRef<[u8]>;

	/// Writes the value into the database and updates the cache.
	fn write_with_cache<K, T, R>(
		&mut self,
		col: u32,
		cache: &mut dyn Cache<K, T>,
		key: K,
		value: T,
		policy: CacheUpdatePolicy
	)
		where
			K: Key<T, Target = R> + Hash + Eq,
			T: rlp::Encodable,
			R: AsRef<[u8]>
	{
		self.write(col, &key, &value);
		match policy {
			CacheUpdatePolicy::Overwrite => {
				cache.insert(key, value);
			},
			CacheUpdatePolicy::Remove => {
				cache.remove(&key);
			}
		}
	}

	/// Writes the values into the database and updates the cache.
	fn extend_with_cache<K, T, R>(
		&mut self,
		col: u32,
		cache: &mut dyn Cache<K, T>,
		values: HashMap<K, T>,
		policy: CacheUpdatePolicy
	)
		where
			K: Key<T, Target = R> + Hash + Eq,
			T: rlp::Encodable,
			R: AsRef<[u8]>
	{
		match policy {
			CacheUpdatePolicy::Overwrite => {
				for (key, value) in values {
					self.write(col, &key, &value);
					cache.insert(key, value);
				}
			},
			CacheUpdatePolicy::Remove => {
				for (key, value) in &values {
					self.write(col, key, value);
					cache.remove(key);
				}
			},
		}
	}

	/// Writes and removes the values into the database and updates the cache.
	fn extend_with_option_cache<K, T, R>(
		&mut self,
		col: u32,
		cache: &mut dyn Cache<K, Option<T>>,
		values: HashMap<K, Option<T>>,
		policy: CacheUpdatePolicy
	)
		where
			K: Key<T, Target = R> + Hash + Eq,
			T: rlp::Encodable,
			R: AsRef<[u8]>
	{
		match policy {
			CacheUpdatePolicy::Overwrite => {
				for (key, value) in values {
					match value {
						Some(ref v) => self.write(col, &key, v),
						None => self.delete(col, &key),
					}
					cache.insert(key, value);
				}
			},
			CacheUpdatePolicy::Remove => {
				for (key, value) in values {
					match value {
						Some(v) => self.write(col, &key, &v),
						None => self.delete(col, &key),
					}
					cache.remove(&key);
				}
			},
		}
	}

}

/// Should be used to read values from database.
pub trait Readable {
	/// Returns value for given key.
	fn read<T, R>(&self, col: u32, key: &dyn Key<T, Target = R>) -> Option<T> where
	T: rlp::Decodable,
	R: AsRef<[u8]>;

	/// Returns value for given key either in cache or in database.
	fn read_with_cache<K, T, C>(&self, col: u32, cache: &RwLock<C>, key: &K) -> Option<T> where
		K: Key<T> + Eq + Hash + Clone,
		T: Clone + rlp::Decodable,
		C: Cache<K, T> {
		{
			let read = cache.read();
			if let Some(v) = read.get(key) {
				return Some(v.clone());
			}
		}

		self.read(col, key).map(|value: T|{
			let mut write = cache.write();
			write.insert(key.clone(), value.clone());
			value
		})
	}

	/// Returns value for given key either in two-layered cache or in database.
	fn read_with_two_layer_cache<K, T, C>(
		&self,
		col: u32,
		l1_cache: &RwLock<C>,
		l2_cache: &RwLock<C>,
		key: &K
	) -> Option<T>
		where
			K: Key<T> + Eq + Hash + Clone,
			T: Clone + rlp::Decodable,
			C: Cache<K, T>
	{
		{
			let read = l1_cache.read();
			if let Some(v) = read.get(key) {
				return Some(v.clone());
			}
		}

		self.read_with_cache(col, l2_cache, key)
	}

	/// Returns true if given value exists.
	fn exists<T, R>(&self, col: u32, key: &dyn Key<T, Target = R>) -> bool where R: AsRef<[u8]>;

	/// Returns true if given value exists either in cache or in database.
	fn exists_with_cache<K, T, R, C>(&self, col: u32, cache: &RwLock<C>, key: &K) -> bool where
	K: Eq + Hash + Key<T, Target = R>,
	R: AsRef<[u8]>,
	C: Cache<K, T> {
		{
			let read = cache.read();
			if read.get(key).is_some() {
				return true;
			}
		}

		self.exists::<T, R>(col, key)
	}
}

impl Writable for DBTransaction {
	fn write<T, R>(&mut self, col: u32, key: &dyn Key<T, Target = R>, value: &T) where T: rlp::Encodable, R: AsRef<[u8]> {
		self.put(col, key.key().as_ref(), &rlp::encode(value));
	}

	fn delete<T, R>(&mut self, col: u32, key: &dyn Key<T, Target = R>) where T: rlp::Encodable, R: AsRef<[u8]> {
		self.delete(col, key.key().as_ref());
	}
}

impl<KVDB: KeyValueDB + ?Sized> Readable for KVDB {
	fn read<T, R>(&self, col: u32, key: &dyn Key<T, Target = R>) -> Option<T>
		where T: rlp::Decodable, R: AsRef<[u8]> {
		self.get(col, key.key().as_ref())
			.expect(&format!("db get failed, key: {:?}", key.key().as_ref()))
			.map(|v| rlp::decode(&v).expect("decode db value failed") )

	}

	fn exists<T, R>(&self, col: u32, key: &dyn Key<T, Target = R>) -> bool where R: AsRef<[u8]> {
		let result = self.get(col, key.key().as_ref());

		match result {
			Ok(v) => v.is_some(),
			Err(err) => {
				panic!("db get failed, key: {:?}, err: {:?}", key.key().as_ref(), err);
			}
		}
	}
}
