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

//! This crate allows automatic caching of `T.len()` with an api that 
//! allows drop in replacement for `parking_lot`
//! [`Mutex`](../lock_api/struct.Mutex.html)
//! and [`RwLock`](../lock_api/struct.RwLock.html) for most common use-cases.
//!
//! This crate implements `Len` for the following types: 
//! `std::collections::{VecDeque, LinkedList, HashMap, BTreeMap, HashSet, BTreeSet, BinaryHeap}`
//!
//! ## Example
//!
//! ```rust
//! use len_caching_lock::LenCachingMutex;
//!
//! let vec: Vec<i32> = Vec::new();
//! let len_caching_mutex = LenCachingMutex::new(vec);
//! assert_eq!(len_caching_mutex.lock().len(), len_caching_mutex.load_len());
//! len_caching_mutex.lock().push(0);
//! assert_eq!(1, len_caching_mutex.load_len());
//! ```

use std::collections::{VecDeque, LinkedList, HashMap, BTreeMap, HashSet, BTreeSet, BinaryHeap};
use std::hash::Hash;

pub mod mutex;
pub mod rwlock;

pub use mutex::LenCachingMutex;
pub use rwlock::LenCachingRwLock;

/// Implement to allow a type with a len() method to be used
/// with [`LenCachingMutex`](mutex/struct.LenCachingMutex.html)
/// or  [`LenCachingRwLock`](rwlock/struct.LenCachingRwLock.html)
pub trait Len {
	fn len(&self) -> usize;
}

impl<T> Len for Vec<T> {
	fn len(&self) -> usize { Vec::len(self) }
}

impl<T> Len for VecDeque<T> {
	fn len(&self) -> usize { VecDeque::len(self) }
}

impl<T> Len for LinkedList<T> {
	fn len(&self) -> usize { LinkedList::len(self) }
}

impl<K: Eq + Hash, V, S: std::hash::BuildHasher> Len for HashMap<K, V, S> {
	fn len(&self) -> usize { HashMap::len(self) }
}

impl<K, V> Len for BTreeMap<K, V> {
	fn len(&self) -> usize { BTreeMap::len(self) }
}

impl<T: Eq + Hash, S: std::hash::BuildHasher> Len for HashSet<T, S> {
	fn len(&self) -> usize { HashSet::len(self) }
}

impl<T> Len for BTreeSet<T> {
	fn len(&self) -> usize { BTreeSet::len(self) }
}

impl<T: Ord> Len for BinaryHeap<T> {
	fn len(&self) -> usize { BinaryHeap::len(self) }
}
