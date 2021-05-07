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

//! Light client logic and implementation.
//!
//! A "light" client stores very little chain-related data locally
//! unlike a full node, which stores all blocks, headers, receipts, and more.
//!
//! This enables the client to have a much lower resource footprint in
//! exchange for the cost of having to ask the network for state data
//! while responding to queries. This makes a light client unsuitable for
//! low-latency applications, but perfectly suitable for simple everyday
//! use-cases like sending transactions from a personal account.
//!
//! The light client performs a header-only sync, doing verification and pruning
//! historical blocks. Upon pruning, batches of 2048 blocks have a number => (hash, TD)
//! mapping sealed into "canonical hash tries" which can later be used to verify
//! historical block queries from peers.

#![deny(missing_docs)]

pub mod client;
pub mod cht;
pub mod net;
pub mod on_demand;
pub mod transaction_queue;
pub mod cache;
pub mod provider;

mod types;

pub use self::cache::Cache;
pub use self::provider::{Provider, MAX_HEADERS_PER_REQUEST};
pub use self::transaction_queue::TransactionQueue;
pub use types::request as request;

#[macro_use]
extern crate serde_derive;

#[macro_use]
extern crate log;

extern crate bincode;
extern crate client_traits;
extern crate common_types;
extern crate engine;
extern crate ethcore_blockchain;
extern crate ethcore_db;
extern crate ethcore_io as io;
extern crate ethcore_network as network;
extern crate executive_state;
extern crate parity_bytes as bytes;
extern crate ethereum_types;
extern crate ethcore_miner as miner;
extern crate hash_db;
extern crate parity_util_mem;
extern crate parity_util_mem as malloc_size_of;
extern crate failsafe;
extern crate futures;
extern crate keccak_hasher;
extern crate machine;
extern crate memory_db;
extern crate trie_db as trie;
extern crate patricia_trie_ethereum as ethtrie;
extern crate fastmap;
extern crate rand;
extern crate rlp;
extern crate parking_lot;
#[macro_use]
extern crate rlp_derive;
extern crate serde;
extern crate spec;
extern crate smallvec;
extern crate stats;
extern crate vm;
extern crate keccak_hash as hash;
extern crate triehash_ethereum as triehash;
extern crate kvdb;
extern crate memory_cache;
extern crate derive_more;
extern crate verification;

#[cfg(test)]
extern crate ethcore;
#[cfg(test)]
extern crate kvdb_memorydb;
#[cfg(test)]
extern crate tempfile;
extern crate journaldb;
