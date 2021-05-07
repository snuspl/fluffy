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

//! Test implementation of SyncProvider.

use std::collections::BTreeMap;
use ethereum_types::{H256, H512};
use parking_lot::RwLock;
use network::client_version::ClientVersion;
use futures::sync::mpsc;
use sync::{SyncProvider, EthProtocolInfo, SyncStatus, PeerInfo, TransactionStats, SyncState};

/// TestSyncProvider config.
pub struct Config {
	/// Protocol version.
	pub network_id: u64,
	/// Number of peers.
	pub num_peers: usize,
}

/// Test sync provider.
pub struct TestSyncProvider {
	/// Sync status.
	pub status: RwLock<SyncStatus>,
	/// is major importing?
	is_importing: RwLock<bool>,
}

impl TestSyncProvider {
	/// Creates new sync provider.
	pub fn new(config: Config) -> Self {
		TestSyncProvider {
			status: RwLock::new(SyncStatus {
				state: SyncState::Idle,
				network_id: config.network_id,
				protocol_version: 64,
				start_block_number: 0,
				last_imported_block_number: None,
				highest_block_number: None,
				blocks_total: 0,
				blocks_received: 0,
				num_peers: config.num_peers,
				num_active_peers: 0,
				mem_used: 0,
				num_snapshot_chunks: 0,
				snapshot_chunks_done: 0,
				last_imported_old_block_number: None,
			}),
			is_importing: RwLock::new(false)
		}
	}

	/// Simulate importing blocks.
	pub fn increase_imported_block_number(&self, count: u64) {
		let mut status =  self.status.write();
		*self.is_importing.write() = true;
		let current_number = status.last_imported_block_number.unwrap_or(0);
		status.last_imported_block_number = Some(current_number + count);
	}
}

impl SyncProvider for TestSyncProvider {
	fn status(&self) -> SyncStatus {
		self.status.read().clone()
	}

	fn peers(&self) -> Vec<PeerInfo> {
		vec![
			PeerInfo {
				id: Some("node1".to_owned()),
				client_version: ClientVersion::from("Parity-Ethereum/1/v2.4.0/linux/rustc"),
				capabilities: vec!["eth/63".to_owned(), "eth/64".to_owned()],
				remote_address: "127.0.0.1:7777".to_owned(),
				local_address: "127.0.0.1:8888".to_owned(),
				eth_info: Some(EthProtocolInfo {
					version: 63,
					difficulty: Some(40.into()),
					head: H256::from_low_u64_be(50),
				}),
				pip_info: None,
			},
			PeerInfo {
				id: None,
				client_version: ClientVersion::from("OpenEthereum/2/v2.7.0/linux/rustc"),
				capabilities: vec!["eth/64".to_owned(), "eth/65".to_owned()],
				remote_address: "Handshake".to_owned(),
				local_address: "127.0.0.1:3333".to_owned(),
				eth_info: Some(EthProtocolInfo {
					version: 65,
					difficulty: None,
					head: H256::from_low_u64_be(60),
				}),
				pip_info: None,
			}
		]
	}

	fn enode(&self) -> Option<String> {
		None
	}

	fn transactions_stats(&self) -> BTreeMap<H256, TransactionStats> {
		btreemap![
			H256::from_low_u64_be(1) => TransactionStats {
				first_seen: 10,
				propagated_to: btreemap![
					H512::from_low_u64_be(128) => 16
				],
			},
			H256::from_low_u64_be(5) => TransactionStats {
				first_seen: 16,
				propagated_to: btreemap![
					H512::from_low_u64_be(16) => 1
				],
			}
		]
	}

	fn sync_notification(&self) -> mpsc::UnboundedReceiver<SyncState> {
		unimplemented!()
	}

	fn is_major_syncing(&self) -> bool {
		match (self.status.read().state, *self.is_importing.read()) {
			(SyncState::Idle, _) => false,
			(SyncState::Blocks, _) => true,
			(_, true) => true,
			_ => false
		}
	}
}
