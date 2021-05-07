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

//! Creates and registers client and network services.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use ansi_term::Colour;
use ethereum_types::H256;
use io::{IoContext, TimerToken, IoHandler, IoService, IoError};
use client_traits::ChainNotify;
use sync::PrivateTxHandler;
use blockchain::{BlockChainDB, BlockChainDBHandler};
use ethcore::client::{Client, ClientConfig};
use ethcore::miner::Miner;
use snapshot::service::{Service as SnapshotService, ServiceParams as SnapServiceParams};
use snapshot::{SnapshotService as _SnapshotService, SnapshotClient};
use spec::Spec;
use common_types::{
	io_message::ClientIoMessage,
	errors::{EthcoreError, SnapshotError},
	snapshot::RestorationStatus,
};
use client_traits::{ImportBlock, Tick};


use ethcore_private_tx::{self, Importer, Signer};

pub struct PrivateTxService {
	provider: Arc<ethcore_private_tx::Provider>,
}

impl PrivateTxService {
	fn new(provider: Arc<ethcore_private_tx::Provider>) -> Self {
		PrivateTxService {
			provider,
		}
	}

	/// Returns underlying provider.
	pub fn provider(&self) -> Arc<ethcore_private_tx::Provider> {
		self.provider.clone()
	}
}

impl PrivateTxHandler for PrivateTxService {
	fn import_private_transaction(&self, rlp: &[u8]) -> Result<H256, String> {
		match self.provider.import_private_transaction(rlp) {
			Ok(import_result) => Ok(import_result),
			Err(err) => {
				warn!(target: "privatetx", "Unable to import private transaction packet: {}", err);
				return Err(err.to_string())
			}
		}
	}

	fn import_signed_private_transaction(&self, rlp: &[u8]) -> Result<H256, String> {
		match self.provider.import_signed_private_transaction(rlp) {
			Ok(import_result) => Ok(import_result),
			Err(err) => {
				warn!(target: "privatetx", "Unable to import signed private transaction packet: {}", err);
				return Err(err.to_string())
			}
		}
	}

	fn private_state_synced(&self, hash: &H256) -> Result<(), String> {
		match self.provider.private_state_synced(hash) {
			Ok(handle_result) => Ok(handle_result),
			Err(err) => {
				warn!(target: "privatetx", "Unable to handle private state synced message: {}", err);
				return Err(err.to_string())
			}
		}
	}
}

/// Client service setup. Creates and registers client and network services with the IO subsystem.
pub struct ClientService {
	io_service: Arc<IoService<ClientIoMessage<Client>>>,
	client: Arc<Client>,
	snapshot: Arc<SnapshotService<Client>>,
	private_tx: Arc<PrivateTxService>,
	database: Arc<dyn BlockChainDB>,
}

impl ClientService {
	/// Start the `ClientService`.
	pub fn start(
		config: ClientConfig,
		spec: &Spec,
		blockchain_db: Arc<dyn BlockChainDB>,
		snapshot_path: &Path,
		restoration_db_handler: Box<dyn BlockChainDBHandler>,
		_ipc_path: &Path,
		miner: Arc<Miner>,
		signer: Arc<dyn Signer>,
		encryptor: Box<dyn ethcore_private_tx::Encryptor>,
		private_tx_conf: ethcore_private_tx::ProviderConfig,
		private_encryptor_conf: ethcore_private_tx::EncryptorConfig,
		) -> Result<ClientService, EthcoreError>
	{
		let io_service = IoService::<ClientIoMessage<Client>>::start()?;

		info!("Configured for {} using {} engine", Colour::White.bold().paint(spec.name.clone()), Colour::Yellow.bold().paint(spec.engine.name().to_string()));

		let pruning = config.pruning;
		let client = Client::new(
			config,
			&spec,
			blockchain_db.clone(),
			miner.clone(),
			io_service.channel(),
		)?;
		spec.engine.register_client(Arc::downgrade(&client) as _);
		miner.set_io_channel(io_service.channel());
		miner.set_in_chain_checker(&client.clone());

		let snapshot_params = SnapServiceParams {
			engine: spec.engine.clone(),
			genesis_block: spec.genesis_block(),
			restoration_db_handler,
			pruning,
			channel: io_service.channel(),
			snapshot_root: snapshot_path.into(),
			client: client.clone(),
		};
		let snapshot = Arc::new(SnapshotService::new(snapshot_params)?);

		let private_keys = Arc::new(ethcore_private_tx::SecretStoreKeys::new(
			client.clone(),
			private_encryptor_conf.key_server_account,
		));
		let provider = Arc::new(ethcore_private_tx::Provider::new(
			client.clone(),
			miner,
			signer,
			encryptor,
			private_tx_conf,
			io_service.channel(),
			private_keys,
			blockchain_db.key_value().clone(),
		));
		let private_tx = Arc::new(PrivateTxService::new(provider.clone()));
		io_service.register_handler(provider)?;

		let client_io = Arc::new(ClientIoHandler {
			client: client.clone(),
			snapshot: snapshot.clone(),
		});
		io_service.register_handler(client_io)?;

		Ok(ClientService {
			io_service: Arc::new(io_service),
			client,
			snapshot,
			private_tx,
			database: blockchain_db,
		})
	}

	/// Get general IO interface
	pub fn register_io_handler(&self, handler: Arc<dyn IoHandler<ClientIoMessage<Client>> + Send>) -> Result<(), IoError> {
		self.io_service.register_handler(handler)
	}

	/// Get client interface
	pub fn client(&self) -> Arc<Client> {
		self.client.clone()
	}

	/// Get snapshot interface.
	pub fn snapshot_service(&self) -> Arc<SnapshotService<Client>> {
		self.snapshot.clone()
	}

	/// Get private transaction service.
	pub fn private_tx_service(&self) -> Arc<PrivateTxService> {
		self.private_tx.clone()
	}

	/// Get network service component
	pub fn io(&self) -> Arc<IoService<ClientIoMessage<Client>>> {
		self.io_service.clone()
	}

	/// Set the actor to be notified on certain chain events
	pub fn add_notify(&self, notify: Arc<dyn ChainNotify>) {
		self.client.add_notify(notify);
	}

	/// Get a handle to the database.
	pub fn db(&self) -> Arc<dyn BlockChainDB> { self.database.clone() }

	/// Shutdown the Client Service
	pub fn shutdown(&self) {
		trace!(target: "shutdown", "Shutting down Client Service");
		self.snapshot.shutdown();
	}
}

/// IO interface for the Client handler
struct ClientIoHandler<C: Send + Sync + 'static> {
	client: Arc<C>,
	snapshot: Arc<SnapshotService<C>>,
}

const CLIENT_TICK_TIMER: TimerToken = 0;
const SNAPSHOT_TICK_TIMER: TimerToken = 1;

const CLIENT_TICK: Duration = Duration::from_secs(5);
const SNAPSHOT_TICK: Duration = Duration::from_secs(10);

impl<C> IoHandler<ClientIoMessage<C>> for ClientIoHandler<C>
where
	C: ImportBlock + SnapshotClient + Tick + 'static,
{
	fn initialize(&self, io: &IoContext<ClientIoMessage<C>>) {
		io.register_timer(CLIENT_TICK_TIMER, CLIENT_TICK).expect("Error registering client timer");
		io.register_timer(SNAPSHOT_TICK_TIMER, SNAPSHOT_TICK).expect("Error registering snapshot timer");
	}

	fn timeout(&self, _io: &IoContext<ClientIoMessage<C>>, timer: TimerToken) {
		trace_time!("service::read");
		match timer {
			CLIENT_TICK_TIMER => {
				use snapshot::SnapshotService;
				let snapshot_restoration = if let RestorationStatus::Ongoing{..} = self.snapshot.status() { true } else { false };
				self.client.tick(snapshot_restoration)
			},
			SNAPSHOT_TICK_TIMER => self.snapshot.tick(),
			_ => warn!("IO service triggered unregistered timer '{}'", timer),
		}
	}

	fn message(&self, _io: &IoContext<ClientIoMessage<C>>, net_message: &ClientIoMessage<C>) {
		trace_time!("service::message");
		use std::thread;

		match *net_message {
			ClientIoMessage::BlockVerified => {
				self.client.import_verified_blocks();
			}
			ClientIoMessage::BeginRestoration(ref manifest) => {
				if let Err(e) = self.snapshot.init_restore(manifest.clone(), true) {
					warn!("Failed to initialize snapshot restoration: {}", e);
				}
			}
			ClientIoMessage::FeedStateChunk(ref hash, ref chunk) => {
				self.snapshot.feed_state_chunk(*hash, chunk)
			}
			ClientIoMessage::FeedBlockChunk(ref hash, ref chunk) => {
				self.snapshot.feed_block_chunk(*hash, chunk)
			}
			ClientIoMessage::TakeSnapshot(num) => {
				let client = self.client.clone();
				let snapshot = self.snapshot.clone();
				let res = thread::Builder::new().name("Periodic Snapshot".into()).spawn(move || {
					if let Err(e) = snapshot.take_snapshot(&*client, num) {
						match e {
							EthcoreError::Snapshot(SnapshotError::SnapshotAborted) => info!("Snapshot aborted"),
							_ => warn!("Failed to take snapshot at block #{}: {}", num, e),
						}
					}
				});

				if let Err(e) = res {
					debug!(target: "snapshot", "Failed to initialize periodic snapshot thread: {:?}", e);
				}
			},
			ClientIoMessage::Execute(ref exec) => {
				(*exec.0)(&self.client);
			}
			_ => {} // ignore other messages
		}
	}
}

#[cfg(test)]
mod tests {
	use std::collections::HashMap;
	use std::sync::Arc;
	use std::{time, thread};

	use tempfile::TempDir;

	use ethcore_db::NUM_COLUMNS;
	use ethcore::client::ClientConfig;
	use ethcore::miner::Miner;
	use spec;
	use ethcore::test_helpers;
	use kvdb_rocksdb::{DatabaseConfig, CompactionProfile};
	use super::*;

	use ethcore_private_tx;

	#[test]
	fn it_can_be_started() {
		let tempdir = TempDir::new().unwrap();
		let client_path = tempdir.path().join("client");
		let snapshot_path = tempdir.path().join("snapshot");

		let mut client_db_config = DatabaseConfig::with_columns(NUM_COLUMNS);

		client_db_config.memory_budget = HashMap::new();
		client_db_config.compaction = CompactionProfile::auto(&client_path);

		let client_db_handler = test_helpers::restoration_db_handler(client_db_config.clone());
		let client_db = client_db_handler.open(&client_path).unwrap();
		let restoration_db_handler = test_helpers::restoration_db_handler(client_db_config);

		let spec = spec::new_test();
		let service = ClientService::start(
			ClientConfig::default(),
			&spec,
			client_db,
			&snapshot_path,
			restoration_db_handler,
			tempdir.path(),
			Arc::new(Miner::new_for_tests(&spec, None)),
			Arc::new(ethcore_private_tx::DummySigner),
			Box::new(ethcore_private_tx::NoopEncryptor),
			Default::default(),
			Default::default(),
		);
		assert!(service.is_ok());
		drop(service.unwrap());
		thread::park_timeout(time::Duration::from_millis(100));
	}
}
