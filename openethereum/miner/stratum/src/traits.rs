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

use ethereum_types::H256;
use jsonrpc_tcp_server::PushMessageError;

#[derive(Debug, Clone)]
pub enum Error {
	NoWork,
	NoWorkers,
	Io(String),
	Tcp(String),
	Dispatch(String),
}

impl From<std::io::Error> for Error {
	fn from(err: std::io::Error) -> Self {
		Error::Io(err.to_string())
	}
}

impl From<PushMessageError> for Error {
	fn from(err: PushMessageError) -> Self {
		Error::Tcp(format!("Push message error: {:?}", err))
	}
}

/// Interface that can provide pow/blockchain-specific responses for the clients
pub trait JobDispatcher: Send + Sync {
	// json for initial client handshake
	fn initial(&self) -> Option<String> { None }
	// json for difficulty dispatch
	fn difficulty(&self) -> Option<String> { None }
	// json for job update given worker_id (payload manager should split job!)
	fn job(&self) -> Option<String> { None }
	// miner job result
	fn submit(&self, payload: Vec<String>) -> Result<(), Error>;
}

/// Interface that can handle requests to push job for workers
pub trait PushWorkHandler: Send + Sync {
	/// push the same work package for all workers (`payload`: json of pow-specific set of work specification)
	fn push_work_all(&self, payload: String);
}

pub struct ServiceConfiguration {
	pub io_path: String,
	pub listen_addr: String,
	pub port: u16,
	pub secret: Option<H256>,
}
