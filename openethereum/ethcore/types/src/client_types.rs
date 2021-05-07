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

//! Client related types.

use std::{
	cmp,
	fmt::{Display, Formatter, Error as FmtError},
	ops,
	time::Duration,
};

use ethereum_types::U256;

/// Operating mode for the client.
#[derive(Debug, Eq, PartialEq, Clone)]
pub enum Mode {
	/// Always on.
	Active,
	/// Goes offline after client is inactive for some (given) time, but
	/// comes back online after a while of inactivity.
	Passive(Duration, Duration),
	/// Goes offline after client is inactive for some (given) time and
	/// stays inactive.
	Dark(Duration),
	/// Always off.
	Off,
}

impl Display for Mode {
	fn fmt(&self, f: &mut Formatter) -> Result<(), FmtError> {
		match *self {
			Mode::Active => write!(f, "active"),
			Mode::Passive(..) => write!(f, "passive"),
			Mode::Dark(..) => write!(f, "dark"),
			Mode::Off => write!(f, "offline"),
		}
	}
}

/// Report on the status of a client.
#[derive(Default, Clone, Debug, Eq, PartialEq)]
pub struct ClientReport {
	/// How many blocks have been imported so far.
	pub blocks_imported: usize,
	/// How many transactions have been applied so far.
	pub transactions_applied: usize,
	/// How much gas has been processed so far.
	pub gas_processed: U256,
	/// Memory used by state DB
	pub state_db_mem: usize,
	/// I/O statistics for the state DB.
	pub io_stats: IoStats,
}

/// I/O statistics.
#[derive(Default, Debug, Clone, Eq, PartialEq)]
pub struct IoStats {
	/// Number of transaction.
	pub transactions: u64,
	/// Number of read operations.
	pub reads: u64,
	/// Number of reads resulted in a read from cache.
	pub cache_reads: u64,
	/// Number of write operations.
	pub writes: u64,
	/// Number of bytes read.
	pub bytes_read: u64,
	/// Number of bytes read from cache.
	pub cache_read_bytes: u64,
	/// Number of bytes write.
	pub bytes_written: u64,
}

impl ClientReport {
	/// Alter internal reporting to reflect the additional `block` has been processed.
	pub fn accrue_block(&mut self, gas_used: U256, transactions: usize) {
		self.blocks_imported += 1;
		self.transactions_applied += transactions;
		self.gas_processed += gas_used;
	}
}

impl<'a> ops::Sub<&'a ClientReport> for ClientReport {
	type Output = Self;

	fn sub(mut self, other: &'a ClientReport) -> Self {
		let higher_mem = cmp::max(self.state_db_mem, other.state_db_mem);
		let lower_mem = cmp::min(self.state_db_mem, other.state_db_mem);

		self.blocks_imported -= other.blocks_imported;
		self.transactions_applied -= other.transactions_applied;
		self.gas_processed = self.gas_processed - other.gas_processed;
		self.state_db_mem = higher_mem - lower_mem;

		self
	}
}

/// Result to be used during get address code at given block's state
pub enum StateResult<T> {
	/// State is missing
	Missing,

	/// State is some
	Some(T),
}
