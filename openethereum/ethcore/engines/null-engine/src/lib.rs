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

use common_types::{
	BlockNumber,
	header::Header,
	engines::params::CommonParams,
	errors::EthcoreError as Error,
};
use engine::Engine;
use block_reward::{self, RewardKind};
use ethereum_types::U256;
use machine::{
	ExecutedBlock,
	Machine,
};
use common_types::{
	ancestry_action::AncestryAction,
	header::ExtendedHeader,
	snapshot::Snapshotting
};

/// Params for a null engine.
#[derive(Clone, Default)]
pub struct NullEngineParams {
	/// base reward for a block.
	pub block_reward: U256,
	/// Immediate finalization.
	pub immediate_finalization: bool
}

impl From<ethjson::spec::NullEngineParams> for NullEngineParams {
	fn from(p: ethjson::spec::NullEngineParams) -> Self {
		NullEngineParams {
			block_reward: p.block_reward.map_or_else(Default::default, Into::into),
			immediate_finalization: p.immediate_finalization.unwrap_or(false)
		}
	}
}

/// An engine which does not provide any consensus mechanism and does not seal blocks.
pub struct NullEngine {
	params: NullEngineParams,
	machine: Machine,
}

impl NullEngine {
	/// Returns new instance of NullEngine with default VM Factory
	pub fn new(params: NullEngineParams, machine: Machine) -> Self {
		NullEngine {
			params,
			machine,
		}
	}
}
impl Engine for NullEngine {
	fn name(&self) -> &str { "NullEngine" }

	fn machine(&self) -> &Machine { &self.machine }

	fn maximum_uncle_count(&self, _block: BlockNumber) -> usize { 2 }

	fn on_close_block(
		&self,
		block: &mut ExecutedBlock,
		_parent_header: &Header
	) -> Result<(), Error> {
		use std::ops::Shr;

		let author = *block.header.author();
		let number = block.header.number();

		let reward = self.params.block_reward;
		if reward == U256::zero() { return Ok(()) }

		let n_uncles = block.uncles.len();

		let mut rewards = Vec::new();

		// Bestow block reward
		let result_block_reward = reward + reward.shr(5) * U256::from(n_uncles);
		rewards.push((author, RewardKind::Author, result_block_reward));

		// bestow uncle rewards.
		for u in &block.uncles {
			let uncle_author = u.author();
			let result_uncle_reward = (reward * U256::from(8 + u.number() - number)).shr(3);
			rewards.push((*uncle_author, RewardKind::uncle(number, u.number()), result_uncle_reward));
		}

		block_reward::apply_block_rewards(&rewards, block, &self.machine)
	}

	fn verify_local_seal(&self, _header: &Header) -> Result<(), Error> {
		Ok(())
	}

	fn snapshot_mode(&self) -> Snapshotting {
		Snapshotting::PoW { blocks: 10_000, max_restore_blocks: 10_000 }
	}

	fn params(&self) -> &CommonParams {
		self.machine.params()
	}

	fn ancestry_actions(&self, _header: &Header, ancestry: &mut dyn Iterator<Item=ExtendedHeader>) -> Vec<AncestryAction> {
		if self.params.immediate_finalization {
			// always mark parent finalized
			ancestry.take(1).map(|e| AncestryAction::MarkFinalized(e.header.hash())).collect()
		} else {
			Vec::new()
		}
	}
}
