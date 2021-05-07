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

//! Ethereum-like state machine definition.

use std::collections::BTreeMap;
use std::cmp;
use std::sync::Arc;

use ethereum_types::{U256, H256, Address};
use rlp::Rlp;
use log::debug;

use common_types::{
	BlockNumber,
	header::Header,
	engines::{
		EthashExtensions,
		params::CommonParams,
	},
	errors::{EngineError, EthcoreError as Error},
	transaction::{self, SYSTEM_ADDRESS, UNSIGNED_SENDER, UnverifiedTransaction, SignedTransaction},
};
use vm::{ActionType, ActionParams, ActionValue, ParamsType};
use vm::{EnvInfo, Schedule};

use account_state::CleanupMode;
use client_traits::BlockInfo;
use ethcore_builtin::Builtin;
use ethcore_call_contract::CallContract;
use trace::{NoopTracer, NoopVMTracer};

use crate::{
	executed_block::ExecutedBlock,
	executive::Executive,
	substate::Substate,
	tx_filter::TransactionFilter,
};

/// Parity tries to round block.gas_limit to multiple of this constant
pub const PARITY_GAS_LIMIT_DETERMINANT: U256 = U256([37, 0, 0, 0]);

/// Special rules to be applied to the schedule.
pub type ScheduleCreationRules = dyn Fn(&mut Schedule, BlockNumber) + Sync + Send;

/// An ethereum-like state machine.
pub struct Machine {
	params: CommonParams,
	builtins: Arc<BTreeMap<Address, Builtin>>,
	tx_filter: Option<Arc<TransactionFilter>>,
	ethash_extensions: Option<EthashExtensions>,
	schedule_rules: Option<Box<ScheduleCreationRules>>,
}

impl Machine {
	/// Regular ethereum machine.
	pub fn regular(params: CommonParams, builtins: BTreeMap<Address, Builtin>) -> Machine {
		let tx_filter = TransactionFilter::from_params(&params).map(Arc::new);
		Machine {
			params,
			builtins: Arc::new(builtins),
			tx_filter,
			ethash_extensions: None,
			schedule_rules: None,
		}
	}

	/// Ethereum machine with ethash extensions.
	// TODO: either unify or specify to mainnet specifically and include other specific-chain HFs?
	pub fn with_ethash_extensions(params: CommonParams, builtins: BTreeMap<Address, Builtin>, extensions: EthashExtensions) -> Machine {
		let mut machine = Machine::regular(params, builtins);
		machine.ethash_extensions = Some(extensions);
		machine
	}

	/// Attach special rules to the creation of schedule.
	pub fn set_schedule_creation_rules(&mut self, rules: Box<ScheduleCreationRules>) {
		self.schedule_rules = Some(rules);
	}

	/// Get a reference to the ethash-specific extensions.
	pub fn ethash_extensions(&self) -> Option<&EthashExtensions> {
		self.ethash_extensions.as_ref()
	}

	/// Execute a call as the system address. Block environment information passed to the
	/// VM is modified to have its gas limit bounded at the upper limit of possible used
	/// gas, including this system call, capped at the maximum value able to be
	/// represented by U256. This system call modifies the block state, but discards other
	/// information. If suicides, logs or refunds happen within the system call, they
	/// will not be executed or recorded. Gas used by this system call will not be counted
	/// on the block.
	pub fn execute_as_system(
		&self,
		block: &mut ExecutedBlock,
		contract_address: Address,
		gas: U256,
		data: Option<Vec<u8>>,
	) -> Result<Vec<u8>, Error> {
		let (code, code_hash) = {
			let state = &block.state;

			(state.code(&contract_address)?,
			 state.code_hash(&contract_address)?)
		};

		self.execute_code_as_system(
			block,
			Some(contract_address),
			code,
			code_hash,
			None,
			gas,
			data,
			None,
		)
	}

	/// Same as execute_as_system, but execute code directly. If contract address is None, use the null sender
	/// address. If code is None, then this function has no effect. The call is executed without finalization, and does
	/// not form a transaction.
	pub fn execute_code_as_system(
		&self,
		block: &mut ExecutedBlock,
		contract_address: Option<Address>,
		code: Option<Arc<Vec<u8>>>,
		code_hash: Option<H256>,
		value: Option<ActionValue>,
		gas: U256,
		data: Option<Vec<u8>>,
		action_type: Option<ActionType>,
	) -> Result<Vec<u8>, Error> {
		let env_info = {
			let mut env_info = block.env_info();
			env_info.gas_limit = env_info.gas_used.saturating_add(gas);
			env_info
		};

		let mut state = block.state_mut();

		let params = ActionParams {
			code_address: contract_address.unwrap_or(UNSIGNED_SENDER),
			address: contract_address.unwrap_or(UNSIGNED_SENDER),
			sender: SYSTEM_ADDRESS,
			origin: SYSTEM_ADDRESS,
			gas,
			gas_price: 0.into(),
			value: value.unwrap_or_else(|| ActionValue::Transfer(0.into())),
			code,
			code_hash,
			code_version: 0.into(),
			data,
			action_type: action_type.unwrap_or(ActionType::Call),
			params_type: ParamsType::Separate,
		};
		let schedule = self.schedule(env_info.number);
		let mut ex = Executive::new(&mut state, &env_info, self, &schedule);
		let mut substate = Substate::new();

		let res = ex.call(params, &mut substate, &mut NoopTracer, &mut NoopVMTracer).map_err(|e| EngineError::FailedSystemCall(format!("{}", e)))?;
		let output = res.return_data.to_vec();

		Ok(output)
	}

	/// Push last known block hash to the state.
	fn push_last_hash(&self, block: &mut ExecutedBlock) -> Result<(), Error> {
		let params = self.params();
		if block.header.number() == params.eip210_transition {
			let state = block.state_mut();
			state.init_code(&params.eip210_contract_address, params.eip210_contract_code.clone())?;
		}
		if block.header.number() >= params.eip210_transition {
			let parent_hash = *block.header.parent_hash();
			let _ = self.execute_as_system(
				block,
				params.eip210_contract_address,
				params.eip210_contract_gas,
				Some(parent_hash.as_bytes().to_vec()),
			)?;
		}
		Ok(())
	}

	/// Logic to perform on a new block: updating last hashes and the DAO
	/// fork, for ethash.
	pub fn on_new_block(&self, block: &mut ExecutedBlock) -> Result<(), Error> {
		self.push_last_hash(block)?;

		if let Some(ref ethash_params) = self.ethash_extensions {
			if block.header.number() == ethash_params.dao_hardfork_transition {
				let state = block.state_mut();
				for child in &ethash_params.dao_hardfork_accounts {
					let beneficiary = &ethash_params.dao_hardfork_beneficiary;
					state.balance(child)
						.and_then(|b| state.transfer_balance(child, beneficiary, &b, CleanupMode::NoEmpty))?;
				}
			}
		}

		Ok(())
	}

	/// Populate a header's fields based on its parent's header.
	/// Usually implements the chain scoring rule based on weight.
	/// The gas floor target must not be lower than the engine's minimum gas limit.
	pub fn populate_from_parent(&self, header: &mut Header, parent: &Header, gas_floor_target: U256, gas_ceil_target: U256) {
		header.set_difficulty(parent.difficulty().clone());
		let gas_limit = parent.gas_limit().clone();
		assert!(!gas_limit.is_zero(), "Gas limit should be > 0");

		if let Some(ref ethash_params) = self.ethash_extensions {
			let gas_limit = {
				let bound_divisor = self.params().gas_limit_bound_divisor;
				let lower_limit = gas_limit - gas_limit / bound_divisor + 1;
				let upper_limit = gas_limit + gas_limit / bound_divisor - 1;
				let gas_limit = if gas_limit < gas_floor_target {
					let gas_limit = cmp::min(gas_floor_target, upper_limit);
					round_block_gas_limit(gas_limit, lower_limit, upper_limit)
				} else if gas_limit > gas_ceil_target {
					let gas_limit = cmp::max(gas_ceil_target, lower_limit);
					round_block_gas_limit(gas_limit, lower_limit, upper_limit)
				} else {
					let total_lower_limit = cmp::max(lower_limit, gas_floor_target);
					let total_upper_limit = cmp::min(upper_limit, gas_ceil_target);
					let gas_limit = cmp::max(gas_floor_target, cmp::min(total_upper_limit,
						lower_limit + (header.gas_used().clone() * 6u32 / 5) / bound_divisor));
					round_block_gas_limit(gas_limit, total_lower_limit, total_upper_limit)
				};
				// ensure that we are not violating protocol limits
				debug_assert!(gas_limit >= lower_limit);
				debug_assert!(gas_limit <= upper_limit);
				gas_limit
			};

			header.set_gas_limit(gas_limit);
			if header.number() >= ethash_params.dao_hardfork_transition &&
				header.number() <= ethash_params.dao_hardfork_transition + 9 {
				header.set_extra_data(b"dao-hard-fork"[..].to_owned());
			}
			return
		}

		header.set_gas_limit({
			let bound_divisor = self.params().gas_limit_bound_divisor;
			if gas_limit < gas_floor_target {
				cmp::min(gas_floor_target, gas_limit + gas_limit / bound_divisor - 1)
			} else {
				cmp::max(gas_floor_target, gas_limit - gas_limit / bound_divisor + 1)
			}
		});
	}

	/// Get the general parameters of the chain.
	pub fn params(&self) -> &CommonParams {
		&self.params
	}

	/// Get the EVM schedule for the given block number.
	pub fn schedule(&self, block_number: BlockNumber) -> Schedule {
		let mut schedule = match self.ethash_extensions {
			None => self.params.schedule(block_number),
			Some(ref ext) => {
				if block_number < ext.homestead_transition {
					Schedule::new_frontier()
				} else {
					self.params.schedule(block_number)
				}
			}
		};

		if let Some(ref rules) = self.schedule_rules {
			(rules)(&mut schedule, block_number)
		}

		schedule
	}

	/// Builtin-contracts for the chain..
	pub fn builtins(&self) -> &BTreeMap<Address, Builtin> {
		&*self.builtins
	}

	/// Attempt to get a handle to a built-in contract.
	/// Only returns references to activated built-ins.
	// TODO: builtin contract routing - to do this properly, it will require removing the built-in configuration-reading logic
	// from Spec into here and removing the Spec::builtins field.
	pub fn builtin(&self, a: &Address, block_number: BlockNumber) -> Option<&Builtin> {
		self.builtins()
			.get(a)
			.and_then(|b| if b.is_active(block_number) { Some(b) } else { None })
	}

	/// Some intrinsic operation parameters; by default they take their value from the `spec()`'s `engine_params`.
	pub fn maximum_extra_data_size(&self) -> usize { self.params().maximum_extra_data_size }

	/// The nonce with which accounts begin at given block.
	pub fn account_start_nonce(&self, block: u64) -> U256 {
		let params = self.params();

		if block >= params.dust_protection_transition {
			U256::from(params.nonce_cap_increment) * U256::from(block)
		} else {
			params.account_start_nonce
		}
	}

	/// The network ID that transactions should be signed with.
	pub fn signing_chain_id(&self, env_info: &EnvInfo) -> Option<u64> {
		let params = self.params();

		if env_info.number >= params.eip155_transition {
			Some(params.chain_id)
		} else {
			None
		}
	}

	/// Does basic verification of the transaction.
	pub fn verify_transaction_basic(&self, t: &UnverifiedTransaction, header: &Header) -> Result<(), transaction::Error> {
		let check_low_s = match self.ethash_extensions {
			Some(ref ext) => header.number() >= ext.homestead_transition,
			None => true,
		};

		let chain_id = if header.number() < self.params().validate_chain_id_transition {
			t.chain_id()
		} else if header.number() >= self.params().eip155_transition {
			Some(self.params().chain_id)
		} else {
			None
		};
		t.verify_basic(check_low_s, chain_id)?;

		Ok(())
	}

	/// Does verification of the transaction against the parent state.
	pub fn verify_transaction<C: BlockInfo + CallContract>(
		&self,
		t: &SignedTransaction,
		parent: &Header,
		client: &C
	) -> Result<(), transaction::Error> {
		if let Some(ref filter) = self.tx_filter.as_ref() {
			if !filter.transaction_allowed(&parent.hash(), parent.number() + 1, t, client) {
				return Err(transaction::Error::NotAllowed.into())
			}
		}

		Ok(())
	}

	/// Performs pre-validation of RLP encoded transaction before other
	/// processing: check length against `max_transaction_size` and decode the
	/// RLP.
	pub fn decode_transaction(&self, transaction: &[u8]) -> Result<UnverifiedTransaction, transaction::Error> {
		let rlp = Rlp::new(&transaction);
		if rlp.as_raw().len() > self.params().max_transaction_size {
			debug!("Rejected oversized transaction of {} bytes", rlp.as_raw().len());
			return Err(transaction::Error::TooBig)
		}
		rlp.as_val().map_err(|e| transaction::Error::InvalidRlp(e.to_string()))
	}

	/// Get the balance, in base units, associated with an account.
	/// Extracts data from the live block.
	pub fn balance(&self, live: &ExecutedBlock, address: &Address) -> Result<U256, Error> {
		live.state.balance(address).map_err(Into::into)
	}

	/// Increment the balance of an account in the state of the live block.
	pub fn add_balance(&self, live: &mut ExecutedBlock, address: &Address, amount: &U256) -> Result<(), Error> {
		live.state_mut().add_balance(address, amount, CleanupMode::NoEmpty).map_err(Into::into)
	}
}

// Try to round gas_limit a bit so that:
// 1) it will still be in desired range
// 2) it will be a nearest (with tendency to increase) multiple of PARITY_GAS_LIMIT_DETERMINANT
fn round_block_gas_limit(gas_limit: U256, lower_limit: U256, upper_limit: U256) -> U256 {
	let increased_gas_limit = gas_limit + (PARITY_GAS_LIMIT_DETERMINANT - gas_limit % PARITY_GAS_LIMIT_DETERMINANT);
	if increased_gas_limit > upper_limit {
		let decreased_gas_limit = increased_gas_limit - PARITY_GAS_LIMIT_DETERMINANT;
		if decreased_gas_limit < lower_limit {
			gas_limit
		} else {
			decreased_gas_limit
		}
	} else {
		increased_gas_limit
	}
}

#[cfg(test)]
mod tests {
	use std::str::FromStr;
	use common_types::header::Header;
	use hex_literal::hex;
	use super::*;

	fn get_default_ethash_extensions() -> EthashExtensions {
		EthashExtensions {
			homestead_transition: 1150000,
			dao_hardfork_transition: u64::max_value(),
			dao_hardfork_beneficiary: Address::from_str("0000000000000000000000000000000000000001").unwrap(),
			dao_hardfork_accounts: Vec::new(),
		}
	}

	#[test]
	fn should_disallow_unsigned_transactions() {
		let rlp = hex!("ea80843b9aca0083015f90948921ebb5f79e9e3920abe571004d0b1d5119c154865af3107a400080038080").to_vec();
		let transaction: UnverifiedTransaction = rlp::decode(&rlp).unwrap();
		assert_eq!(
			transaction::Error::from(transaction.verify_unordered().unwrap_err()),
			transaction::Error::InvalidSignature("invalid EC signature".into()),
		);
	}

	#[test]
	fn ethash_gas_limit_is_multiple_of_determinant() {
		use ethereum_types::U256;

		let spec = spec::new_homestead_test();
		let ethparams = get_default_ethash_extensions();

		let machine = Machine::with_ethash_extensions(
			spec.params().clone(),
			Default::default(),
			ethparams,
		);

		let mut parent = Header::new();
		let mut header = Header::new();
		header.set_number(1);

		// this test will work for this constant only
		assert_eq!(PARITY_GAS_LIMIT_DETERMINANT, U256::from(37));

		// when parent.gas_limit < gas_floor_target:
		parent.set_gas_limit(U256::from(50_000));
		machine.populate_from_parent(&mut header, &parent, U256::from(100_000), U256::from(200_000));
		assert_eq!(*header.gas_limit(), U256::from(50_024));

		// when parent.gas_limit > gas_ceil_target:
		parent.set_gas_limit(U256::from(250_000));
		machine.populate_from_parent(&mut header, &parent, U256::from(100_000), U256::from(200_000));
		assert_eq!(*header.gas_limit(), U256::from(249_787));

		// when parent.gas_limit is in miner's range
		header.set_gas_used(U256::from(150_000));
		parent.set_gas_limit(U256::from(150_000));
		machine.populate_from_parent(&mut header, &parent, U256::from(100_000), U256::from(200_000));
		assert_eq!(*header.gas_limit(), U256::from(150_035));

		// when parent.gas_limit is in miner's range
		// && we can NOT increase it to be multiple of constant
		header.set_gas_used(U256::from(150_000));
		parent.set_gas_limit(U256::from(150_000));
		machine.populate_from_parent(&mut header, &parent, U256::from(100_000), U256::from(150_002));
		assert_eq!(*header.gas_limit(), U256::from(149_998));

		// when parent.gas_limit is in miner's range
		// && we can NOT increase it to be multiple of constant
		// && we can NOT decrease it to be multiple of constant
		header.set_gas_used(U256::from(150_000));
		parent.set_gas_limit(U256::from(150_000));
		machine.populate_from_parent(&mut header, &parent, U256::from(150_000), U256::from(150_002));
		assert_eq!(*header.gas_limit(), U256::from(150_002));
	}
}
