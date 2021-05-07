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

/// Validator set maintained in a contract, updated using `getValidators` method.
/// It can also report validators for misbehaviour with two levels: `reportMalicious` and `reportBenign`.

use std::sync::Weak;

use parity_bytes::Bytes;
use ethabi_contract::use_contract;
use ethereum_types::{H256, U256, Address};
use log::{warn, trace};
use machine::Machine;
use parking_lot::RwLock;
use common_types::{
	BlockNumber,
	ids::BlockId,
	header::Header,
	errors::EthcoreError,
	engines::machine::Call,
	receipt::Receipt,
	transaction,
};

use client_traits::{EngineClient, TransactionRequest};
use engine::SystemCall;

use crate::{
	ValidatorSet, SimpleList,
	safe_contract::ValidatorSafeContract
};

use_contract!(validator_report, "res/validator_report.json");

/// A validator contract with reporting.
pub struct ValidatorContract {
	contract_address: Address,
	validators: ValidatorSafeContract,
	client: RwLock<Option<Weak<dyn EngineClient>>>, // TODO [keorn]: remove
	posdao_transition: Option<BlockNumber>,
}

impl ValidatorContract {
	pub fn new(contract_address: Address, posdao_transition: Option<BlockNumber>) -> Self {
		ValidatorContract {
			contract_address,
			validators: ValidatorSafeContract::new(contract_address, posdao_transition),
			client: RwLock::new(None),
			posdao_transition,
		}
	}
}

impl ValidatorContract {
	fn transact(&self, data: Bytes, gas_price: Option<U256>, client: &dyn EngineClient) -> Result<(), String> {
		let full_client = client.as_full_client().ok_or("No full client!")?;
		let tx_request = TransactionRequest::call(self.contract_address, data).gas_price(gas_price);
		match full_client.transact(tx_request) {
			Ok(()) | Err(transaction::Error::AlreadyImported) => Ok(()),
			Err(e) => Err(e.to_string())?,
		}
	}

	fn do_report_malicious(&self, address: &Address, block: BlockNumber, proof: Bytes) -> Result<(), EthcoreError> {
		let client = self.client.read().as_ref().and_then(Weak::upgrade).ok_or("No client!")?;
		let latest = client.block_header(BlockId::Latest).ok_or("No latest block!")?;
		if !self.contains(&latest.parent_hash(), address) {
			warn!(target: "engine", "Not reporting {} on block {}: Not a validator", address, block);
			return Ok(());
		}
		let data = validator_report::functions::report_malicious::encode_input(*address, block, proof);
		self.validators.enqueue_report(*address, block, data.clone());
		let gas_price = self.report_gas_price(latest.number());
		self.transact(data, gas_price, &*client)?;
		warn!(target: "engine", "Reported malicious validator {} at block {}", address, block);
		Ok(())
	}

	fn do_report_benign(&self, address: &Address, block: BlockNumber) -> Result<(), EthcoreError> {
		let client = self.client.read().as_ref().and_then(Weak::upgrade).ok_or("No client!")?;
		let latest = client.block_header(BlockId::Latest).ok_or("No latest block!")?;
		let data = validator_report::functions::report_benign::encode_input(*address, block);
		let gas_price = self.report_gas_price(latest.number());
		self.transact(data, gas_price, &*client)?;
		warn!(target: "engine", "Benign report for validator {} at block {}", address, block);
		Ok(())
	}

	/// Returns the gas price for report transactions.
	///
	/// After `posdaoTransition`, this is zero. Otherwise it is the default (`None`).
	fn report_gas_price(&self, block: BlockNumber) -> Option<U256> {
		if self.posdao_transition? <= block {
			Some(0.into())
		} else {
			None
		}
	}
}

impl ValidatorSet for ValidatorContract {
	fn default_caller(&self, id: BlockId) -> Box<Call> {
		self.validators.default_caller(id)
	}

	fn generate_engine_transactions(&self, first: bool, header: &Header, call: &mut SystemCall)
		-> Result<Vec<(Address, Bytes)>, EthcoreError>
	{
		self.validators.generate_engine_transactions(first, header, call)
	}

	fn on_close_block(&self, header: &Header, address: &Address) -> Result<(), EthcoreError> {
		self.validators.on_close_block(header, address)
	}

	fn on_epoch_begin(&self, first: bool, header: &Header, call: &mut SystemCall) -> Result<(), EthcoreError> {
		self.validators.on_epoch_begin(first, header, call)
	}

	fn genesis_epoch_data(&self, header: &Header, call: &Call) -> Result<Vec<u8>, String> {
		self.validators.genesis_epoch_data(header, call)
	}

	fn is_epoch_end(&self, first: bool, chain_head: &Header) -> Option<Vec<u8>> {
		self.validators.is_epoch_end(first, chain_head)
	}

	fn signals_epoch_end(
		&self,
		first: bool,
		header: &Header,
		receipts: Option<&[Receipt]>,
	) -> engine::EpochChange {
		self.validators.signals_epoch_end(first, header, receipts)
	}

	fn epoch_set(&self, first: bool, machine: &Machine, number: BlockNumber, proof: &[u8]) -> Result<(SimpleList, Option<H256>), EthcoreError> {
		self.validators.epoch_set(first, machine, number, proof)
	}

	fn contains_with_caller(&self, bh: &H256, address: &Address, caller: &Call) -> bool {
		self.validators.contains_with_caller(bh, address, caller)
	}

	fn get_with_caller(&self, bh: &H256, nonce: usize, caller: &Call) -> Address {
		self.validators.get_with_caller(bh, nonce, caller)
	}

	fn count_with_caller(&self, bh: &H256, caller: &Call) -> usize {
		self.validators.count_with_caller(bh, caller)
	}

	fn report_malicious(&self, address: &Address, _set_block: BlockNumber, block: BlockNumber, proof: Bytes) {
		if let Err(s) = self.do_report_malicious(address, block, proof) {
			warn!(target: "engine", "Validator {} could not be reported ({}) on block {}", address, s, block);
		}
	}

	fn report_benign(&self, address: &Address, _set_block: BlockNumber, block: BlockNumber) {
		trace!(target: "engine", "validator set recording benign misbehaviour at block #{} by {:#x}", block, address);
		if let Err(s) = self.do_report_benign(address, block) {
			warn!(target: "engine", "Validator {} could not be reported ({}) on block {}", address, s, block);
		}
	}

	fn register_client(&self, client: Weak<dyn EngineClient>) {
		self.validators.register_client(client.clone());
		*self.client.write() = Some(client);
	}
}

#[cfg(test)]
mod tests {
	use std::sync::Arc;

	use accounts::AccountProvider;
	use call_contract::CallContract;
	use common_types::{header::Header, ids::BlockId};
	use client_traits::{BlockChainClient, ChainInfo, BlockInfo, TransactionRequest};
	use ethabi::FunctionOutputDecoder;
	use ethcore::{
		miner::{self, MinerService},
		test_helpers::generate_dummy_client_with_spec,
	};
	use ethereum_types::{H520, Address};
	use keccak_hash::keccak;
	use parity_bytes::ToPretty;
	use rlp::encode;
	use rustc_hex::FromHex;
	use spec;

	use super::super::ValidatorSet;
	use super::ValidatorContract;

	#[test]
	fn fetches_validators() {
		let client = generate_dummy_client_with_spec(spec::new_validator_contract);
		let addr: Address = "0000000000000000000000000000000000000005".parse().unwrap();
		let vc = Arc::new(ValidatorContract::new(addr, None));
		vc.register_client(Arc::downgrade(&client) as _);
		let last_hash = client.best_block_header().hash();
		assert!(vc.contains(&last_hash, &"7d577a597b2742b498cb5cf0c26cdcd726d39e6e".parse::<Address>().unwrap()));
		assert!(vc.contains(&last_hash, &"82a978b3f5962a5b0957d9ee9eef472ee55b42f1".parse::<Address>().unwrap()));
	}

	#[test]
	fn reports_validators() {
		let _ = ::env_logger::try_init();
		let tap = Arc::new(AccountProvider::transient_provider());
		let v1 = tap.insert_account(keccak("1").into(), &"".into()).unwrap();
		let client = generate_dummy_client_with_spec(spec::new_validator_contract);
		client.engine().register_client(Arc::downgrade(&client) as _);
		let validator_contract = "0000000000000000000000000000000000000005".parse::<Address>().unwrap();

		// Make sure reporting can be done.
		client.miner().set_gas_range_target((1_000_000.into(), 1_000_000.into()));
		let signer = Box::new((tap.clone(), v1, "".into()));
		client.miner().set_author(miner::Author::Sealer(signer));

		// Check a block that is a bit in future, reject it but don't report the validator.
		let mut header = Header::default();
		let seal = vec![encode(&4u8), encode(&H520::zero().as_bytes())];
		header.set_seal(seal);
		header.set_author(v1);
		header.set_number(2);
		header.set_parent_hash(client.chain_info().best_block_hash);
		assert!(client.engine().verify_block_external(&header).is_err());
		client.engine().step();
		assert_eq!(client.chain_info().best_block_number, 0);
		// `reportBenign` when the designated proposer releases block from the future (bad clock).
		assert!(client.engine().verify_block_basic(&header).is_err());

		// Now create one that is more in future. That one should be rejected and validator should be reported.
		let mut header = Header::default();
		let seal = vec![encode(&8u8), encode(&H520::zero().as_bytes())];
		header.set_seal(seal);
		header.set_author(v1);
		header.set_number(2);
		header.set_parent_hash(client.chain_info().best_block_hash);
		// `reportBenign` when the designated proposer releases block from the future (bad clock).
		assert!(client.engine().verify_block_basic(&header).is_err());
		// Seal a block.
		client.engine().step();
		assert_eq!(client.chain_info().best_block_number, 1);
		// Check if the unresponsive validator is `disliked`. "d8f2e0bf" accesses the field `disliked`..
		assert_eq!(
			client.call_contract(BlockId::Latest, validator_contract, "d8f2e0bf".from_hex().unwrap()).unwrap().to_hex(),
			"0000000000000000000000007d577a597b2742b498cb5cf0c26cdcd726d39e6e"
		);
		// Simulate a misbehaving validator by handling a double proposal.
		let header = client.best_block_header();
		assert!(client.engine().verify_block_family(&header, &header).is_err());
		// Seal a block.
		client.engine().step();
		client.engine().step();
		assert_eq!(client.chain_info().best_block_number, 2);
		let (data, decoder) = super::validator_report::functions::malice_reported_for_block::call(v1, 1);
		let reported_enc = client.call_contract(BlockId::Latest, validator_contract, data).expect("call failed");
		assert_ne!(Vec::<Address>::new(), decoder.decode(&reported_enc).expect("decoding failed"));

		// Check if misbehaving validator was removed.
		client.transact(TransactionRequest::call(Default::default(), Default::default())).unwrap();
		client.engine().step();
		client.engine().step();
		assert_eq!(client.chain_info().best_block_number, 2);
	}
}
