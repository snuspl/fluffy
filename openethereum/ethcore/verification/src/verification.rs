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

//! Block and transaction verification functions
//!
//! Block verification is done in 3 steps
//! 1. Quick verification upon adding to the block queue
//! 2. Signatures verification done in the queue.
//! 3. Final verification against the blockchain done before enactment.

use std::collections::HashSet;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use keccak_hash::keccak;
use rlp::Rlp;
use triehash::ordered_trie_root;
use unexpected::{Mismatch, OutOfBounds};

use blockchain::BlockProvider;
use call_contract::CallContract;
use client_traits::BlockInfo;
use engine::Engine;
use common_types::{
	BlockNumber,
	header::Header,
	errors::{EthcoreError as Error, BlockError},
	engines::MAX_UNCLE_AGE,
	block::{BlockRlpRepresentation, PreverifiedBlock},
	verification::Unverified,
};

use time_utils::CheckedSystemTime;

/// Phase 1 quick block verification. Only does checks that are cheap. Operates on a single block
pub fn verify_block_basic(block: &Unverified, engine: &dyn Engine, check_seal: bool) -> Result<(), Error> {
	verify_header_params(&block.header, engine, check_seal)?;
	verify_header_time(&block.header)?;
	verify_block_integrity(block)?;

	if check_seal {
		engine.verify_block_basic(&block.header)?;
	}

	for uncle in &block.uncles {
		verify_header_params(uncle, engine, check_seal)?;
		if check_seal {
			engine.verify_block_basic(uncle)?;
		}
	}

	if let Some(gas_limit) = engine.gas_limit_override(&block.header) {
		if *block.header.gas_limit() != gas_limit {
			return Err(From::from(BlockError::InvalidGasLimit(
				OutOfBounds { min: Some(gas_limit), max: Some(gas_limit), found: *block.header.gas_limit() }
			)));
		}
	}

	for t in &block.transactions {
		engine.verify_transaction_basic(t, &block.header)?;
	}

	Ok(())
}

/// Phase 2 verification. Perform costly checks such as transaction signatures and block nonce for ethash.
/// Still operates on a individual block
/// Returns a `PreverifiedBlock` structure populated with transactions along with the RLP representation of the block.
pub fn verify_block_unordered(
	block: Unverified,
	engine: &dyn Engine,
	check_seal: bool,
) -> Result<(PreverifiedBlock, BlockRlpRepresentation), Error> {
	let header = block.header;
	if check_seal {
		engine.verify_block_unordered(&header)?;
		for uncle in &block.uncles {
			engine.verify_block_unordered(uncle)?;
		}
	}
	// Verify transactions.
	let nonce_cap = if header.number() >= engine.params().dust_protection_transition {
		Some((engine.params().nonce_cap_increment * header.number()).into())
	} else {
		None
	};

	let transactions = block.transactions
		.into_iter()
		.map(|t| {
			let t = t.verify_unordered()?;
			if let Some(max_nonce) = nonce_cap {
				if t.nonce >= max_nonce {
					return Err(BlockError::TooManyTransactions(t.sender()).into());
				}
			}
			Ok(t)
		})
		.collect::<Result<Vec<_>, Error>>()?;

	Ok((PreverifiedBlock {
			header,
			transactions,
			uncles: block.uncles,
		},
		block.bytes,
	))
}

/// Parameters for full verification of block family
pub struct FullFamilyParams<'a, C: BlockInfo + CallContract + 'a> {
	/// Preverified block
	pub block: &'a PreverifiedBlock,

	/// Block provider to use during verification
	pub block_provider: &'a dyn BlockProvider,

	/// Engine client to use during verification
	pub client: &'a C,
}

/// Phase 3 verification. Check block information against parent and uncles.
pub fn verify_block_family<C: BlockInfo + CallContract>(
	header: &Header,
	parent: &Header,
	engine: &dyn Engine,
	params: FullFamilyParams<C>
) -> Result<(), Error> {
	// TODO: verify timestamp
	verify_parent(&header, &parent, engine)?;
	engine.verify_block_family(&header, &parent)?;
	verify_uncles(params.block, params.block_provider, engine)?;

	for tx in &params.block.transactions {
		// transactions are verified against the parent header since the current
		// state wasn't available when the tx was created
		engine.machine().verify_transaction(tx, parent, params.client)?;
	}

	Ok(())
}

fn verify_uncles(block: &PreverifiedBlock, bc: &dyn BlockProvider, engine: &dyn Engine) -> Result<(), Error> {
	let header = &block.header;
	let num_uncles = block.uncles.len();
	let max_uncles = engine.maximum_uncle_count(header.number());
	if num_uncles != 0 {
		if num_uncles > max_uncles {
			return Err(From::from(BlockError::TooManyUncles(OutOfBounds {
				min: None,
				max: Some(max_uncles),
				found: num_uncles,
			})));
		}

		let mut excluded = HashSet::new();
		excluded.insert(header.hash());
		let mut hash = *header.parent_hash();
		excluded.insert(hash);
		for _ in 0..MAX_UNCLE_AGE {
			match bc.block_details(&hash) {
				Some(details) => {
					excluded.insert(details.parent);
					let b = bc.block(&hash).expect("parent already known to be stored; qed");
					excluded.extend(b.uncle_hashes());
					hash = details.parent;
				}
				None => break
			}
		}

		let mut verified = HashSet::new();
		for uncle in &block.uncles {
			if excluded.contains(&uncle.hash()) {
				return Err(From::from(BlockError::UncleInChain(uncle.hash())))
			}

			if verified.contains(&uncle.hash()) {
				return Err(From::from(BlockError::DuplicateUncle(uncle.hash())))
			}

			// uncle.number() needs to be within specific number range which is
			// [header.number() - MAX_UNCLE_AGE, header.number() - 1]
			//
			// depth is the difference between uncle.number() and header.number()
			// and the previous condition implies that it is always in range
			// [1, MAX_UNCLE_AGE]
			let depth = if header.number() > uncle.number() &&
				uncle.number() + MAX_UNCLE_AGE >= header.number() {
				header.number() - uncle.number()
			} else {
				return Err(BlockError::UncleOutOfBounds(OutOfBounds {
					min: Some(header.number() - MAX_UNCLE_AGE),
					max: Some(header.number() - 1),
					found: uncle.number()
				}).into());
			};

			// cB
			// cB.p^1	    1 depth, valid uncle
			// cB.p^2	---/  2
			// cB.p^3	-----/  3
			// cB.p^4	-------/  4
			// cB.p^5	---------/  5
			// cB.p^6	-----------/  6
			// cB.p^7	-------------/
			// cB.p^8
			let mut expected_uncle_parent = *header.parent_hash();
			let uncle_parent = bc.block_header_data(&uncle.parent_hash())
				.ok_or_else(|| BlockError::UnknownUncleParent(*uncle.parent_hash()))?;
			for _ in 0..depth {
				match bc.block_details(&expected_uncle_parent) {
					Some(details) => {
						expected_uncle_parent = details.parent;
					},
					None => break
				}
			}
			if expected_uncle_parent != uncle_parent.hash() {
				return Err(From::from(BlockError::UncleParentNotInChain(uncle_parent.hash())));
			}

			let uncle_parent = uncle_parent.decode()?;
			verify_parent(&uncle, &uncle_parent, engine)?;
			engine.verify_block_family(&uncle, &uncle_parent)?;
			verified.insert(uncle.hash());
		}
	}

	Ok(())
}

/// Phase 4 verification. Check block information against transaction enactment results,
pub fn verify_block_final(expected: &Header, got: &Header) -> Result<(), Error> {
	if expected.state_root() != got.state_root() {
		return Err(From::from(BlockError::InvalidStateRoot(Mismatch {
			expected: *expected.state_root(),
			found: *got.state_root()
		})))
	}
	if expected.gas_used() != got.gas_used() {
		return Err(From::from(BlockError::InvalidGasUsed(Mismatch {
			expected: *expected.gas_used(),
			found: *got.gas_used()
		})))
	}
	if expected.log_bloom() != got.log_bloom() {
		return Err(From::from(BlockError::InvalidLogBloom(Box::new(Mismatch {
			expected: *expected.log_bloom(),
			found: *got.log_bloom()
		}))))
	}
	if expected.receipts_root() != got.receipts_root() {
		return Err(From::from(BlockError::InvalidReceiptsRoot(Mismatch {
			expected: *expected.receipts_root(),
			found: *got.receipts_root()
		})))
	}
	Ok(())
}

/// Check basic header parameters.
pub(crate) fn verify_header_params(header: &Header, engine: &dyn Engine, check_seal: bool) -> Result<(), Error> {
	if check_seal {
		let expected_seal_fields = engine.seal_fields(header);
		if header.seal().len() != expected_seal_fields {
			return Err(From::from(BlockError::InvalidSealArity(
				Mismatch { expected: expected_seal_fields, found: header.seal().len() }
			)));
		}
	}

	if header.number() >= From::from(BlockNumber::max_value()) {
		return Err(From::from(BlockError::RidiculousNumber(OutOfBounds {
			max: Some(From::from(BlockNumber::max_value())),
			min: None,
			found: header.number()
		})))
	}
	if header.gas_used() > header.gas_limit() {
		return Err(From::from(BlockError::TooMuchGasUsed(OutOfBounds {
			max: Some(*header.gas_limit()),
			min: None,
			found: *header.gas_used()
		})));
	}
	if engine.gas_limit_override(header).is_none() {
		let min_gas_limit = engine.min_gas_limit();
		if header.gas_limit() < &min_gas_limit {
			return Err(From::from(BlockError::InvalidGasLimit(OutOfBounds {
				min: Some(min_gas_limit),
				max: None,
				found: *header.gas_limit()
			})));
		}
		if let Some(limit) = engine.maximum_gas_limit() {
			if header.gas_limit() > &limit {
				return Err(From::from(BlockError::InvalidGasLimit(OutOfBounds {
					min: None,
					max: Some(limit),
					found: *header.gas_limit()
				})));
			}
		}
	}
	let maximum_extra_data_size = engine.maximum_extra_data_size();
	if header.number() != 0 && header.extra_data().len() > maximum_extra_data_size {
		return Err(From::from(BlockError::ExtraDataOutOfBounds(OutOfBounds {
			min: None,
			max: Some(maximum_extra_data_size),
			found: header.extra_data().len()
		})));
	}

	if let Some(ref ext) = engine.machine().ethash_extensions() {
		if header.number() >= ext.dao_hardfork_transition &&
			header.number() <= ext.dao_hardfork_transition + 9 &&
			header.extra_data()[..] != b"dao-hard-fork"[..] {
			return Err(From::from(BlockError::ExtraDataOutOfBounds(OutOfBounds {
				min: None,
				max: None,
				found: 0
			})));
		}
	}

	Ok(())
}

/// A header verification step that should be done for new block headers, but not for uncles.
pub(crate) fn verify_header_time(header: &Header) -> Result<(), Error> {
	const ACCEPTABLE_DRIFT: Duration = Duration::from_secs(15);
	// this will resist overflow until `year 2037`
	let max_time = SystemTime::now() + ACCEPTABLE_DRIFT;
	let invalid_threshold = max_time + ACCEPTABLE_DRIFT * 9;
	let timestamp = CheckedSystemTime::checked_add(UNIX_EPOCH, Duration::from_secs(header.timestamp()))
		.ok_or(BlockError::TimestampOverflow)?;

	if timestamp > invalid_threshold {
		return Err(From::from(BlockError::InvalidTimestamp(OutOfBounds {
			max: Some(max_time),
			min: None,
			found: timestamp
		}.into())))
	}

	if timestamp > max_time {
		return Err(From::from(BlockError::TemporarilyInvalid(OutOfBounds {
			max: Some(max_time),
			min: None,
			found: timestamp
		}.into())))
	}

	Ok(())
}

/// Check header parameters against parent header.
fn verify_parent(header: &Header, parent: &Header, engine: &dyn Engine) -> Result<(), Error> {
	assert!(header.parent_hash().is_zero() || &parent.hash() == header.parent_hash(),
			"Parent hash should already have been verified; qed");

	if !engine.is_timestamp_valid(header.timestamp(), parent.timestamp()) {
		let now = SystemTime::now();
		let min = CheckedSystemTime::checked_add(now, Duration::from_secs(parent.timestamp().saturating_add(1)))
			.ok_or(BlockError::TimestampOverflow)?;
		let found = CheckedSystemTime::checked_add(now, Duration::from_secs(header.timestamp()))
			.ok_or(BlockError::TimestampOverflow)?;
		return Err(From::from(BlockError::InvalidTimestamp(OutOfBounds { max: None, min: Some(min), found }.into())))
	}
	if header.number() != parent.number() + 1 {
		return Err(From::from(BlockError::InvalidNumber(Mismatch {
			expected: parent.number() + 1,
			found: header.number()
		})));
	}

	if header.number() == 0 {
		return Err(BlockError::RidiculousNumber(OutOfBounds {
			min: Some(1),
			max: None,
			found: header.number()
		}).into());
	}
	if engine.gas_limit_override(header).is_none() {
		let gas_limit_divisor = engine.params().gas_limit_bound_divisor;
		let parent_gas_limit = *parent.gas_limit();
		let min_gas = parent_gas_limit - parent_gas_limit / gas_limit_divisor;
		let max_gas = parent_gas_limit + parent_gas_limit / gas_limit_divisor;
		if header.gas_limit() <= &min_gas || header.gas_limit() >= &max_gas {
			return Err(From::from(BlockError::InvalidGasLimit(OutOfBounds {
				min: Some(min_gas),
				max: Some(max_gas),
				found: *header.gas_limit()
			})));
		}
	}

	Ok(())
}

/// Verify block data against header: transactions root and uncles hash.
fn verify_block_integrity(block: &Unverified) -> Result<(), Error> {
	let block_rlp = Rlp::new(&block.bytes);
	let tx = block_rlp.at(1)?;
	let expected_root = ordered_trie_root(tx.iter().map(|r| r.as_raw()));
	if &expected_root != block.header.transactions_root() {
		return Err(BlockError::InvalidTransactionsRoot(Mismatch {
			expected: expected_root,
			found: *block.header.transactions_root(),
		}).into());
	}
	let expected_uncles = keccak(block_rlp.at(2)?.as_raw());
	if &expected_uncles != block.header.uncles_hash(){
		return Err(BlockError::InvalidUnclesHash(Mismatch {
			expected: expected_uncles,
			found: *block.header.uncles_hash(),
		}).into());
	}
	Ok(())
}

#[cfg(test)]
mod tests {
	use super::*;

	use std::collections::BTreeMap;
	use std::time::{SystemTime, UNIX_EPOCH};

	use ethereum_types::{H256, U256, Address};
	use parity_bytes::Bytes;
	use keccak_hash::keccak;
	use engine::Engine;
	use parity_crypto::publickey::{Random, Generator};
	use ethcore::test_helpers::{
		create_test_block_with_data, create_test_block, TestBlockChainClient
	};
	use common_types::{
		engines::params::CommonParams,
		errors::BlockError::*,
		transaction::{SignedTransaction, Transaction, UnverifiedTransaction, Action},
	};
	use triehash::ordered_trie_root;
	use machine::Machine;
	use null_engine::NullEngine;

	use crate::test_helpers::TestBlockChain;

	fn check_ok(result: Result<(), Error>) {
		result.unwrap_or_else(|e| panic!("Block verification failed: {:?}", e));
	}

	fn check_fail(result: Result<(), Error>, e: BlockError) {
		match result {
			Err(Error::Block(ref error)) if *error == e => (),
			Err(other) => panic!("Block verification failed.\nExpected: {:?}\nGot: {:?}", e, other),
			Ok(_) => panic!("Block verification failed.\nExpected: {:?}\nGot: Ok", e),
		}
	}

	fn check_fail_timestamp(result: Result<(), Error>, temp: bool) {
		let name = if temp { "TemporarilyInvalid" } else { "InvalidTimestamp" };
		match result {
			Err(Error::Block(BlockError::InvalidTimestamp(_))) if !temp => (),
			Err(Error::Block(BlockError::TemporarilyInvalid(_))) if temp => (),
			Err(other) => panic!("Block verification failed.\nExpected: {}\nGot: {:?}", name, other),
			Ok(_) => panic!("Block verification failed.\nExpected: {}\nGot: Ok", name),
		}
	}

	fn basic_test(bytes: &[u8], engine: &dyn Engine) -> Result<(), Error> {
		let unverified = Unverified::from_rlp(bytes.to_vec())?;
		verify_block_basic(&unverified, engine, true)
	}

	fn family_test<BC>(bytes: &[u8], engine: &dyn Engine, bc: &BC) -> Result<(), Error> where BC: BlockProvider {
		let block = Unverified::from_rlp(bytes.to_vec()).unwrap();
		let header = block.header;
		let transactions: Vec<_> = block.transactions
			.into_iter()
			.map(SignedTransaction::new)
			.collect::<Result<_,_>>()?;

		// TODO: client is really meant to be used for state query here by machine
		// additions that need access to state (tx filter in specific)
		// no existing tests need access to test, so having this not function
		// is fine.
		let client = TestBlockChainClient::default();
		let parent = bc.block_header_data(header.parent_hash())
			.ok_or(BlockError::UnknownParent(*header.parent_hash()))?
			.decode()?;

		let block = PreverifiedBlock {
			header,
			transactions,
			uncles: block.uncles,
		};

		let full_params = FullFamilyParams {
			block: &block,
			block_provider: bc as &dyn BlockProvider,
			client: &client,
		};
		verify_block_family(&block.header, &parent, engine, full_params)
	}

	fn unordered_test(bytes: &[u8], engine: &dyn Engine) -> Result<(), Error> {
		let un = Unverified::from_rlp(bytes.to_vec())?;
		verify_block_unordered(un, engine, false)?;
		Ok(())
	}

	#[test]
	fn test_verify_block_basic_with_invalid_transactions() {
		let spec = spec::new_test();
		let engine = &*spec.engine;

		let block = {
			let mut rlp = rlp::RlpStream::new_list(3);
			let mut header = Header::default();
			// that's an invalid transaction list rlp
			let invalid_transactions = vec![vec![0u8]];
			header.set_transactions_root(ordered_trie_root(&invalid_transactions));
			header.set_gas_limit(engine.min_gas_limit());
			rlp.append(&header);
			rlp.append_list::<Vec<u8>, _>(&invalid_transactions);
			rlp.append_raw(&rlp::EMPTY_LIST_RLP, 1);
			rlp.out()
		};

		assert!(basic_test(&block, engine).is_err());
	}

	#[test]
	fn test_verify_block() {
		use rlp::RlpStream;

		// Test against null_morden
		let mut good = Header::new();
		let spec = spec::new_test();
		let engine = &*spec.engine;

		let min_gas_limit = engine.min_gas_limit();
		good.set_gas_limit(min_gas_limit);
		good.set_timestamp(40);
		good.set_number(10);

		let keypair = Random.generate();

		let tr1 = Transaction {
			action: Action::Create,
			value: U256::from(0),
			data: Bytes::new(),
			gas: U256::from(30_000),
			gas_price: U256::from(40_000),
			nonce: U256::one()
		}.sign(keypair.secret(), None);

		let tr2 = Transaction {
			action: Action::Create,
			value: U256::from(0),
			data: Bytes::new(),
			gas: U256::from(30_000),
			gas_price: U256::from(40_000),
			nonce: U256::from(2)
		}.sign(keypair.secret(), None);

		let tr3 = Transaction {
			action: Action::Call(Address::from_low_u64_be(0x0)),
			value: U256::from(0),
			data: Bytes::new(),
			gas: U256::from(30_000),
			gas_price: U256::from(0),
			nonce: U256::zero(),
		}.null_sign(0);

		let good_transactions = [ tr1.clone(), tr2.clone() ];
		let eip86_transactions = [ tr3.clone() ];

		let diff_inc = U256::from(0x40);

		let mut parent6 = good.clone();
		parent6.set_number(6);
		let mut parent7 = good.clone();
		parent7.set_number(7);
		parent7.set_parent_hash(parent6.hash());
		parent7.set_difficulty(parent6.difficulty().clone() + diff_inc);
		parent7.set_timestamp(parent6.timestamp() + 10);
		let mut parent8 = good.clone();
		parent8.set_number(8);
		parent8.set_parent_hash(parent7.hash());
		parent8.set_difficulty(parent7.difficulty().clone() + diff_inc);
		parent8.set_timestamp(parent7.timestamp() + 10);

		let mut good_uncle1 = good.clone();
		good_uncle1.set_number(9);
		good_uncle1.set_parent_hash(parent8.hash());
		good_uncle1.set_difficulty(parent8.difficulty().clone() + diff_inc);
		good_uncle1.set_timestamp(parent8.timestamp() + 10);
		let mut ex = good_uncle1.extra_data().to_vec();
		ex.push(1u8);
		good_uncle1.set_extra_data(ex);

		let mut good_uncle2 = good.clone();
		good_uncle2.set_number(8);
		good_uncle2.set_parent_hash(parent7.hash());
		good_uncle2.set_difficulty(parent7.difficulty().clone() + diff_inc);
		good_uncle2.set_timestamp(parent7.timestamp() + 10);
		let mut ex = good_uncle2.extra_data().to_vec();
		ex.push(2u8);
		good_uncle2.set_extra_data(ex);

		let good_uncles = vec![ good_uncle1.clone(), good_uncle2.clone() ];
		let mut uncles_rlp = RlpStream::new();
		uncles_rlp.append_list(&good_uncles);
		let good_uncles_hash = keccak(uncles_rlp.as_raw());
		let good_transactions_root = ordered_trie_root(good_transactions.iter().map(|t| ::rlp::encode::<UnverifiedTransaction>(t)));
		let eip86_transactions_root = ordered_trie_root(eip86_transactions.iter().map(|t| ::rlp::encode::<UnverifiedTransaction>(t)));

		let mut parent = good.clone();
		parent.set_number(9);
		parent.set_timestamp(parent8.timestamp() + 10);
		parent.set_parent_hash(parent8.hash());
		parent.set_difficulty(parent8.difficulty().clone() + diff_inc);

		good.set_parent_hash(parent.hash());
		good.set_difficulty(parent.difficulty().clone() + diff_inc);
		good.set_timestamp(parent.timestamp() + 10);

		let mut bc = TestBlockChain::new();
		bc.insert(create_test_block(&good));
		bc.insert(create_test_block(&parent));
		bc.insert(create_test_block(&parent6));
		bc.insert(create_test_block(&parent7));
		bc.insert(create_test_block(&parent8));

		check_ok(basic_test(&create_test_block(&good), engine));

		let mut bad_header = good.clone();
		bad_header.set_transactions_root(eip86_transactions_root.clone());
		bad_header.set_uncles_hash(good_uncles_hash.clone());

		let mut header = good.clone();
		header.set_transactions_root(good_transactions_root.clone());
		header.set_uncles_hash(good_uncles_hash.clone());
		check_ok(basic_test(&create_test_block_with_data(&header, &good_transactions, &good_uncles), engine));

		header.set_gas_limit(min_gas_limit - 1);
		check_fail(basic_test(&create_test_block(&header), engine),
			InvalidGasLimit(OutOfBounds { min: Some(min_gas_limit), max: None, found: header.gas_limit().clone() }));

		header = good.clone();
		header.set_number(BlockNumber::max_value());
		check_fail(basic_test(&create_test_block(&header), engine),
			RidiculousNumber(OutOfBounds { max: Some(BlockNumber::max_value()), min: None, found: header.number() }));

		header = good.clone();
		let gas_used = header.gas_limit().clone() + 1;
		header.set_gas_used(gas_used);
		check_fail(basic_test(&create_test_block(&header), engine),
			TooMuchGasUsed(OutOfBounds { max: Some(header.gas_limit().clone()), min: None, found: header.gas_used().clone() }));

		header = good.clone();
		let mut ex = header.extra_data().to_vec();
		ex.resize(engine.maximum_extra_data_size() + 1, 0u8);
		header.set_extra_data(ex);
		check_fail(basic_test(&create_test_block(&header), engine),
			ExtraDataOutOfBounds(OutOfBounds { max: Some(engine.maximum_extra_data_size()), min: None, found: header.extra_data().len() }));

		header = good.clone();
		let mut ex = header.extra_data().to_vec();
		ex.resize(engine.maximum_extra_data_size() + 1, 0u8);
		header.set_extra_data(ex);
		check_fail(basic_test(&create_test_block(&header), engine),
			ExtraDataOutOfBounds(OutOfBounds { max: Some(engine.maximum_extra_data_size()), min: None, found: header.extra_data().len() }));

		header = good.clone();
		header.set_uncles_hash(good_uncles_hash.clone());
		check_fail(basic_test(&create_test_block_with_data(&header, &good_transactions, &good_uncles), engine),
			InvalidTransactionsRoot(Mismatch { expected: good_transactions_root.clone(), found: header.transactions_root().clone() }));

		header = good.clone();
		header.set_transactions_root(good_transactions_root.clone());
		check_fail(basic_test(&create_test_block_with_data(&header, &good_transactions, &good_uncles), engine),
			InvalidUnclesHash(Mismatch { expected: good_uncles_hash.clone(), found: header.uncles_hash().clone() }));

		check_ok(family_test(&create_test_block(&good), engine, &bc));
		check_ok(family_test(&create_test_block_with_data(&good, &good_transactions, &good_uncles), engine, &bc));

		header = good.clone();
		header.set_parent_hash(H256::random());
		check_fail(family_test(&create_test_block_with_data(&header, &good_transactions, &good_uncles), engine, &bc),
			UnknownParent(header.parent_hash().clone()));

		header = good.clone();
		header.set_timestamp(10);
		check_fail_timestamp(family_test(&create_test_block_with_data(&header, &good_transactions, &good_uncles), engine, &bc), false);

		header = good.clone();
		// will return `BlockError::TimestampOverflow` when timestamp > `i32::max_value()`
		header.set_timestamp(i32::max_value() as u64);
		check_fail_timestamp(basic_test(&create_test_block_with_data(&header, &good_transactions, &good_uncles), engine), false);

		header = good.clone();
		header.set_timestamp(SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() + 20);
		check_fail_timestamp(basic_test(&create_test_block_with_data(&header, &good_transactions, &good_uncles), engine), true);

		header = good.clone();
		header.set_timestamp(SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() + 10);
		header.set_uncles_hash(good_uncles_hash.clone());
		header.set_transactions_root(good_transactions_root.clone());
		check_ok(basic_test(&create_test_block_with_data(&header, &good_transactions, &good_uncles), engine));

		header = good.clone();
		header.set_number(9);
		check_fail(family_test(&create_test_block_with_data(&header, &good_transactions, &good_uncles), engine, &bc),
			InvalidNumber(Mismatch { expected: parent.number() + 1, found: header.number() }));

		header = good.clone();
		let mut bad_uncles = good_uncles.clone();
		bad_uncles.push(good_uncle1.clone());
		check_fail(family_test(&create_test_block_with_data(&header, &good_transactions, &bad_uncles), engine, &bc),
			TooManyUncles(OutOfBounds { max: Some(engine.maximum_uncle_count(header.number())), min: None, found: bad_uncles.len() }));

		header = good.clone();
		bad_uncles = vec![ good_uncle1.clone(), good_uncle1.clone() ];
		check_fail(family_test(&create_test_block_with_data(&header, &good_transactions, &bad_uncles), engine, &bc),
			DuplicateUncle(good_uncle1.hash()));

		header = good.clone();
		header.set_gas_limit(0.into());
		header.set_difficulty("0000000000000000000000000000000000000000000000000000000000020000".parse::<U256>().unwrap());
		match family_test(&create_test_block(&header), engine, &bc) {
			Err(Error::Block(InvalidGasLimit(_))) => {},
			Err(_) => { panic!("should be invalid difficulty fail"); },
			_ => { panic!("Should be error, got Ok"); },
		}

		// TODO: some additional uncle checks
	}

	#[test]
	fn dust_protection() {
		let mut params = CommonParams::default();
		params.dust_protection_transition = 0;
		params.nonce_cap_increment = 2;

		let mut header = Header::default();
		header.set_number(1);

		let keypair = Random.generate();
		let bad_transactions: Vec<_> = (0..3).map(|i| Transaction {
			action: Action::Create,
			value: U256::zero(),
			data: Vec::new(),
			gas: 0.into(),
			gas_price: U256::zero(),
			nonce: i.into(),
		}.sign(keypair.secret(), None)).collect();

		let good_transactions = [bad_transactions[0].clone(), bad_transactions[1].clone()];

		let machine = Machine::regular(params, BTreeMap::new());
		let engine = NullEngine::new(Default::default(), machine);
		check_fail(unordered_test(&create_test_block_with_data(&header, &bad_transactions, &[]), &engine), TooManyTransactions(keypair.address()));
		unordered_test(&create_test_block_with_data(&header, &good_transactions, &[]), &engine).unwrap();
	}
}
