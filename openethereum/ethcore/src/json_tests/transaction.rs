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

use std::path::Path;
use super::test_common::*;
use test_helpers::EvmTestClient;
use ethjson;
use rlp::Rlp;
use types::{
	header::Header,
	errors::EthcoreError as Error,
	transaction::UnverifiedTransaction
};
use machine::transaction_ext::Transaction;

#[allow(dead_code)]
fn do_json_test<H: FnMut(&str, HookType)>(path: &Path, json_data: &[u8], start_stop_hook: &mut H) -> Vec<String> {
	// Block number used to run the tests.
	// Make sure that all the specified features are activated.
	const BLOCK_NUMBER: u64 = 0x6ffffffffffffe;

	let tests = ethjson::test_helpers::transaction::Test::load(json_data)
		.expect(&format!("Could not parse JSON transaction test data from {}", path.display()));
	let mut failed = Vec::new();
	for (name, test) in tests.into_iter() {
		start_stop_hook(&name, HookType::OnStart);

		for (spec_name, result) in test.post_state {
			let spec = match EvmTestClient::fork_spec_from_json(&spec_name) {
				Some(spec) => spec,
				None => {
					println!("   - {} | {:?} Ignoring tests because of missing spec", name, spec_name);
					continue;
				}
			};

			let mut fail_unless = |cond: bool, title: &str| if !cond {
				failed.push(format!("{}-{:?}", name, spec_name));
				println!("Transaction failed: {:?}-{:?}: {:?}", name, spec_name, title);
			};

			let rlp: Vec<u8> = test.rlp.clone().into();
			let res = Rlp::new(&rlp)
				.as_val()
				.map_err(Error::from)
				.and_then(|t: UnverifiedTransaction| {
					let mut header: Header = Default::default();
					// Use high enough number to activate all required features.
					header.set_number(BLOCK_NUMBER);

					let minimal = t.gas_required(&spec.engine.schedule(header.number())).into();
					if t.gas < minimal {
						return Err(::types::transaction::Error::InsufficientGas {
							minimal, got: t.gas,
						}.into());
					}
					spec.engine.verify_transaction_basic(&t, &header)?;
					Ok(t.verify_unordered()?)
				});

			match (res, result.hash, result.sender) {
				(Ok(t), Some(hash), Some(sender)) => {
					fail_unless(t.sender() == sender.into(), "sender mismatch");
					fail_unless(t.hash() == hash.into(), "hash mismatch");
				},
				(Err(_), None, None) => {},
				data => {
					fail_unless(
						false,
						&format!("Validity different: {:?}", data)
					);
				}
			}
		}

		start_stop_hook(&name, HookType::OnStop);
	}

	for f in &failed {
		println!("FAILED: {:?}", f);
	}
	failed
}

declare_test!{TransactionTests_ttAddress, "TransactionTests/ttAddress"}
declare_test!{TransactionTests_ttData, "TransactionTests/ttData"}
declare_test!{TransactionTests_ttGasLimit, "TransactionTests/ttGasLimit"}
declare_test!{TransactionTests_ttGasPrice, "TransactionTests/ttGasPrice"}
declare_test!{TransactionTests_ttNonce, "TransactionTests/ttNonce"}
declare_test!{TransactionTests_ttRSValue, "TransactionTests/ttRSValue"}
declare_test!{TransactionTests_ttSignature, "TransactionTests/ttSignature"}
declare_test!{TransactionTests_ttValue, "TransactionTests/ttValue"}
declare_test!{TransactionTests_ttVValue, "TransactionTests/ttVValue"}
declare_test!{TransactionTests_ttWrongRLP, "TransactionTests/ttWrongRLP"}
