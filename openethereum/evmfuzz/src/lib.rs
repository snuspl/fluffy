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

#[macro_use]
extern crate lazy_static;

extern crate bitreader;
extern crate protobuf;
extern crate rand;
extern crate rand_xorshift;

extern crate strum;
#[macro_use]
extern crate strum_macros;


use std::sync::Arc;
use std::{fmt, fs};
use std::path::PathBuf;

use parity_bytes::{Bytes, ToPretty};
use docopt::Docopt;
use ethereum_types::{H160, U256, Address, H256};
use ethcore::{json_tests};
use spec;
use serde::Deserialize;
use vm::{ActionParams, ActionType};

mod fuzzer;

use rand::{SeedableRng, Rng};
use rand::distributions::{Standard, Distribution};

use evm::{Instruction, CostType};
use common_types::transaction;
use common_types::transaction::{SignedTransaction, UnverifiedTransaction, Transaction};
use vm::EnvInfo;
use vm::Schedule;
use std::str::FromStr;

use rustc_hex::{ToHex, FromHex};
use pod::PodState;
use pod::PodAccount;

use std::collections::{BTreeMap, HashMap, HashSet};

use ethcore::test_helpers::{EvmTestClient, EvmTestError, TransactErr, TransactSuccess, TrieSpec};

use strum::IntoEnumIterator;
use std::iter::FromIterator;

use protobuf::{Message, RepeatedField};

lazy_static! {
    static ref SPEC: spec::Spec = spec::new_foundation(&String::new());
    static ref BLOCK_CANDIDATE_LIST: Vec<u64> = get_block_candidate_list();
    static ref VALID_INSTRUCTION_LIST: Vec<Instruction> = create_valid_instruction_list();
    static ref BUILTIN_ADDRS: Vec<String> = get_builtins();
}

static GENESIS_ADDRESS: &str = "2adc25665018aa1fe0e6bc666dac8fc2697ff9ba";

#[derive(Debug)]
enum MutationTarget {
	Block,
	Tx,
	Constructor,
	Contract,
}
impl Distribution<MutationTarget> for Standard {
	fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> MutationTarget {
		match rng.gen_range(0, 10) {
			0 => MutationTarget::Block,          // 10%
			1 => MutationTarget::Tx,             // 10%
			2...5 => MutationTarget::Constructor, // 40%
			_ => MutationTarget::Contract,       // 40%
		}
	}
}

#[derive(Debug)]
enum OpcodeMutation {
	Add,
	Delete,
	Mutate,
	Copy, // src offset, dst offset, ...
	Clone,
}
impl Distribution<OpcodeMutation> for Standard {
	fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> OpcodeMutation {
		match rng.gen_range(0, 5) {
			0 => OpcodeMutation::Add,          // 20%
			1 => OpcodeMutation::Delete,       // 20%
			2 => OpcodeMutation::Mutate,       // 20%
			3 => OpcodeMutation::Copy,         // 20%
			_ => OpcodeMutation::Clone,        // 20%
		}
	}
}

#[derive(Debug)]
enum BlockMutation {
	AddBlock,
	DeleteBlock,
	CopyBlock,
	CloneBlock,
	MutateBlockNumber,
	MutateTimestamp,
	MutateDifficulty,
}
impl Distribution<BlockMutation> for Standard {
	fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> BlockMutation {
		match rng.gen_range(0, 20) {
			0 => BlockMutation::AddBlock,
			1 => BlockMutation::DeleteBlock,
			2 => BlockMutation::CopyBlock,
			3 => BlockMutation::CloneBlock,
			4 => BlockMutation::MutateTimestamp,
			5 => BlockMutation::MutateDifficulty,
			_ => BlockMutation::MutateBlockNumber, // 75% (6~20)
		}
	}
}

#[derive(Debug)]
enum TxMutation {
	AddCreateTx,
	AddCallTx,
	DeleteTx,
	CopyTx,
	CloneTx,
	MutateGas,
	MutateVal,
	MutateData,
	MutateReceiver,
}
impl Distribution<TxMutation> for Standard {
	fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> TxMutation {
		match rng.gen_range(0, 20) {
			0 => TxMutation::AddCreateTx,
			1 => TxMutation::AddCallTx,
			2 => TxMutation::DeleteTx,
			3 => TxMutation::CopyTx,
			4 => TxMutation::CloneTx,
			5 => TxMutation::MutateVal,
			6 => TxMutation::MutateData,
			7...13 => TxMutation::MutateGas,
			_ => TxMutation::MutateReceiver,
		}
	}
}

#[derive(Debug)]
enum DataMutation {
	Add,
	Delete,
	Copy,
	Mutate,
	Clone,
}
impl Distribution<DataMutation> for Standard {
	fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> DataMutation {
		match rng.gen_range(0, 5) {
			0 => DataMutation::Add,
			1 => DataMutation::Delete,
			2 => DataMutation::Copy,
			3 => DataMutation::Clone,
			_ => DataMutation::Mutate,
		}
	}
}

fn initial_protobuf() -> fuzzer::Fuzzed {
	let mut fuzzed = fuzzer::Fuzzed::new();
	fuzzed.set_is_debug_mode(false);

	let builtin_addrs_local = &BUILTIN_ADDRS.clone();
	for builtin_addr in builtin_addrs_local {
		fuzzed.mut_builtin_addrs().push(builtin_addr.to_string());
	}

	{
		let mut genesis_account = fuzzer::EOA::new();

		// Constants
		genesis_account.set_address(GENESIS_ADDRESS.to_string());
		genesis_account.set_nonce(0);
		genesis_account.set_balance(std::u64::MAX); // Constant (large value), to avoid ExecutionError

		// DONE!
		fuzzed.set_genesis_account(genesis_account);
	}

	fuzzed.set_blocks(protobuf::RepeatedField::new());

	return fuzzed;
}

pub fn convert_to_proto(fuzz_data: &[u8]) -> Option<fuzzer::Fuzzed> {
	match protobuf::parse_from_bytes::<fuzzer::Fuzzed>(fuzz_data) {
		Ok(fuzzed) => Some(fuzzed),
		Err(_) => None,
	}
}

pub fn do_fuzz_mutate(bytes: &mut Vec<u8>, max_size: usize, seed: u32) {
	let mut rng: rand_xorshift::XorShiftRng = SeedableRng::seed_from_u64(seed.into());

	match protobuf::parse_from_bytes::<fuzzer::Fuzzed>(bytes.as_slice()) {
		Ok(mut fuzzed) => {
			let mt: MutationTarget = rng.gen();

			let fuzzed_copy = fuzzed.clone();

			if fuzzed_copy.get_blocks().iter()
				.any(|b| b.get_transactions().is_empty()) {
				panic!("COPY FUZZED: {:?}", fuzzed_copy);
			}

			let mutated_fuzzed = match mt {
				MutationTarget::Block => mutate_block(fuzzed, &mut rng),
				MutationTarget::Tx => mutate_tx(fuzzed, &mut rng),
				MutationTarget::Constructor => mutate_opcode(fuzzed, true, &mut rng),
				MutationTarget::Contract => mutate_opcode(fuzzed, false, &mut rng),
			};


			if mutated_fuzzed.get_blocks().iter()
				.any(|b| b.get_transactions().is_empty()) {
				panic!("FUZZED - before: {:?} / after: {:?}", fuzzed_copy, mutated_fuzzed);
			}

			bytes.clear();
			bytes.extend(mutated_fuzzed.write_to_bytes().unwrap());

			match protobuf::parse_from_bytes::<fuzzer::Fuzzed>(bytes.as_slice()) {
				Ok(ser_de_mutated_fuzzed) => {
					assert_eq!(mutated_fuzzed, ser_de_mutated_fuzzed);
				},
				_ => (),
			}
		},
        Err(err) => {
			bytes.clear();
			bytes.extend(initial_protobuf().write_to_bytes().unwrap());
		},
	}
}

fn mutate_data<R: Rng + ?Sized>(fuzzed: &fuzzer::Fuzzed,
								target_tx: &mut fuzzer::Transaction,
								rng: &mut R) {
	let dm: DataMutation = rng.gen();
	match dm {
		DataMutation::Add => {
			let new_byte: u8 = rng.gen();
			let offset = pick_offset_for_insertion(target_tx.get_call_tx_data(), rng);
			target_tx.mut_call_tx_data().insert(offset, new_byte);
		},
		DataMutation::Delete => {
			match pick_offset(target_tx.get_call_tx_data(), rng) {
				Some(offset) => {
					target_tx.mut_call_tx_data().remove(offset);
				},
				None => (),
			}
		},
		DataMutation::Mutate => {
			match pick_offset(target_tx.get_call_tx_data(), rng) {
				Some(offset) => {
					let new_byte: u8 = rng.gen();
					std::mem::replace(&mut target_tx.mut_call_tx_data()[offset], new_byte);
				},
				None => (),
			}
		},
		DataMutation::Copy => {
			let all_txs: Vec<&fuzzer::Transaction> = fuzzed
				.get_blocks()
				.iter()
				.flat_map(|block| block.get_transactions())
				.collect();

			match pick_and_copy(&all_txs, rng) {
				Some(src_tx) => {
					if !src_tx.get_is_create_tx() {
						target_tx.set_call_tx_data(src_tx.get_call_tx_data().to_vec());
					} else {
						if rng.gen_bool(0.5) {
							target_tx.set_call_tx_data(src_tx.get_create_tx_contract().to_vec());
						} else {
							target_tx.set_call_tx_data(src_tx.get_create_tx_constructor().to_vec());
						}
					}
					()
				},
				None => (),
			}
		},
		DataMutation::Clone => {
			let all_txs: Vec<&fuzzer::Transaction> = fuzzed
				.get_blocks()
				.iter()
				.flat_map(|block| block.get_transactions())
				.collect();

			match pick_and_copy(&all_txs, rng) {
				Some(src_tx) => {
					let src_bytes;
					if !src_tx.get_is_create_tx() {
						src_bytes = src_tx.get_call_tx_data().to_vec();
					} else {
						if rng.gen_bool(0.5) {
							src_bytes = src_tx.get_create_tx_contract().to_vec();
						} else {
							src_bytes = src_tx.get_create_tx_constructor().to_vec();
						}
					}

					let dst_offset = pick_offset_for_insertion(target_tx.get_call_tx_data(), rng);

					target_tx.mut_call_tx_data().splice(
						dst_offset..dst_offset,
						src_bytes);
					()
				},
				None => (),
			}

		},
	}
}

fn mutate_opcode<R: Rng + ?Sized>(fuzzed: fuzzer::Fuzzed,
								  is_constructor: bool,
								  rng: &mut R) -> fuzzer::Fuzzed {
	let mut result = fuzzed.clone();

	let block_indices: Vec<usize> = fuzzed.get_blocks().iter()
		.enumerate()
		.filter(|&(index, b)| b.get_transactions().iter().any(|t| t.get_is_create_tx()))
		.map(|(index, _)| index)
		.collect();

	match pick_and_copy(&block_indices, rng) {
		Some(block_offset) => {
			let target_block = fuzzed.get_blocks().get(block_offset).unwrap();
			let block_num = target_block.get_number();

			let tx_indices: Vec<usize> = target_block.get_transactions().iter()
				.enumerate()
				.filter(|&(index, tx)| tx.get_is_create_tx())
				.map(|(index, _)| index)
				.collect();

			match pick_and_copy(&tx_indices, rng) {
				Some(tx_offset) => {
					let target_tx = target_block.get_transactions().get(tx_offset).unwrap();

					let mut opcodes_temp_copy: Vec<u8> = match is_constructor {
						true => target_tx.get_create_tx_constructor().to_vec(),
						false => target_tx.get_create_tx_contract().to_vec(),
					};

					let om: OpcodeMutation = rng.gen();
					let valid_instructions = VALID_INSTRUCTION_LIST.as_slice();

					match om {
						OpcodeMutation::Add => {
							let offset = pick_offset_for_insertion(opcodes_temp_copy.as_slice(), rng);
							let new_op = pick_and_copy(valid_instructions, rng).unwrap();
							opcodes_temp_copy.insert(offset, new_op as u8);
						},
						OpcodeMutation::Delete => {
							match pick_offset(opcodes_temp_copy.as_slice(), rng) {
								Some(offset) => {
									opcodes_temp_copy.remove(offset);
									()
								},
								_ => (),
							}
						},
						OpcodeMutation::Mutate => {
							match pick_offset(opcodes_temp_copy.as_slice(), rng) {
								Some(offset) => {
									let new_op = pick_and_copy(valid_instructions, rng).unwrap();
									std::mem::replace(&mut opcodes_temp_copy[offset], new_op as u8);
									()
								},
								None => ()
							}
						},
						OpcodeMutation::Copy => {
							let src_block_index = pick_and_copy(&block_indices, rng).unwrap();
							let src_tx_candidates: Vec<&fuzzer::Transaction> = fuzzed.get_blocks().get(src_block_index).unwrap()
								.get_transactions()
								.iter()
								.filter(|&tx| tx.get_is_create_tx())
								.collect();
							let src_tx = pick_and_copy(&src_tx_candidates, rng).unwrap();

							if rng.gen_bool(0.5) {
								opcodes_temp_copy = src_tx.get_create_tx_contract().to_vec();
							} else {
								opcodes_temp_copy = src_tx.get_create_tx_constructor().to_vec();
							}
						},
						OpcodeMutation::Clone => {
							let src_block_index = pick_and_copy(&block_indices, rng).unwrap();
							let src_tx_candidates: Vec<&fuzzer::Transaction> = fuzzed.get_blocks().get(src_block_index).unwrap()
								.get_transactions()
								.iter()
								.filter(|&tx| tx.get_is_create_tx())
								.collect();
							let src_tx = pick_and_copy(&src_tx_candidates, rng).unwrap();

							let dst_offset = pick_offset_for_insertion(opcodes_temp_copy.as_slice(), rng);

							if rng.gen_bool(0.5) {
								opcodes_temp_copy.splice(
									dst_offset..dst_offset,
									src_tx.get_create_tx_constructor().to_vec());
							} else {
								opcodes_temp_copy.splice(
									dst_offset..dst_offset,
									src_tx.get_create_tx_contract().to_vec());
							}
						},
					}

					let block_num = target_block.get_number();

					let result_target_block = result
						.mut_blocks().get_mut(block_offset).unwrap();
					let result_target_tx = result_target_block
						.mut_transactions().get_mut(tx_offset).unwrap();

					if is_constructor {
						result_target_tx.set_create_tx_constructor(opcodes_temp_copy.clone());
					} else {
						result_target_tx.set_create_tx_contract(opcodes_temp_copy.clone());
					}

					update_create_tx_postfixes(result_target_tx);
					avoid_not_enough_base_gas(result_target_tx, block_num);
				},
				None => (),
			}

		},
		None => (),
	}

	return result;
}

fn mutate_block<R: Rng + ?Sized>(fuzzed: fuzzer::Fuzzed, rng: &mut R) -> fuzzer::Fuzzed {
	let mut result = fuzzed.clone();

	let bm: BlockMutation = rng.gen();
	match bm {
		BlockMutation::AddBlock => {
			match pick_and_copy(&get_remaining_block_nums(&fuzzed), rng) {
				Some(block_num) => {
					match pick_timestamp(&fuzzed, block_num, rng) {
						Some(timestamp) => {
							let mut new_block = fuzzer::Block::new();
							new_block.set_timestamp(timestamp);
							new_block.set_number(block_num);
							new_block.set_difficulty(rng.next_u64());

							new_block.set_gas_limit(std::u64::MAX); 
							new_block.set_author(GENESIS_ADDRESS.to_string()); 

							new_block.mut_transactions().push(create_new_tx(true, block_num, rng));

							result.mut_blocks().push(new_block);
						},
						None => (),
					}
				},
				None => (),
			}
		},
		BlockMutation::DeleteBlock => {
			match pick_offset(fuzzed.get_blocks(), rng) {
				Some(offset) => {
					result.mut_blocks().remove(offset);
					()
				},
				None => (),
			}
		},
		BlockMutation::CopyBlock => {
			match pick_and_copy(&get_remaining_block_nums(&fuzzed), rng) {
				Some(block_num) => {
					match pick_timestamp(&fuzzed, block_num, rng) {
						Some(timestamp) => {
							if !fuzzed.get_blocks().is_empty() {
								let mut src_clone = pick_and_copy(fuzzed.get_blocks(), rng).unwrap().clone();
								src_clone.set_number(block_num);
								src_clone.set_timestamp(timestamp);

								let dst_offset = pick_offset(fuzzed.get_blocks(), rng).unwrap();
								result.mut_blocks().as_mut_slice()[dst_offset] = src_clone;
							}
						},
						None => (),
					}

				},
				None => (),
			}
		},
		BlockMutation::CloneBlock => {
			match pick_and_copy(&get_remaining_block_nums(&fuzzed), rng) {
				Some(block_num) => {
					match pick_timestamp(&fuzzed, block_num, rng) {
						Some(timestamp) => {
							if !fuzzed.get_blocks().is_empty() {
								let mut src_clone = pick_and_copy(fuzzed.get_blocks(), rng).unwrap().clone();
								src_clone.set_number(block_num);
								src_clone.set_timestamp(timestamp);

								result.mut_blocks().push(src_clone);
							}
						},
						None => (),
					}

				},
				None => (),
			}
		},
		BlockMutation::MutateBlockNumber => {
			match pick_offset(fuzzed.get_blocks(), rng) {
				Some(offset) => {
					let dst = result.mut_blocks().get_mut(offset).unwrap();

					match pick_and_copy(&get_remaining_block_nums(&fuzzed), rng) {
						Some(block_num) => {
							match pick_timestamp(&fuzzed, block_num, rng) {
								Some(timestamp) => {
									dst.set_number(block_num);
									dst.set_timestamp(timestamp); 
								},
								None => (),
							}
						}
						None => (),
					}



				},
				None => (),
			}
		},
		BlockMutation::MutateTimestamp => {
			match pick_offset(fuzzed.get_blocks(), rng) {
				Some(offset) => {
					let dst = result.mut_blocks().get_mut(offset).unwrap();

					match pick_timestamp(&fuzzed, dst.get_number(), rng) {
						Some(timestamp) => dst.set_timestamp(timestamp),
						None => (),
					}
				},
				None => (),
			}
		},
		BlockMutation::MutateDifficulty => {
			match pick_offset(fuzzed.get_blocks(), rng) {
				Some(offset) => {
					let dst = result.mut_blocks().get_mut(offset).unwrap();

					if rng.gen_bool(0.5) {
						let src = pick_and_copy(fuzzed.get_blocks(), rng).unwrap();
						dst.set_difficulty(src.get_difficulty());
					} else {
						dst.set_difficulty(rng.next_u64());
					}
				},
				None => (),
			}

		},
	}

	return result;
}

fn update_create_tx_postfixes(t: &mut fuzzer::Transaction) {
	t.set_create_tx_constructor_postfix(new_create_tx_constructor_postfix(
		t.get_create_tx_constructor().len(),
		t.get_create_tx_contract().len()));

	t.set_create_tx_contract_postfix(new_create_tx_contract_postfix(
		t.get_create_tx_constructor().len(),
		t.get_create_tx_contract().len()));
}

fn avoid_not_enough_base_gas(t: &mut fuzzer::Transaction, block_num: u64) {
	let required = gas_required_for(t.get_is_create_tx(), get_data_bytes(t).as_slice(), block_num);
	if t.get_gas() < required {
		t.set_gas(required);
	}
}


fn do_PUSH2(v: &mut Vec<u8>, num: usize) {
	let bytes: [u8; 8] = num.to_be_bytes(); 

	v.push(bytes[6]);
	v.push(bytes[7]);
}

fn new_create_tx_constructor_postfix(constructor_size: usize, contract_size: usize) -> Vec<u8> {
	let mut v: Vec<u8> = Vec::new();
	v.push(Instruction::PUSH2 as u8);
	do_PUSH2(&mut v, contract_size + constructor_size + 4);
	v.push(Instruction::JUMP as u8);
	return v;
}

fn new_create_tx_contract_postfix(constructor_size: usize, contract_size: usize) -> Vec<u8> {
	let code_begin_offset = constructor_size + 4;

	let mut v = Vec::new();
	v.push(Instruction::JUMPDEST as u8);

	v.push(Instruction::PUSH2 as u8);

	v.push(Instruction::PUSH2 as u8);
	do_PUSH2(&mut v, code_begin_offset); 

	v.push(Instruction::PUSH2 as u8);
	do_PUSH2(&mut v, code_begin_offset); 

	v.push(Instruction::CODECOPY as u8);

	v.push(Instruction::PUSH2 as u8);
	do_PUSH2(&mut v, contract_size); 
	v.push(Instruction::PUSH2 as u8);
	do_PUSH2(&mut v, code_begin_offset); 
	v.push(Instruction::RETURN as u8);

	return v;
}

fn create_new_tx<R: Rng + ?Sized>(is_create: bool, block_num: u64, rng: &mut R) -> fuzzer::Transaction {
	let mut tx = fuzzer::Transaction::new();

	tx.set_sender(GENESIS_ADDRESS.to_string()); 
	tx.set_gas_price(1); 
	tx.set_value(rng.next_u64());

	tx.set_is_create_tx(is_create);
	if is_create {
		tx.set_create_tx_constructor("".into());
		tx.set_create_tx_contract("".into());
		update_create_tx_postfixes(&mut tx);
	} else {
		tx.set_call_tx_data("".into());
		tx.set_receiver(rng.next_u32());
	}

	avoid_not_enough_base_gas(&mut tx, block_num);

	return tx;
}

fn get_data_bytes(tx: &fuzzer::Transaction) -> Vec<u8> {
	return match tx.get_is_create_tx() {
		true =>  [tx.get_create_tx_constructor(),
			tx.get_create_tx_constructor_postfix(),
			tx.get_create_tx_contract(),
			tx.get_create_tx_contract_postfix()].concat().to_vec(),
		false => tx.get_call_tx_data().to_vec(),
	};
}

fn mutate_tx<R: Rng + ?Sized>(fuzzed: fuzzer::Fuzzed, rng: &mut R) -> fuzzer::Fuzzed {
	let mut result = fuzzed.clone();

	match pick_offset(fuzzed.get_blocks(), rng) {
		Some(block_offset) =>  {
			let target_block = fuzzed.get_blocks().get(block_offset).unwrap();
			let result_target_block = result.mut_blocks().get_mut(block_offset).unwrap();

			let tm: TxMutation = rng.gen();
			match tm {
				TxMutation::AddCreateTx => {
					let new_tx = create_new_tx(true,target_block.get_number(), rng);
					let target_txs = target_block.get_transactions();
					let target_offset = pick_offset_for_insertion(target_txs, rng);

					result_target_block.mut_transactions().insert(target_offset, new_tx);
				},
				TxMutation::AddCallTx => {
					let new_tx = create_new_tx(false,target_block.get_number(), rng);
					let target_txs = target_block.get_transactions();
					let target_offset = pick_offset_for_insertion(target_txs, rng);

					result_target_block.mut_transactions().insert(target_offset, new_tx);
				},
				TxMutation::DeleteTx => {
					let target_txs = target_block.get_transactions();
					let offset = pick_offset(target_txs, rng).unwrap();
					result_target_block.mut_transactions().remove(offset);

					if target_txs.len() == 1 {
						result.mut_blocks().remove(block_offset);
					}
				},
				TxMutation::CopyTx => {
					let src_block = pick_and_copy(fuzzed.get_blocks(), rng).unwrap();
					let src_tx = pick_and_copy(src_block.get_transactions(), rng).unwrap();

					let target_txs = target_block.get_transactions();
					let offset = pick_offset(target_txs, rng).unwrap();

					result_target_block.mut_transactions().as_mut_slice()[offset] = src_tx.clone();
				},
				TxMutation::CloneTx => {
					let src_block = pick_and_copy(fuzzed.get_blocks(), rng).unwrap();
					let src_tx = pick_and_copy(src_block.get_transactions(), rng).unwrap();

					let target_txs = target_block.get_transactions();
					let offset = pick_offset_for_insertion(target_txs, rng);
					result_target_block.mut_transactions().insert(offset, src_tx.clone());
				},
				TxMutation::MutateGas => {
					match pick_offset(target_block.get_transactions(), rng) {
						Some(tx_offset) => {
							let mut result_target_tx = result_target_block.mut_transactions().get_mut(tx_offset).unwrap();

							if rng.gen_bool(0.5) {
								let src_block = pick_and_copy(fuzzed.get_blocks(), rng).unwrap();
								let src_tx = pick_and_copy(src_block.get_transactions(), rng).unwrap();
								result_target_tx.set_gas(src_tx.get_gas());
							} else {
								let base_gas = gas_required_for(
									result_target_tx.get_is_create_tx(),
									get_data_bytes(result_target_tx).as_slice(),
									target_block.get_number());

								let largest_gas_cost_create = 32_000;
								let gas_cost_multiplier = 50;

								let reasonable_gas = base_gas + rng.gen_range(
									0,
									largest_gas_cost_create * gas_cost_multiplier);
								result_target_tx.set_gas(reasonable_gas);
							}
						},
						None => (),
					}
				},
				TxMutation::MutateVal => {
					match pick_offset(target_block.get_transactions(), rng) {
						Some(tx_offset) => {
							let mut result_target_tx = result_target_block.mut_transactions().get_mut(tx_offset).unwrap();

							if rng.gen_bool(0.5) {
								let src_block = pick_and_copy(fuzzed.get_blocks(), rng).unwrap();
								let src_tx = pick_and_copy(src_block.get_transactions(), rng).unwrap();
								result_target_tx.set_value(src_tx.get_value());
							} else {
								if rng.gen_bool(0.5) {
									result_target_tx.set_value(0);
								} else {
									if rng.gen_bool(0.5) {
										result_target_tx.set_value(1);
									} else {
										result_target_tx.set_value(rng.next_u64());
									}
								}
							}

						},
						None => (),
					}
				},
				TxMutation::MutateData => {
					match pick_offset(target_block.get_transactions(), rng) {
						Some(tx_offset) => {
							let result_target_tx = result_target_block.mut_transactions().get_mut(tx_offset).unwrap();

							mutate_data(&fuzzed, result_target_tx, rng);
							avoid_not_enough_base_gas(result_target_tx, target_block.get_number());
						},
						None => (),
					}

				},
				TxMutation::MutateReceiver => {
					match pick_offset(target_block.get_transactions(), rng) {
						Some(tx_offset) => {
							let mut result_target_tx = result_target_block.mut_transactions().get_mut(tx_offset).unwrap();

							if rng.gen_bool(0.5) {
								let src_block = pick_and_copy(fuzzed.get_blocks(), rng).unwrap();
								let src_tx = pick_and_copy(src_block.get_transactions(), rng).unwrap();
								result_target_tx.set_receiver(src_tx.get_receiver());
							} else {
								result_target_tx.set_receiver(rng.next_u32());
							}

						},
						None => (),
					}

				},
			}

		},
		None => (),
	}

	return result;
}


fn pick_timestamp<R: Rng + ?Sized>(fuzzed: &fuzzer::Fuzzed,
								   queried_block_number: u64,
								   rng: &mut R) -> Option<u64> {
	let min = fuzzed.get_blocks().iter()
		.filter(|&block| block.get_number() < queried_block_number)
		.map(|block| block.get_timestamp() + 1) 
		.max()
		.unwrap_or(0);

	let max = fuzzed.get_blocks().iter()
		.filter(|&block| block.get_number() > queried_block_number)
		.map(|block| block.get_timestamp()) 
		.min()
		.unwrap_or(std::u64::MAX);

	if min == max {
		return Option::None;
	} else if min > max {
		panic!("{:?} / block_num {:?} / min {:?} / max {:?}", fuzzed, queried_block_number, min, max);
	} else {
        return Option::Some(rng.gen_range(min, max));
	}
}

fn get_remaining_block_nums(fuzzed: &fuzzer::Fuzzed) -> Vec<u64> {
	let cur_blocks: Vec<u64> = fuzzed.get_blocks().iter().map(|b| b.get_number()).collect();

	let cur_block_nums: HashSet<u64> = HashSet::from_iter(cur_blocks.iter().copied());
	let all_block_nums: HashSet<u64> = HashSet::from_iter(BLOCK_CANDIDATE_LIST.iter().copied());

	let mut remaining_block_nums: Vec<u64> = all_block_nums.difference(&cur_block_nums).copied().collect();

	remaining_block_nums.sort();

	return remaining_block_nums.to_vec();
}

/*

fn pick_mut_with_offset<'a, T, R: Rng + ?Sized>(array: &'a [&'a mut T], rng: &mut R) -> Option<(&'a mut T, usize)> {
	let offset = rng.gen_range(0, array.len());

	return match array.is_empty() {
		true => Option::Some((array[offset], offset)),
		false => Option::None,
	};
}

fn pick_mut<'a, T, R: Rng + ?Sized>(array: &'a [&'a mut T], rng: &mut R) -> Option<&'a mut T> {
	return match pick_mut_with_offset(array, rng) {
		Some((picked, _)) => Some(picked),
		None => None,
	};
}
*/

fn pick_and_copy<T: Clone, R: Rng + ?Sized>(array: &[T], rng: &mut R) -> Option<T> {
	return match array.is_empty() {
		false => Option::Some(array[rng.gen_range(0, array.len())].clone()),
		true => Option::None,
	};
}

fn pick_offset<T, R: Rng + ?Sized>(array: &[T], rng: &mut R) -> Option<usize> {
	return match array.is_empty() {
		false => Option::Some(rng.gen_range(0, array.len())),
		true => Option::None,
	};
}

fn pick_offset_for_insertion<T: Clone, R: Rng + ?Sized>(array: &[T], rng: &mut R) -> usize {
	return rng.gen_range(0, array.len() + 1);
}


fn create_valid_instruction_list() -> Vec<Instruction> {
	let mut list = Vec::new();
	for instruction in Instruction::iter() {
		if is_valid(instruction as u8) {
			list.push(instruction);
		}
	}
	return list;
}

fn is_valid(instruction: u8) -> bool {
	return match Instruction::from_u8(instruction) {
		Some(i) => !i.is_push(),
		None => false,
	};
}

fn get_builtins() -> Vec<String> {
	let builtins = &SPEC.engine.machine().builtins();

	let mut result = Vec::new();
	for addr in builtins.keys() {
		result.push(addr.to_hex());
	}

	return result;
}

pub fn well_formed_create_tx_data(fuzzed_code: Vec<u8>, constructor_length: u8) -> Vec<u8> {
	let valid_instruction_list = VALID_INSTRUCTION_LIST.clone();

	let mut valid_code: Vec<u8> = Vec::new();

	let mut position = 0;
	while position < fuzzed_code.len() {
		let fuzzed_instruction = fuzzed_code[position];
		let valid_instruction: Instruction = match is_valid(fuzzed_instruction) {
			true => Instruction::from_u8(fuzzed_instruction).unwrap(),
			false => valid_instruction_list[fuzzed_instruction as usize % valid_instruction_list.len()],
		};

		valid_code.push(valid_instruction as u8);
		position = position + 1;


		if valid_instruction.is_push() {
			panic!(); 
		}
	}

	assert_eq!(fuzzed_code.len(), valid_code.len());

	let mut constructor_and_code: Vec<u8> = Vec::new();
	for i in 0..valid_code.len() {
		if i == constructor_length as usize {
			constructor_and_code.push(Instruction::PUSH1 as u8);
			constructor_and_code.push(fuzzed_code.len() as u8 + 3);
			constructor_and_code.push(Instruction::JUMP as u8);
		}

		constructor_and_code.push(valid_code[i]);
	}

	let code_begin_offset = constructor_length + 3;
	let code_length = fuzzed_code.len() as u8 - constructor_length;

	constructor_and_code.push(Instruction::JUMPDEST as u8);


	constructor_and_code.push(Instruction::PUSH1 as u8);
    constructor_and_code.push(code_length); 

    constructor_and_code.push(Instruction::PUSH1 as u8);
    constructor_and_code.push(code_begin_offset); 

    constructor_and_code.push(Instruction::PUSH1 as u8);
    constructor_and_code.push(code_begin_offset); 

    constructor_and_code.push(Instruction::CODECOPY as u8);

	constructor_and_code.push(Instruction::PUSH1 as u8);
    constructor_and_code.push(code_length); 
    constructor_and_code.push(Instruction::PUSH1 as u8);
    constructor_and_code.push(code_begin_offset); 
    constructor_and_code.push(Instruction::RETURN as u8);

	return constructor_and_code;
}

pub fn pretty_print(proto: fuzzer::Fuzzed) {
	let mut blocks_with_tx = Vec::new();

	let mut num_tx = 0;
	for b in proto.get_blocks() {
		num_tx = num_tx + b.get_transactions().len();

		if b.get_transactions().len() > 0 {
			blocks_with_tx.push(b);
		}
	}

	println!("{} Txs => {:?}", num_tx, blocks_with_tx);
}

fn gas_required_for(is_create: bool, data: &[u8], block_num: u64) -> u64 {
	let schedule = &SPEC.engine.machine().schedule(block_num);
	data.iter().fold(
		(if is_create {schedule.tx_create_gas} else {schedule.tx_gas}) as u64,
		|g, b| g + (match *b { 0 => schedule.tx_data_zero_gas, _ => schedule.tx_data_non_zero_gas }) as u64
	)
}

fn read_bytes(num_bytes: usize, bitreader: &mut bitreader::BitReader) -> Vec<u8> {
	let mut fuzzed_data_raw = vec![0; num_bytes];
	bitreader.read_u8_slice(fuzzed_data_raw.as_mut_slice()).unwrap();
	return fuzzed_data_raw;
}

fn get_block_candidate_list() -> Vec<u64> {
	let mut block_number_list = Vec::new();
	for block_number in &SPEC.hard_forks { 
		block_number_list.push(*block_number);
	}
	return block_number_list;
}

fn construct_pre_state(accs: Vec<&fuzzer::EOA>, builtins: &[String]) -> PodState {
	let mut pre: BTreeMap<H160, PodAccount> = BTreeMap::new();
	for acc in accs {
		let mut storage: BTreeMap<H256, H256> = BTreeMap::new();
		let pod_acc = PodAccount {
			balance: acc.get_balance().into(),
			nonce: acc.get_nonce().into(),
			code: Option::None,
			storage: BTreeMap::new(),
			version: U256::zero(),
		};
		pre.insert(Address::from_str(acc.get_address()).unwrap(), pod_acc);
	}
	for builtin in builtins {
		let pod_acc = PodAccount {
			balance: 1.into(),
			nonce: 0.into(),
			code: Option::None,
			storage: BTreeMap::new(),
			version: U256::zero(),
		};
		pre.insert(Address::from_str(builtin).unwrap(), pod_acc);
	}

	return PodState::from(pre);
}

pub fn get_fuzz_result(fuzz_result: &[u8]) -> fuzzer::FuzzResult {
	return protobuf::parse_from_bytes::<fuzzer::FuzzResult>(fuzz_result).unwrap();
}

pub fn get_nth_tx(fuzzed: &fuzzer::Fuzzed, nth: usize) -> (fuzzer::Block, fuzzer::Transaction) {
	let mut index = 0;
	for block in fuzzed.get_blocks() {
		for tx in block.get_transactions() {
			if index == nth {
				let mut block_clone = block.clone();
				block_clone.clear_transactions();
				return (block_clone, tx.clone());
			}
			index = index + 1;
		}
	}

	panic!();
}

pub fn execute_proto(fuzzed: &fuzzer::Fuzzed)
	-> Vec<(String, Option<PodState>, Vec<trace::FlatTrace>, Option<trace::VMTrace>)> {
	let mut initial_addrs: Vec<Address> = Vec::new();
	initial_addrs.push(Address::from_str(&GENESIS_ADDRESS.to_string()).unwrap());
	for builtin_addr in fuzzed.get_builtin_addrs() {
		initial_addrs.push(Address::from_str(builtin_addr).unwrap());
	}
	let mut active_addrs = initial_addrs.clone();

	let accs = vec!{fuzzed.get_genesis_account()};
	let pre_state = construct_pre_state(accs.clone(), fuzzed.get_builtin_addrs().clone());


	let is_debug_mode = fuzzed.get_is_debug_mode();
	let trie_spec = match is_debug_mode {
		true => TrieSpec::Fat, 
		false => TrieSpec::Secure, 
	};
	let mut client = EvmTestClient::from_pod_state_with_trie(
		&SPEC, pre_state.clone(), trie_spec.clone()).unwrap();
	let do_dump = trie_spec == TrieSpec::Fat;
	if do_dump {
		client.set_dump_state();
	}
	client.state.activated_addrs.extend(initial_addrs);

	let mut nonce = 0u64;
	let mut blocks_sorted_by_number = fuzzed.get_blocks().to_vec();
	blocks_sorted_by_number.sort_by(|a, b| a.get_number().cmp(&b.get_number()));
	let mut result_list: Vec<(String, Option<PodState>, Vec<trace::FlatTrace>, Option<trace::VMTrace>)> = Vec::new();

	for block in blocks_sorted_by_number {
		let env_info = EnvInfo {
			number: block.get_number(),
			author: Address::from_str(block.get_author()).unwrap(),
			timestamp: block.get_timestamp(),
			difficulty: block.get_difficulty().into(),
			gas_limit: block.get_gas_limit().into(),
			last_hashes: Default::default(),
			gas_used: U256::default(), // Parity-specific internal thingy(?) that should be set to the default value
		};


		for tx in block.get_transactions() {
			let action: transaction::Action;
			if tx.get_is_create_tx() {
				action = transaction::Action::Create;

			} else {
				let &chosen = client.state.activated_addrs
					.get(tx.get_receiver() as usize % client.state.activated_addrs.len())
					.unwrap();
				action = transaction::Action::Call(chosen);
			};

			let transaction = Transaction {
				data: get_data_bytes(tx),
				gas: tx.get_gas().into(),
				gas_price: tx.get_gas_price().into(),
				nonce: nonce.into(),
				action: action,
				value: tx.get_value().into(),
			};
			let unvertx = UnverifiedTransaction {
				unsigned: transaction,
				v: 0,
				r: 0.into(),
				s: 0.into(),
				hash: H256::zero(),
			};
			let signedtx = SignedTransaction {
				transaction: unvertx,
				sender: Address::from_str(tx.get_sender()).unwrap(),
				public: None,
			};

			let result = match is_debug_mode {
				true => client.transact(&env_info, signedtx, trace::ExecutiveTracer::default(), trace::ExecutiveVMTracer::toplevel()),
				false => client.transact(&env_info, signedtx, trace::NoopTracer, trace::NoopVMTracer),
			};

			nonce = nonce + 1; 

			match result {
				Ok(TransactSuccess { state_root, gas_left, output, trace, vm_trace, end_state, .. }) => {
					result_list.push((format!("0x{}", state_root.to_hex()), end_state, trace, vm_trace));
				},
				Err(TransactErr { state_root, error, end_state }) => {
					result_list.push((format!("0x{}", state_root.to_hex()), end_state, Vec::new(), Option::None));
				},
			}
		}
	}

	return result_list;
}
