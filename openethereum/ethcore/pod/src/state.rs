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

//! State of all accounts in the system expressed in Plain Old Data.

use std::collections::BTreeMap;
use ethereum_types::{H256, Address};
use triehash::sec_trie_root;
use common_types::state_diff::StateDiff;
use serde::Serialize;

use crate::account::PodAccount;

/// State of all accounts in the system expressed in Plain Old Data.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize)]
pub struct PodState(BTreeMap<Address, PodAccount>);

impl PodState {
	/// Get the underlying map.
	pub fn get(&self) -> &BTreeMap<Address, PodAccount> {
		&self.0
	}

	/// Get the root hash of the trie of the RLP of this.
	pub fn root(&self) -> H256 {
		sec_trie_root(self.0.iter().map(|(k, v)| (k, v.rlp())))
	}

	/// Drain object to get the underlying map.
	pub fn drain(self) -> BTreeMap<Address, PodAccount> {
		self.0
	}
}

impl From<ethjson::spec::State> for PodState {
	fn from(s: ethjson::spec::State) -> PodState {
		let state: BTreeMap<_,_> = s.into_iter()
			.filter(|pair| !pair.1.is_empty())
			.map(|(addr, acc)| (addr.into(), PodAccount::from(acc)))
			.collect();
		PodState(state)
	}
}

impl From<BTreeMap<Address, PodAccount>> for PodState {
	fn from(s: BTreeMap<Address, PodAccount>) -> Self {
		PodState(s)
	}
}

/// Calculate and return diff between `pre` state and `post` state.
pub fn diff_pod(pre: &PodState, post: &PodState) -> StateDiff {
	StateDiff {
		raw: pre.0.keys()
			.chain(post.0.keys())
			.filter_map(|acc| crate::account::diff_pod(pre.0.get(acc), post.0.get(acc)).map(|d| (*acc, d)))
			.collect()
	}
}

#[cfg(test)]
mod test {
	use common_types::{
		account_diff::{AccountDiff, Diff},
		state_diff::StateDiff,
	};
	use ethereum_types::Address;
	use crate::account::PodAccount;
	use super::PodState;
	use maplit::btreemap;

	#[test]
	fn create_delete() {
		let a = PodState::from(btreemap![
			Address::from_low_u64_be(1) => PodAccount {
				balance: 69.into(),
				nonce: 0.into(),
				code: Some(Vec::new()),
				storage: btreemap![],
				version: 0.into(),
			}
		]);
		assert_eq!(super::diff_pod(&a, &PodState::default()), StateDiff { raw: btreemap![
			Address::from_low_u64_be(1) => AccountDiff{
				balance: Diff::Died(69.into()),
				nonce: Diff::Died(0.into()),
				code: Diff::Died(vec![]),
				storage: btreemap![],
			}
		]});
		assert_eq!(super::diff_pod(&PodState::default(), &a), StateDiff { raw: btreemap![
			Address::from_low_u64_be(1) => AccountDiff{
				balance: Diff::Born(69.into()),
				nonce: Diff::Born(0.into()),
				code: Diff::Born(vec![]),
				storage: btreemap![],
			}
		]});
	}

	#[test]
	fn create_delete_with_unchanged() {
		let a = PodState::from(btreemap![
			Address::from_low_u64_be(1) => PodAccount {
				balance: 69.into(),
				nonce: 0.into(),
				code: Some(Vec::new()),
				storage: btreemap![],
				version: 0.into(),
			}
		]);
		let b = PodState::from(btreemap![
			Address::from_low_u64_be(1) => PodAccount {
				balance: 69.into(),
				nonce: 0.into(),
				code: Some(Vec::new()),
				storage: btreemap![],
				version: 0.into(),
			},
			Address::from_low_u64_be(2) => PodAccount {
				balance: 69.into(),
				nonce: 0.into(),
				code: Some(Vec::new()),
				storage: btreemap![],
				version: 0.into(),
			}
		]);
		assert_eq!(super::diff_pod(&a, &b), StateDiff { raw: btreemap![
			Address::from_low_u64_be(2) => AccountDiff {
				balance: Diff::Born(69.into()),
				nonce: Diff::Born(0.into()),
				code: Diff::Born(vec![]),
				storage: btreemap![],
			}
		]});
		assert_eq!(super::diff_pod(&b, &a), StateDiff { raw: btreemap![
			Address::from_low_u64_be(2) => AccountDiff {
				balance: Diff::Died(69.into()),
				nonce: Diff::Died(0.into()),
				code: Diff::Died(vec![]),
				storage: btreemap![],
			}
		]});
	}

	#[test]
	fn change_with_unchanged() {
		let a = PodState::from(btreemap![
			Address::from_low_u64_be(1) => PodAccount {
				balance: 69.into(),
				nonce: 0.into(),
				code: Some(Vec::new()),
				storage: btreemap![],
				version: 0.into(),
			},
			Address::from_low_u64_be(2) => PodAccount {
				balance: 69.into(),
				nonce: 0.into(),
				code: Some(Vec::new()),
				storage: btreemap![],
				version: 0.into(),
			}
		]);
		let b = PodState::from(btreemap![
			Address::from_low_u64_be(1) => PodAccount {
				balance: 69.into(),
				nonce: 1.into(),
				code: Some(Vec::new()),
				storage: btreemap![],
				version: 0.into(),
			},
			Address::from_low_u64_be(2) => PodAccount {
				balance: 69.into(),
				nonce: 0.into(),
				code: Some(Vec::new()),
				storage: btreemap![],
				version: 0.into(),
			}
		]);
		assert_eq!(super::diff_pod(&a, &b), StateDiff { raw: btreemap![
			Address::from_low_u64_be(1) => AccountDiff {
				balance: Diff::Same,
				nonce: Diff::Changed(0.into(), 1.into()),
				code: Diff::Same,
				storage: btreemap![],
			}
		]});
	}

}
