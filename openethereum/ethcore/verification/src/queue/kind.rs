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

//! Definition of valid items for the verification queue.

use engine::Engine;

use parity_util_mem::MallocSizeOf;
use ethereum_types::{H256, U256};

use common_types::errors::EthcoreError as Error;

pub use self::blocks::Blocks;
pub use self::headers::Headers;

/// Something which can produce a hash and a parent hash.
pub trait BlockLike {
	/// Get the hash of this item - i.e. the header hash.
	fn hash(&self) -> H256;

	/// Get a raw hash of this item - i.e. the hash of the RLP representation.
	fn raw_hash(&self) -> H256;

	/// Get the hash of this item's parent.
	fn parent_hash(&self) -> H256;

	/// Get the difficulty of this item.
	fn difficulty(&self) -> U256;
}

/// Defines transitions between stages of verification.
///
/// It starts with a fallible transformation from an "input" into the unverified item.
/// This consists of quick, simply done checks as well as extracting particular data.
///
/// Then, there is a `verify` function which performs more expensive checks and
/// produces the verified output.
///
/// For correctness, the hashes produced by each stage of the pipeline should be
/// consistent.
pub trait Kind: 'static + Sized + Send + Sync {
	/// The first stage: completely unverified.
	type Input: Sized + Send + BlockLike + MallocSizeOf;

	/// The second stage: partially verified.
	type Unverified: Sized + Send + BlockLike + MallocSizeOf;

	/// The third stage: completely verified.
	type Verified: Sized + Send + BlockLike + MallocSizeOf;

	/// Attempt to create the `Unverified` item from the input.
	///
	/// The return type is quite complex because in some scenarios the input
	/// is needed (typically for BlockError) to get the raw block bytes without cloning them
	fn create(
		input: Self::Input,
		engine: &dyn Engine,
		check_seal: bool
	) -> Result<Self::Unverified, (Error, Option<Self::Input>)>;

	/// Attempt to verify the `Unverified` item using the given engine.
	fn verify(unverified: Self::Unverified, engine: &dyn Engine, check_seal: bool) -> Result<Self::Verified, Error>;
}

/// The blocks verification module.
pub mod blocks {
	use super::{Kind, BlockLike};

	use engine::Engine;
	use common_types::{
		block::{BlockRlpRepresentation, PreverifiedBlock},
		errors::{EthcoreError as Error, BlockError},
		verification::Unverified,
	};
	use log::{debug, warn};
	use crate::verification::{verify_block_basic, verify_block_unordered};

	use ethereum_types::{H256, U256};

	/// A mode for verifying blocks.
	pub struct Blocks;

	impl Kind for Blocks {
		type Input = Unverified;
		type Unverified = Unverified;
		type Verified = (PreverifiedBlock, BlockRlpRepresentation);

		fn create(
			input: Self::Input,
			engine: &dyn Engine,
			check_seal: bool
		) -> Result<Self::Unverified, (Error, Option<Self::Input>)> {
			match verify_block_basic(&input, engine, check_seal) {
				Ok(()) => Ok(input),
				Err(Error::Block(BlockError::TemporarilyInvalid(oob))) => {
					debug!(target: "client", "Block received too early {}: {:?}", input.hash(), oob);
					Err((BlockError::TemporarilyInvalid(oob).into(), Some(input)))
				},
				Err(e) => {
					warn!(target: "client", "Stage 1 block verification failed for {}: {:?}", input.hash(), e);
					Err((e, Some(input)))
				}
			}
		}

		fn verify(un: Self::Unverified, engine: &dyn Engine, check_seal: bool) -> Result<Self::Verified, Error> {
			let hash = un.hash();
			match verify_block_unordered(un, engine, check_seal) {
				Ok(verified) => Ok(verified),
				Err(e) => {
					warn!(target: "client", "Stage 2 block verification failed for {}: {:?}", hash, e);
					Err(e)
				}
			}
		}
	}

	impl BlockLike for Unverified {
		fn hash(&self) -> H256 {
			self.header.hash()
		}

		fn raw_hash(&self) -> H256 {
			keccak_hash::keccak(&self.bytes)
		}

		fn parent_hash(&self) -> H256 {
			*self.header.parent_hash()
		}

		fn difficulty(&self) -> U256 {
			*self.header.difficulty()
		}
	}

	impl BlockLike for (PreverifiedBlock, BlockRlpRepresentation) {
		fn hash(&self) -> H256 {
			self.0.header.hash()
		}

		fn raw_hash(&self) -> H256 {
			keccak_hash::keccak(&self.1)
		}

		fn parent_hash(&self) -> H256 {
			*self.0.header.parent_hash()
		}

		fn difficulty(&self) -> U256 {
			*self.0.header.difficulty()
		}
	}
}

/// Verification for headers.
pub mod headers {
	use super::{Kind, BlockLike};

	use engine::Engine;
	use common_types::{
		header::Header,
		errors::EthcoreError as Error,
	};
	use crate::verification::{verify_header_params, verify_header_time};

	use ethereum_types::{H256, U256};

	impl BlockLike for Header {
		fn hash(&self) -> H256 { self.hash() }
		fn raw_hash(&self) -> H256 { self.hash() }
		fn parent_hash(&self) -> H256 { *self.parent_hash() }
		fn difficulty(&self) -> U256 { *self.difficulty() }
	}

	/// A mode for verifying headers.
	pub struct Headers;

	impl Kind for Headers {
		type Input = Header;
		type Unverified = Header;
		type Verified = Header;

		fn create(
			input: Self::Input,
			engine: &dyn Engine,
			check_seal: bool
		) -> Result<Self::Unverified, (Error, Option<Self::Input>)> {
			let res = verify_header_params(&input, engine, check_seal)
				.and_then(|_| verify_header_time(&input));

			match res {
				Ok(_) => Ok(input),
				Err(e) => Err((e, Some(input))),
			}
		}

		fn verify(unverified: Self::Unverified, engine: &dyn Engine, check_seal: bool) -> Result<Self::Verified, Error> {
			match check_seal {
				true => engine.verify_block_unordered(&unverified).map(|_| unverified),
				false => Ok(unverified),
			}
		}
	}
}
