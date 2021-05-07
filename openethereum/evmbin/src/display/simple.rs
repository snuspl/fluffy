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

//! Log EVM instruction output data traces from a simple formatting informant.

use trace;
use parity_bytes::ToPretty;

use crate::{
	display,
	info as vm,
};

/// Simple formatting informant.
#[derive(Default)]
pub struct Informant;

impl vm::Informant for Informant {

	type Sink = ();

	fn before_test(&mut self, name: &str, action: &str) {
		println!("Test: {} ({})", name, action);
	}

	fn clone_sink(&self) -> Self::Sink { () }

	fn finish(result: vm::RunResult<Self::Output>, _sink: &mut Self::Sink) {
		match result {
			Ok(success) => {
				println!("Output: 0x{}", success.output.to_hex());
				println!("Gas used: {:x}", success.gas_used);
				println!("Time: {}", display::format_time(&success.time));
			},
			Err(failure) => {
				println!("Error: {}", failure.error);
				println!("Time: {}", display::format_time(&failure.time));
			},
		}
	}
}

impl trace::VMTracer for Informant {
	type Output = ();

	fn prepare_subtrace(&mut self, _code: &[u8]) { Default::default() }
	fn done_subtrace(&mut self) {}
	fn drain(self) -> Option<()> { None }
}
