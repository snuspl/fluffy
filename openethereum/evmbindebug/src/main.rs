
// This file is part of Parity.

// Parity is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Parity is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Parity.  If not, see <http://www.gnu.org/licenses/>.

extern crate evmfuzz;
extern crate protobuf;

use std::io;
use std::io::prelude::*;
use std::fs::{File, OpenOptions};
use std::path::PathBuf;

use protobuf::Message;


fn main() {
	let args: Vec<String> = std::env::args().collect();
	if args.len() == 2 {
		let file_path = &args[1];
		let mut file = File::open(file_path).unwrap();

		let mut fuzz_bytes = Vec::new();
		file.read_to_end(&mut fuzz_bytes).unwrap();

		match evmfuzz::convert_to_proto(fuzz_bytes.as_slice()) {
			Some(fuzz_proto) => {
				let mut fuzz_proto_debug = fuzz_proto.clone();
				fuzz_proto_debug.set_is_debug_mode(true);

				let result = evmfuzz::execute_proto(&fuzz_proto_debug);
				let (_, final_podstate, trace1, trace2) = result[result.len() - 1].clone();

				println!("========================");
				println!("{}", file_path);
				evmfuzz::pretty_print(fuzz_proto.clone());
				println!("{:?}", final_podstate.unwrap());
				println!("{:?}", trace1);
				println!("{:?}", trace2);
				println!("{:?}", result);
				println!("========================");
			},
			None => println!("NOTHING"),
		}
	} else if args.len() == 3 {
		let input_dir = &args[1];
		let output_dir = &args[2];

		let mut entries: Vec<PathBuf> = std::fs::read_dir(input_dir).unwrap()
			.map(|res| res.map(|e| e.path()))
			.collect::<Result<Vec<PathBuf>, io::Error>>().unwrap();

		for input_path in entries {

			let mut raw_fuzz_input = Vec::new();
			unsafe {
				let mut readfrom_file = OpenOptions::new().read(true).open(input_path.as_path()).unwrap();
				readfrom_file.read_to_end(&mut raw_fuzz_input).unwrap();
			}

			match evmfuzz::convert_to_proto(raw_fuzz_input.as_slice()) {
				Some(proto_fuzz_input) => {
					let mut proto_fuzz_input_ser = proto_fuzz_input.write_to_bytes().unwrap();


					let mut output_path = PathBuf::from(output_dir);

					println!("INPUT PATH {:?}", input_path);
					println!("OUTPUT PATH {:?}", output_path);
					output_path.push(input_path.file_name().unwrap().to_str().unwrap());
					println!("OUTPUT PATH-2 {:?}", output_path);

					unsafe {
						let mut writeTo_file = OpenOptions::new().write(true).create_new(true).open(output_path.as_path()).unwrap();
						writeTo_file.write_all(proto_fuzz_input_ser.as_slice()).unwrap();
					}
				},
				None => (),
			}
		}
	} else {
		println!("WRONG # ARGS");
	}
}


