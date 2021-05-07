#![no_main]

extern crate libc;
extern crate rand;

use libfuzzer_sys::fuzz_target;
use libfuzzer_sys::fuzz_mutate;

use std::process::Command;
use std::ffi::CString;
use std::fs::{File, remove_file};
use std::fs::OpenOptions;
use std::io::prelude::*;

use rand::RngCore;
use evmfuzz::execute_proto;

use protobuf::Message;

static mut FIRST_TIME: bool = true;


static mut WRITE_TO: String = String::new();
static mut READ_FROM: String = String::new();

fn get_absolute_path_string(path_from_workspace_root: String) -> String {
	let mut cur_dir = std::env::current_dir().unwrap();
	cur_dir.pop();
	cur_dir.pop();

	println!("{:?}", cur_dir);

	cur_dir.push(std::path::PathBuf::from(path_from_workspace_root));
	return cur_dir.to_str().unwrap().into();
}

fn run_geth(data: &[u8]) -> Vec<u8> {
	unsafe {
		let mut writeTo_file = OpenOptions::new().write(true).open(WRITE_TO.clone()).unwrap();
		writeTo_file.write_all(data).unwrap();
	}

	let mut response = Vec::new();
	unsafe {
		let mut readfrom_file = OpenOptions::new().read(true).open(READ_FROM.clone()).unwrap();
		readfrom_file.read_to_end(&mut response).unwrap();
	}

	return response;
}

fn fuzz_main(data: &[u8]) {
	unsafe {
		if (FIRST_TIME) {

			WRITE_TO = get_absolute_path_string(format!("fifos/{}", rand::thread_rng().next_u64().to_string()));
			READ_FROM = get_absolute_path_string(format!("fifos/{}", rand::thread_rng().next_u64().to_string()));

			libc::mkfifo(CString::new(WRITE_TO.clone()).unwrap().as_ptr(), 0o644);
			libc::mkfifo(CString::new(READ_FROM.clone()).unwrap().as_ptr(), 0o644);

			Command::new(get_absolute_path_string("geth/src/github.com/ethereum/go-ethereum/build/bin/evm".into()))
				.arg(WRITE_TO.as_str())
				.arg(READ_FROM.as_str())
				.spawn() 
				.unwrap();

			FIRST_TIME = false;
		}

	}


	match evmfuzz::convert_to_proto(data) {
		Some(proto) => {
			let parity_results = execute_proto(&proto);

            let geth_result_bytes = run_geth(data);
            let geth_results = evmfuzz::get_fuzz_result(geth_result_bytes.as_slice());

            assert_eq!(parity_results.len(), geth_results.get_roots().len());
            assert_eq!(parity_results.len(), geth_results.get_dumps().len());

            for i in 0..parity_results.len() {
                let geth_result = geth_results.get_roots()[i].clone();
                let parity_result = parity_results[i].clone();

                if geth_result != parity_result.0 {
                    let mut proto_for_debug = proto.clone();
                    proto_for_debug.set_is_debug_mode(true);

                    let parity_debug_results = execute_proto(&proto_for_debug);
                    let bug_tx = evmfuzz::get_nth_tx(&proto, i);

                    let geth_debug_results_bytes =
                        run_geth(proto_for_debug.write_to_bytes().unwrap().as_slice());
                    let geth_debug_results_proto = evmfuzz::get_fuzz_result(geth_debug_results_bytes.as_slice());
                    let geth_debug_results = geth_debug_results_proto.get_dumps().clone();


                    if i == 0 {
                        println!("FIRST TX is the problem (very low chance but hey it happened...)");
                        println!("Bug Tx: {:?}", bug_tx);
                    } else {
                        let parity_state_before_bug = parity_debug_results[i-1].clone().1.unwrap();
                        let parity_state_after_bug =  parity_debug_results[i].clone().1.unwrap();

                        let geth_state_before_bug = geth_debug_results[i-1].clone();
                        let geth_state_after_bug = geth_debug_results[i].clone();

                        println!("===================BUG SUMMARY=================");
                        println!("Bug Tx: {:?}", bug_tx);
                        println!("Parity before tx: {:?}", parity_state_before_bug);
                        println!("Parity after tx: {:?}", parity_state_after_bug);
                        println!("Geth before tx: {}", geth_state_before_bug);
                        println!("Geth after tx: {}", geth_state_after_bug);
                        println!("===================BUGs SUMMARY=================");


                        println!("Geth trace {}", geth_debug_results_proto.get_traces()[i].clone());

                        println!("Parity CALL/CREATE trace");
                        for t in parity_debug_results[i].clone().2 {
                            println!("{:?}", t);
                        }
                    }
                }

                assert_eq!(geth_result, parity_result.0);
			}
		},
		None => (),
	}
}

fuzz_target!(|data: &[u8]| {
	fuzz_main(data);
});

fn fuzz_mutate(bytes: &mut Vec<u8>, max_size: usize, seed: u32) {
	evmfuzz::do_fuzz_mutate(bytes, max_size, seed);
}

fuzz_mutate!(|bytes: &mut Vec<u8>, max_size: usize, seed: u32| {
	fuzz_mutate(bytes, max_size, seed);
});


