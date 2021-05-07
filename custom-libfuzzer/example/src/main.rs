#![no_main]

use libfuzzer_sys::fuzz_target;
use libfuzzer_sys::fuzz_mutate;

fuzz_target!(|data: &[u8]| {
    if data == b"banana!" {
        panic!("success!");
    }

});

fuzz_mutate! (|data: &mut Vec<u8>, max_size: usize, seed: u32| {
    mutatethis(data, max_size, seed);
    return max_size;
});

fn mutatethis(data: &mut Vec<u8>, max_size: usize, seed: u32) {
    data.push(0);
}
