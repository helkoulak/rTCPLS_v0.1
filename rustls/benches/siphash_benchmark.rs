
use rustls::SideData;
use crate::bench_util::CPUTime;

mod bench_util;
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use rand::Rng;

use smallvec::ToSmallVec;
use rustls::crypto::cipherx::HeaderProtector;


fn siphash_benchmark(c: &mut Criterion<CPUTime>) {
    let mut rng = rand::thread_rng();
    let enc_tcpls_header: Vec<u8> = (0..8).map(|_| rng.gen()).collect(); //Encrypted TCPLS header to be decrypted
    let sample: Vec<u8> = (0..16).map(|_| rng.gen()).collect(); // Input to siphash function
    let siphash_key: [u8; 16] = rng.gen();

    c.bench_function("SipHash decoding", |b| {
        let mut hasher = HeaderProtector::new_with_key(siphash_key);
        
        b.iter(|| {
          black_box(hasher.decrypt_in_output(&sample, &enc_tcpls_header))   // decrypt TCPLS header
        });
    });
}


/*criterion_group!{
    name = benches;
    config = Criterion::default()
        .with_profiler(PProfProfiler::new(100, Output::Flamegraph(None)))
        .measurement_time(std::time::Duration::from_secs(15))
        .sample_size(9000);
    targets = criterion_benchmark
}
criterion_main!(benches);*/

criterion_group! {
    name = benches;
    config = Criterion::default()
        .measurement_time(std::time::Duration::from_secs(10))
        .with_measurement(CPUTime)
        .sample_size(500);
    targets = siphash_benchmark
}
criterion_main!(benches);