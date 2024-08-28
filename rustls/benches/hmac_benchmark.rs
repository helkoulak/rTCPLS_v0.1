
use rustls::SideData;
use crate::bench_util::CPUTime;

mod bench_util;
use criterion::{black_box, criterion_group, criterion_main, Criterion};

use smallvec::ToSmallVec;

use ring::{hmac, rand};
use ring::hmac::Key;
use ring::rand::SecureRandom;


fn decrypt_header(sample: &[u8; 16], enc_tcpls_header: &[u8; 8], hmac_key: &Key ) {
    let tag = hmac::sign(hmac_key, sample);
    let first_8_bytes = &tag.as_ref()[..8];
    let mut output = vec![0u8; 8];
    for i in 0..enc_tcpls_header.len() {
        output[i] = first_8_bytes[i] ^ enc_tcpls_header[i];
    }

}

fn hmac_benchmark(c: &mut Criterion<CPUTime>) {
    let mut rng = rand::SystemRandom::new();
    let mut sample = [0u8; 16];
    let mut enc_tcpls_header = [0u8; 8];
    rng.fill(&mut sample).expect("Generate rand failed");
    rng.fill(&mut enc_tcpls_header).expect("Generate rand failed");
    let key = Key::generate(hmac::HMAC_SHA256, &rng).unwrap();

    c.bench_function("HMAC decoding", |b| {
       
        b.iter(|| {
          black_box(decrypt_header(&sample, &enc_tcpls_header, &key))   // decrypt TCPLS header
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
    targets = hmac_benchmark
}
criterion_main!(benches);