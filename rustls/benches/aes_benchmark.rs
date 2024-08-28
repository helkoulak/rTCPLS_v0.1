
use rustls::SideData;
use crate::bench_util::CPUTime;

mod bench_util;
use criterion::{black_box, criterion_group, criterion_main, Criterion};

use smallvec::ToSmallVec;

use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};

use ring::rand::SecureRandom;


fn decrypt_header_aes(sample: &mut Vec<u8>, enc_tcpls_header: &[u8; 8], less_safe_key: &LessSafeKey, aad: Aad<[u8; 0]>, nonce_bytes: [u8; 12]) {
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);
    let _ = less_safe_key.seal_in_place_separate_tag(nonce, aad, sample).expect("decryption failed");
    let first_8_bytes = &sample.as_slice()[..8];
    let mut output = vec![0u8; 8];
    for i in 0..enc_tcpls_header.len() {
        output[i] = first_8_bytes[i] ^ enc_tcpls_header[i];
    }

}

fn aes_benchmark(c: &mut Criterion<CPUTime>) {
    c.bench_function("AES_256_GCM decoding", |b| {
        let mut rng = ring::rand::SystemRandom::new();
        let mut sample = vec![0u8; 16];
        let mut enc_tcpls_header = [0u8; 8];
        let mut key_bytes = [0u8; 32];
        let mut nonce_bytes = [0u8; 12];

        black_box(rng.fill(&mut sample).expect("Generate rand failed"));
        black_box(rng.fill(&mut enc_tcpls_header).expect("Generate rand failed"));
        black_box(rng.fill(&mut key_bytes).expect("Generate rand failed"));
        black_box(rng.fill(&mut nonce_bytes).expect("Generate rand failed"));

        let aad = Aad::empty(); // No additional authenticated data

        let key = black_box(UnboundKey::new(&AES_256_GCM, &key_bytes).unwrap()) ;
        let less_safe_key = black_box(LessSafeKey::new(key)) ;

        b.iter(|| {
          black_box(decrypt_header_aes(black_box(&mut sample), black_box(&enc_tcpls_header), black_box(&less_safe_key), aad, black_box(nonce_bytes)))   // decrypt TCPLS header
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
    targets = aes_benchmark
}
criterion_main!(benches);