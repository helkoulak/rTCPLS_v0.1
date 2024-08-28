
use rustls::SideData;
use crate::bench_util::CPUTime;

mod bench_util;
use criterion::{black_box, criterion_group, criterion_main, Criterion};

use smallvec::ToSmallVec;

use ring::{hmac, rand};
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
use ring::hmac::Key;
use ring::rand::SecureRandom;
use rustls::crypto::cipher::HeaderProtector;

fn decrypt_header_hmac(sample: &[u8; 16], enc_tcpls_header: &[u8; 8], hmac_key: &Key ) {
    let tag = hmac::sign(hmac_key, sample);
    let first_8_bytes = &tag.as_ref()[..8];
    let mut output = vec![0u8; 8];
    for i in 0..enc_tcpls_header.len() {
        output[i] = first_8_bytes[i] ^ enc_tcpls_header[i];
    }

}

fn decrypt_header_aes(sample: &mut Vec<u8>, enc_tcpls_header: &[u8; 8], less_safe_key: &LessSafeKey, aad: Aad<[u8; 0]>, nonce_bytes: [u8; 12]) {
    let nonce = Nonce::assume_unique_for_key(nonce_bytes);
    let _ = less_safe_key.seal_in_place_separate_tag(nonce, aad, sample).expect("decryption failed");
    let first_8_bytes = &sample.as_slice()[..8];
    let mut output = vec![0u8; 8];
    for i in 0..enc_tcpls_header.len() {
        output[i] = first_8_bytes[i] ^ enc_tcpls_header[i];
    }

}

fn tcpls_header_decryption_benchmark(c: &mut Criterion<CPUTime>) {
    let mut rng = rand::SystemRandom::new();
    let mut sample = [0u8; 16];
    let mut enc_tcpls_header = [0u8; 8];
    let mut siphash_key = [0u8; 16];
    rng.fill(&mut sample).expect("Generate rand failed");
    rng.fill(&mut enc_tcpls_header).expect("Generate rand failed");
    rng.fill(&mut siphash_key).expect("Generate rand failed");
    let key = Key::generate(hmac::HMAC_SHA256, &rng).unwrap();

    c.bench_function("HMAC decoding", |b| {
       
        b.iter(|| {
          black_box(decrypt_header_hmac(&sample, &enc_tcpls_header, &key))
        });
    });

    c.bench_function("SipHash decoding", |b| {
        let mut hasher = HeaderProtector::new_with_key(siphash_key);

        b.iter(|| {
            black_box(hasher.decrypt_in_output(&sample, &enc_tcpls_header))
        });
    });

    c.bench_function("AES_256_GCM decoding", |b| {
        let mut sample = vec![0u8; 16];
        let mut key_bytes = [0u8; 32];
        let mut nonce_bytes = [0u8; 12];

        rng.fill(&mut sample).expect("Generate rand failed");
        rng.fill(&mut key_bytes).expect("Generate rand failed");
        rng.fill(&mut nonce_bytes).expect("Generate rand failed");

        let aad = Aad::empty(); // No additional authenticated data

        let key = UnboundKey::new(&AES_256_GCM, &key_bytes).unwrap();
        let less_safe_key = LessSafeKey::new(key);

        b.iter(|| {
            black_box(decrypt_header_aes(&mut sample, &enc_tcpls_header, &less_safe_key, aad, nonce_bytes))
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
    targets = tcpls_header_decryption_benchmark
}
criterion_main!(benches);