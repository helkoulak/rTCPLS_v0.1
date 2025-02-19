use crate::bench_util::CPUTime;

mod bench_util;
use criterion::{black_box, criterion_group, criterion_main, Criterion};


use aes::Aes128;

use cipher::{generic_array::GenericArray, BlockDecrypt, KeyInit};
use ring::hmac::Key;
use ring::rand::SecureRandom;
use ring::{hmac, rand};
use rustls::crypto::cipherx::HeaderProtector;

fn decrypt_header_hmac(sample: &[u8; 16], enc_tcpls_header: &[u8; 8], hmac_key: &Key ) {
    let tag = hmac::sign(hmac_key, sample);
    let first_8_bytes = &tag.as_ref()[..8];
    let mut output = vec![0u8; 8];
    for i in 0..enc_tcpls_header.len() {
        output[i] = first_8_bytes[i] ^ enc_tcpls_header[i];
    }

}

fn decrypt_header_aes(sample: &mut Vec<u8>, enc_header: &mut Vec<u8>, cipher: &Aes128 ) {
    let mut mask = GenericArray::default() ;
    cipher.decrypt_block_b2b(GenericArray::from_slice(sample), &mut mask);
    let first_8_bytes = &mask.as_slice()[..8];
    let mut output = vec![0u8; 8];
    for i in 0..7 {
        output[i] = first_8_bytes[i] ^ enc_header[i];
    }

}

fn tcpls_header_decryption_benchmark(c: &mut Criterion<CPUTime>) {
    let rng = rand::SystemRandom::new();
    let mut sample = [0u8; 16];
    let mut enc_tcpls_header = [0u8; 8];
    let mut siphash_key = [0u8; 16];
    rng.fill(&mut sample).expect("Generate rand failed");
    rng.fill(&mut enc_tcpls_header).expect("Generate rand failed");
    rng.fill(&mut siphash_key).expect("Generate rand failed");
    let key = Key::generate(hmac::HMAC_SHA256, &rng).unwrap();

    c.bench_function("HMAC_SHA256 decoding", |b| {
       
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

    c.bench_function("AES_128 decoding", |b| {
        let mut sample = vec![0u8; 16];
        let mut key_bytes = [0u8; 16];
        let mut encrypted_header = vec![0u8; 8];

        rng.fill(&mut sample).expect("Generate rand failed");
        rng.fill(&mut key_bytes).expect("Generate rand failed");
        rng.fill(&mut encrypted_header).expect("Generate rand failed");

        let key = GenericArray::from_slice(&key_bytes);
        let cipher = Aes128::new(key);

        b.iter(|| {
            black_box(decrypt_header_aes(&mut sample, &mut encrypted_header, &cipher))
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