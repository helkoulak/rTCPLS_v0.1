use crate::bench_util::CPUTime;
use rustls::{ContentType, Error, ProtocolVersion};


mod bench_util;
use criterion::{criterion_group, criterion_main, Criterion};



use ring::aead::{LessSafeKey, UnboundKey, AES_128_GCM};
use ring::rand::SecureRandom;
use ring::{aead, rand};
use rustls::crypto::cipherx::{make_tls13_aad, HeaderProtector, OutboundChunks, PrefixedPayload, NONCE_LEN};

use rustls::tcpls::frame::{Frame, TcplsHeader};

pub(crate) const MAX_FRAGMENT_LEN: usize = 16384;
pub(crate) const HEADER_SIZE: usize = 1 + 2 + 2;



pub const TCPLS_HEADER_SIZE: usize = 8;

pub const SAMPLE_PAYLOAD_LENGTH: usize = 16;

pub const STREAM_FRAME_HEADER_SIZE: usize = 3;

pub const MAX_TCPLS_FRAGMENT_LEN: usize = MAX_FRAGMENT_LEN - rustls::tcpls::frame::TCPLS_OVERHEAD;

pub const TCPLS_OVERHEAD: usize = rustls::tcpls::frame::TCPLS_HEADER_SIZE + rustls::tcpls::frame::STREAM_FRAME_HEADER_SIZE;

pub const TCPLS_PAYLOAD_OFFSET: usize = 13;


#[derive(Default)]
pub struct Iv([u8; NONCE_LEN]);

impl From<[u8; NONCE_LEN]> for Iv {
    fn from(bytes: [u8; NONCE_LEN]) -> Self {
        Self(bytes)
    }
}
pub struct Nonce(pub [u8; NONCE_LEN]);


pub(crate) fn put_u64(v: u64, bytes: &mut [u8]) {
    let bytes: &mut [u8; 8] = (&mut bytes[..8]).try_into().unwrap();
    *bytes = u64::to_be_bytes(v);
}


pub(crate) fn put_u32(v: u32, bytes: &mut [u8]) {
    let bytes: &mut [u8; 4] = (&mut bytes[..4]).try_into().unwrap();
    *bytes = u32::to_be_bytes(v);
}
impl Nonce {
    /// Combine an `Iv` and sequence number to produce a unique nonce.
    ///
    /// This is `iv ^ seq` where `seq` is encoded as a 96-bit big-endian integer.
    #[inline]
    pub fn new(iv: &Iv, seq: u64, stream_id: u32) -> Self {
        let mut nonce = Self([0u8; NONCE_LEN]);
        put_u64(seq, &mut nonce.0[4..]);
        put_u32(stream_id,&mut nonce.0[..4]);
        nonce
            .0
            .iter_mut()
            .zip(iv.0.iter())
            .for_each(|(nonce, iv)| {
                *nonce ^= *iv;
            });

        nonce
    }
}
struct Tls13MessageEncrypter {
    enc_key: LessSafeKey,
    iv: Iv,
}
pub fn make_tls13_aad_tcpls(payload_len: usize, header: &TcplsHeader) -> [u8; 13] {
    let version = ProtocolVersion::TLSv1_2.to_array();
    build_aad_inner(payload_len, header, version)
}

fn build_aad_inner(payload_len: usize, header: &TcplsHeader, version: [u8; 2]) -> [u8; 13] {
    [
        ContentType::ApplicationData.into(),
        // Note: this is `legacy_record_version`, i.e. TLS1.2 even for TLS1.3.
        version[0],
        version[1],
        (payload_len >> 8) as u8,
        (payload_len & 0xff) as u8,
        (header.chunk_num >> 24) as u8,
        (header.chunk_num >> 16) as u8,
        (header.chunk_num >> 8) as u8,
        (header.chunk_num & 0xff) as u8,
        (header.stream_id >> 24) as u8,
        (header.stream_id >> 16) as u8,
        (header.stream_id >> 8) as u8,
        (header.stream_id & 0xff) as u8
    ]
}

fn write_header(tcpls_header: &TcplsHeader, payload: &mut PrefixedPayload) {
    let header_bytes = [
        (tcpls_header.chunk_num >> 24) as u8,
        (tcpls_header.chunk_num >> 16) as u8,
        (tcpls_header.chunk_num >> 8) as u8,
        (tcpls_header.chunk_num & 0xff) as u8,
        (tcpls_header.stream_id >> 24) as u8,
        (tcpls_header.stream_id >> 16) as u8,
        (tcpls_header.stream_id >> 8) as u8,
        (tcpls_header.stream_id & 0xff) as u8,
    ];

    payload.as_mut()[..8].copy_from_slice(&header_bytes);
}

fn encrypted_payload_len(payload_len: usize, enc_key: &LessSafeKey) -> usize {
    payload_len + 1 + enc_key.algorithm().tag_len()
}
fn encrypted_payload_len_tcpls(payload_len: usize, header_len: usize, less_safe_key: &LessSafeKey) -> (usize, usize) {
    let tag_len = less_safe_key.algorithm().tag_len();

    (payload_len + header_len + 1 + tag_len, tag_len)
}

pub fn with_capacity_tcpls(capacity: usize) -> Vec<u8> {
    let mut payload: Vec<u8> = Vec::with_capacity(HEADER_SIZE + TCPLS_HEADER_SIZE + capacity);
    payload.resize(HEADER_SIZE + TCPLS_HEADER_SIZE, 0);
    payload
}
fn encrypt_header(
    msg: &Vec<u8>,
    seq: u64,
    stream_id: u32,
    tcpls_header: &TcplsHeader,
    frame_header: Option<&Frame>,
    header_encrypter: &mut HeaderProtector,
    msg_encrypter: & Tls13MessageEncrypter,
) -> Result<(), Error> {
    let plain_len = msg.len();
    let hdr_len =  match frame_header.as_ref() {
        Some(_header) => STREAM_FRAME_HEADER_SIZE,
        None => 0,
    };
    let (enc_payload_len, tag_len) = encrypted_payload_len_tcpls(plain_len, hdr_len, &msg_encrypter.enc_key);
    let mut payload = PrefixedPayload::with_capacity_tcpls(enc_payload_len);
    let total_len = TCPLS_HEADER_SIZE + enc_payload_len;


    let nonce = aead::Nonce::assume_unique_for_key(Nonce::new(&msg_encrypter.iv, seq, stream_id).0);
    let aad = aead::Aad::from(make_tls13_aad_tcpls(total_len, tcpls_header));

    //Write payload in output buffer
    payload.extend_from_chunks(&OutboundChunks::Single(msg));
    //Write TCPLS header
    write_header(tcpls_header, &mut payload);
    // Write frame header and type
    match frame_header {
        Some(ref header) => {
            payload.extend_from_slice(vec![0u8; 4].as_slice());
            let mut b =
                octets::OctetsMut::with_slice_at_offset(payload.as_mut(), plain_len + TCPLS_HEADER_SIZE);
            header.encode(&mut b).unwrap();
            b.put_bytes(&ContentType::ApplicationData.to_array()).unwrap();
            ()
        },
        None => {
            payload.extend_from_slice(&ContentType::ApplicationData.to_array());
            ()
        },
    }


    msg_encrypter.enc_key
        .seal_in_place_append_tag_tcpls(nonce, aad, &mut payload, TCPLS_HEADER_SIZE)
        .map_err(|_| Error::EncryptError)?;

    // Take the LSBs of calculated tag as input sample for hash function
    let sample = payload.as_mut_tcpls_payload().rchunks(tag_len).next().unwrap();

    let mut i = 0;
    let mask = header_encrypter.generate_mask(sample);
    // Calculate hash(sample) XOR TCPLS header
    for byte in mask {
        payload.as_mut_tcpls_header()[i] ^= byte;
        i += 1;
    }

    Ok(())
}



fn encrypt(
    msg: &Vec<u8>,
    seq: u64,
    msg_encrypter: & Tls13MessageEncrypter,
) -> Result<(), Error> {
    let total_len = encrypted_payload_len(msg.len(), &msg_encrypter.enc_key);
    let mut payload = PrefixedPayload::with_capacity(total_len);

    let nonce = aead::Nonce::assume_unique_for_key(Nonce::new(&msg_encrypter.iv, seq, 0).0);
    let aad = aead::Aad::from(make_tls13_aad(total_len));
    payload.extend_from_chunks(&OutboundChunks::Single(msg));
    payload.extend_from_slice(&ContentType::ApplicationData.to_array());

    msg_encrypter.enc_key
        .seal_in_place_append_tag(nonce, aad, &mut payload)
        .map_err(|_| Error::EncryptError)?;

    Ok(())
}

fn encryption_benchmark(c: &mut Criterion<CPUTime>) {
    let rng = rand::SystemRandom::new();
    let mut msg = vec![0u8; MAX_TCPLS_FRAGMENT_LEN];
    let mut header_protection_key = [0u8; 16];
    let mut iv = [0u8; 12];
    let enc_tcpls_header = TcplsHeader {
        chunk_num: 636873673,
        stream_id: 64684,

    };
    let frame_header: Option<&Frame> = Some(&Frame::Stream {
        length: MAX_TCPLS_FRAGMENT_LEN as u16,
        fin: 1,
    });
    let mut key_bytes = [0u8; 16];
    let mut nonce_bytes = [0u8; 12];

    let key = UnboundKey::new(&AES_128_GCM, &key_bytes).unwrap();
    let less_safe_key = LessSafeKey::new(key);

    rng.fill(&mut msg).expect("Generate rand failed");
    rng.fill(&mut iv).expect("Generate rand failed");
    rng.fill(&mut key_bytes).expect("Generate rand failed");
    rng.fill(&mut nonce_bytes).expect("Generate rand failed");
    rng.fill(&mut header_protection_key).expect("Generate rand failed");

    let msg_encrypter = Tls13MessageEncrypter{
        iv: Iv::from(iv),
        enc_key: less_safe_key,
    };

    let mut header_protector: HeaderProtector = HeaderProtector::new_with_key(&header_protection_key);

    c.bench_function("AES_128_GCM encryption without tcpls header", |b| {

        b.iter(|| {
            encrypt(&msg, 0, &msg_encrypter)
        });
    });
    c.bench_function("AES_128_GCM encryption with tcpls header", |b| {

        b.iter(|| {
            encrypt_header(&msg, 0, 0, &enc_tcpls_header, frame_header,
                                     &mut header_protector, &msg_encrypter)
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
        .measurement_time(std::time::Duration::from_secs(1))
        .with_measurement(CPUTime)
        .sample_size(500);
    targets = encryption_benchmark
}
criterion_main!(benches);