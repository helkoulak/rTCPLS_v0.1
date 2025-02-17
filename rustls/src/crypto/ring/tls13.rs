use crate::crypto::cipherx::{make_tls13_aad, make_tls13_aad_tcpls, AeadKey, HeaderProtector, InboundOpaqueMessage, Iv, MessageDecrypter, MessageEncrypter, Nonce, Tls13AeadAlgorithm, UnsupportedOperationError};
use crate::crypto::tls13::{Hkdf, HkdfExpander, OkmBlock, OutputLengthError};
use crate::enums::{CipherSuite, ContentType, ProtocolVersion};
use crate::error::Error;
use alloc::boxed::Box;
use std::collections::hash_map;
use std::prelude::rust_2018::ToString;
use std::vec;

use crate::msgs::fragmenter::MAX_FRAGMENT_LEN;
use crate::msgs::message::{InboundPlainMessage, OutboundOpaqueMessage, OutboundPlainMessage, PrefixedPayload, CHUNK_NUM_SIZE, HEADER_SIZE, STREAM_ID_SIZE};
use crate::recvbuf::RecvBufMap;
use crate::suites::{CipherSuiteCommon, ConnectionTrafficSecrets, SupportedCipherSuite};
use crate::tcpls::frame::{Frame, TcplsHeader, STREAM_FRAME_HEADER_SIZE, TCPLS_HEADER_SIZE};
use crate::tls13::Tls13CipherSuite;
use crate::{crypto, PeerMisbehaved};

use super::ring_like::hkdf::KeyType;
use super::ring_like::{aead, hkdf, hmac};
use crate::tcpls::stream::SimpleIdHashMap;

/// The TLS1.3 ciphersuite TLS_CHACHA20_POLY1305_SHA256
pub static TLS13_CHACHA20_POLY1305_SHA256: SupportedCipherSuite =
    SupportedCipherSuite::Tls13(TLS13_CHACHA20_POLY1305_SHA256_INTERNAL);

pub(crate) static TLS13_CHACHA20_POLY1305_SHA256_INTERNAL: &Tls13CipherSuite = &Tls13CipherSuite {
    common: CipherSuiteCommon {
        suite: CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
        hash_provider: &super::hash::SHA256,
        confidentiality_limit: u64::MAX,
    },
    hkdf_provider: &RingHkdf(hkdf::HKDF_SHA256, hmac::HMAC_SHA256),
    aead_alg: &Chacha20Poly1305Aead(AeadAlgorithm(&aead::CHACHA20_POLY1305)),
    quic: Some(&super::quic::KeyBuilder {
        packet_alg: &aead::CHACHA20_POLY1305,
        header_alg: &aead::quic::CHACHA20,
        confidentiality_limit: u64::MAX,
        integrity_limit: 1 << 36,
    }),
};

/// The TLS1.3 ciphersuite TLS_AES_256_GCM_SHA384
pub static TLS13_AES_256_GCM_SHA384: SupportedCipherSuite =
    SupportedCipherSuite::Tls13(&Tls13CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::TLS13_AES_256_GCM_SHA384,
            hash_provider: &super::hash::SHA384,
            confidentiality_limit: 1 << 23,
        },
        hkdf_provider: &RingHkdf(hkdf::HKDF_SHA384, hmac::HMAC_SHA384),
        aead_alg: &Aes256GcmAead(AeadAlgorithm(&aead::AES_256_GCM)),
        quic: Some(&super::quic::KeyBuilder {
            packet_alg: &aead::AES_256_GCM,
            header_alg: &aead::quic::AES_256,
            confidentiality_limit: 1 << 23,
            integrity_limit: 1 << 52,
        }),
    });

/// The TLS1.3 ciphersuite TLS_AES_128_GCM_SHA256
pub static TLS13_AES_128_GCM_SHA256: SupportedCipherSuite =
    SupportedCipherSuite::Tls13(TLS13_AES_128_GCM_SHA256_INTERNAL);

pub(crate) static TLS13_AES_128_GCM_SHA256_INTERNAL: &Tls13CipherSuite = &Tls13CipherSuite {
    common: CipherSuiteCommon {
        suite: CipherSuite::TLS13_AES_128_GCM_SHA256,
        hash_provider: &super::hash::SHA256,
        confidentiality_limit: 1 << 23,
    },
    hkdf_provider: &RingHkdf(hkdf::HKDF_SHA256, hmac::HMAC_SHA256),
    aead_alg: &Aes128GcmAead(AeadAlgorithm(&aead::AES_128_GCM)),
    quic: Some(&super::quic::KeyBuilder {
        packet_alg: &aead::AES_128_GCM,
        header_alg: &aead::quic::AES_128,
        confidentiality_limit: 1 << 23,
        integrity_limit: 1 << 52,
    }),
};

fn unpad_tls13_from_slice(v: &mut [u8]) -> (ContentType, usize) {
    let mut last = v.len() - 1;
    loop {
        match v[last] {
            0 => last -= 1,
            content_type => {
                let typ = ContentType::from(content_type);
                v[last] = 0x00;
                return (typ, last)
            },
        }
    }
}

struct Chacha20Poly1305Aead(AeadAlgorithm);

impl Tls13AeadAlgorithm for Chacha20Poly1305Aead {
    fn encrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageEncrypter> {
        self.0.encrypter(key, iv)
    }

    fn decrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageDecrypter> {
        self.0.decrypter(key, iv)
    }

    fn key_len(&self) -> usize {
        self.0.key_len()
    }

    fn extract_keys(
        &self,
        key: AeadKey,
        iv: Iv,
    ) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
        Ok(ConnectionTrafficSecrets::Chacha20Poly1305 { key, iv })
    }

    fn fips(&self) -> bool {
        false // chacha20poly1305 not FIPS approved
    }
}

struct Aes256GcmAead(AeadAlgorithm);

impl Tls13AeadAlgorithm for Aes256GcmAead {
    fn encrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageEncrypter> {
        self.0.encrypter(key, iv)
    }

    fn decrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageDecrypter> {
        self.0.decrypter(key, iv)
    }

    fn key_len(&self) -> usize {
        self.0.key_len()
    }

    fn extract_keys(
        &self,
        key: AeadKey,
        iv: Iv,
    ) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
        Ok(ConnectionTrafficSecrets::Aes256Gcm { key, iv })
    }

    fn fips(&self) -> bool {
        super::fips()
    }
}

struct Aes128GcmAead(AeadAlgorithm);

impl Tls13AeadAlgorithm for Aes128GcmAead {
    fn encrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageEncrypter> {
        self.0.encrypter(key, iv)
    }

    fn decrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageDecrypter> {
        self.0.decrypter(key, iv)
    }

    fn key_len(&self) -> usize {
        self.0.key_len()
    }

    fn extract_keys(
        &self,
        key: AeadKey,
        iv: Iv,
    ) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
        Ok(ConnectionTrafficSecrets::Aes128Gcm { key, iv })
    }

    fn fips(&self) -> bool {
        super::fips()
    }
}

// common encrypter/decrypter/key_len items for above Tls13AeadAlgorithm impls
struct AeadAlgorithm(&'static aead::Algorithm);

impl AeadAlgorithm {
    fn encrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageEncrypter> {
        // safety: the caller arranges that `key` is `key_len()` in bytes, so this unwrap is safe.
        Box::new(Tls13MessageEncrypter {
            enc_key: aead::LessSafeKey::new(aead::UnboundKey::new(self.0, key.as_ref()).unwrap()),
            iv,
            write_seq_map: WriteSeqMap::default(),
        })
    }

    fn decrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageDecrypter> {
        // safety: the caller arranges that `key` is `key_len()` in bytes, so this unwrap is safe.
        Box::new(Tls13MessageDecrypter {
            dec_key: aead::LessSafeKey::new(aead::UnboundKey::new(self.0, key.as_ref()).unwrap()),
            iv,
            read_seq_map: ReadSeqMap::default(),
        })
    }

    fn key_len(&self) -> usize {
        self.0.key_len()
    }
}

struct Tls13MessageEncrypter {
    enc_key: aead::LessSafeKey,
    iv: Iv,
    write_seq_map: WriteSeqMap,

}

struct Tls13MessageDecrypter {
    dec_key: aead::LessSafeKey,
    iv: Iv,
    read_seq_map: ReadSeqMap,
}

impl MessageEncrypter for Tls13MessageEncrypter {
    fn encrypt(
        &mut self,
        msg: OutboundPlainMessage,
        seq: u64,
    ) -> Result<OutboundOpaqueMessage, Error> {
        let total_len = self.encrypted_payload_len(msg.payload.len());
        let mut payload = PrefixedPayload::with_capacity(total_len);

        let nonce = aead::Nonce::assume_unique_for_key(Nonce::new(&self.iv, seq, 0).0);
        let aad = aead::Aad::from(make_tls13_aad(total_len));
        payload.extend_from_chunks(&msg.payload);
        payload.extend_from_slice(&msg.typ.to_array());

        self.enc_key
            .seal_in_place_append_tag(nonce, aad, &mut payload)
            .map_err(|_| Error::EncryptError)?;

        Ok(OutboundOpaqueMessage::new(
            ContentType::ApplicationData,
            // Note: all TLS 1.3 application data records use TLSv1_2 (0x0303) as the legacy record
            // protocol version, see https://www.rfc-editor.org/rfc/rfc8446#section-5.1
            ProtocolVersion::TLSv1_2,
            payload,
        ))
    }

    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        payload_len + 1 + self.enc_key.algorithm().tag_len()
    }

    fn encrypt_tcpls(
        &mut self,
        msg: OutboundPlainMessage,
        seq: u64,
        stream_id: u32,
        tcpls_header: &TcplsHeader,
        frame_header: Option<Frame>,
        header_encrypter: &mut HeaderProtector,
    ) -> Result<OutboundOpaqueMessage, Error> {
        let plain_len = msg.payload.len();
        let hdr_len =  match frame_header.as_ref() {
            Some(_header) => STREAM_FRAME_HEADER_SIZE,
            None => 0,
        };
        let (enc_payload_len, tag_len) = self.encrypted_payload_len_tcpls(plain_len, hdr_len);
        let mut payload = PrefixedPayload::with_capacity_tcpls(enc_payload_len);
        let total_len = TCPLS_HEADER_SIZE + enc_payload_len;


        let nonce = aead::Nonce::assume_unique_for_key(Nonce::new(&self.iv, seq, stream_id).0);
        let aad = aead::Aad::from(make_tls13_aad_tcpls(total_len, tcpls_header));

        //Write payload in output buffer
        payload.extend_from_chunks(&msg.payload);
        //Write TCPLS header
        payload.as_mut()[0] = (tcpls_header.chunk_num >> 24) as u8;
        payload.as_mut()[1] = (tcpls_header.chunk_num >> 16) as u8;
        payload.as_mut()[2] = (tcpls_header.chunk_num >> 8) as u8;
        payload.as_mut()[3] = (tcpls_header.chunk_num & 0xff) as u8;
        payload.as_mut()[4] = (tcpls_header.stream_id >> 24) as u8;
        payload.as_mut()[5] = (tcpls_header.stream_id >> 16) as u8;
        payload.as_mut()[6] = (tcpls_header.stream_id >> 8) as u8;
        payload.as_mut()[7] = (tcpls_header.stream_id & 0xff) as u8;

        // Write frame header and type
        match frame_header {
            Some(ref header) => {
                payload.extend_from_slice(vec![0u8; 4].as_slice());
                let mut b =
                    octets::OctetsMut::with_slice_at_offset(payload.as_mut(), plain_len + TCPLS_HEADER_SIZE);
                header.encode(&mut b)?;
                b.put_bytes(&msg.typ.to_array()).unwrap();

            },
            None => {
                payload.extend_from_slice(&msg.typ.to_array());

            },
        }


        self.enc_key
            .seal_in_place_append_tag_tcpls(nonce, aad, &mut payload, TCPLS_HEADER_SIZE)
            .map_err(|_| Error::EncryptError)?;

        // Take the LSBs of calculated tag as input sample for hash function
        let sample = payload.as_mut_tcpls_payload().rchunks(tag_len).next().unwrap();

        // Encrypt sample AES(sample) and XOR with TCPLS header
        for (i, byte) in header_encrypter.generate_mask(sample).into_iter().enumerate(){
            payload.as_mut_tcpls_header()[i] ^= byte;
            if i == 7 {break}
        }

        Ok(OutboundOpaqueMessage::new(
            ContentType::ApplicationData,
            // Note: all TLS 1.3 application data records use TLSv1_2 (0x0303) as the legacy record
            // protocol version, see https://www.rfc-editor.org/rfc/rfc8446#section-5.1
            ProtocolVersion::TLSv1_2,
            payload,
        ))
    }

    fn encrypted_payload_len_tcpls(&self, payload_len: usize, header_len: usize) -> (usize, usize) {
        let tag_len = self.enc_key.algorithm().tag_len();

        (payload_len + header_len + 1 + tag_len, tag_len)
    }

    fn get_tag_length(&self) -> usize {
        self.enc_key.algorithm().tag_len()
    }

    fn increase_write_seq(&mut self, stream_id: u32) {
        self.write_seq_map.get_or_create(stream_id as u64).write_seq += 1;
    }

    fn get_or_create_write_seq(&mut self, stream_id: u32) -> u64 {
        self.write_seq_map.get_or_create(stream_id as u64).write_seq
    }

    fn reset_write_seq(&mut self) {
       self.write_seq_map.reset_write_seq();
    }

    fn get_write_seq(&self, stream_id: u32) -> u64 {
        self.write_seq_map.get(stream_id as u64).write_seq
    }
}

impl MessageDecrypter for Tls13MessageDecrypter {
    fn decrypt<'a>(
        &mut self,
        mut msg: InboundOpaqueMessage<'a>,
        seq: u64,
    ) -> Result<InboundPlainMessage<'a>, Error> {
        let payload = &mut msg.payload;
        if payload.len() < self.dec_key.algorithm().tag_len() {
            return Err(Error::DecryptError);
        }

        let nonce = aead::Nonce::assume_unique_for_key(Nonce::new(&self.iv, seq, 0).0);
        let aad = aead::Aad::from(make_tls13_aad(payload.len()));
        let plain_len = self
            .dec_key
            .open_in_place(nonce, aad, payload)
            .map_err(|_| Error::DecryptError)?
            .len();

        payload.truncate(plain_len);
        msg.into_tls13_unpadded_message()
    }

    fn decrypt_tcpls<'a>(
        &mut self,
        mut msg: InboundOpaqueMessage<'a>,
        app_bufs: &'a mut RecvBufMap,
        header_decrypted: bool,
        header_decrypter: &mut HeaderProtector,
    ) -> Result<(InboundPlainMessage<'a>, u64, u32, u32), Error> {

        let stream_id: u32;
        let chunk_num: u32;

        let payload = &mut msg.payload;

        if payload.len() < self.dec_key.algorithm().tag_len() {
            return Err(Error::DecryptError);
        }

        match header_decrypted {
            true => {},
            false => {
                // Take the LSBs of calculated tag as input sample for hash function
                let sample = payload[..].rchunks(self.dec_key.algorithm().tag_len()).next().unwrap();


                // Calculate hash(sample) XOR TCPLS header
                for (i, byte) in header_decrypter.generate_mask(sample).into_iter().enumerate(){
                    payload[..TCPLS_HEADER_SIZE][i] ^= byte;
                    if i == 7 {break}
                }
            },
        }

        chunk_num = u32::from_be_bytes(payload[..CHUNK_NUM_SIZE]
            .try_into()
            .unwrap());
        stream_id = u32::from_be_bytes(payload[STREAM_ID_SIZE..TCPLS_HEADER_SIZE]
            .try_into()
            .unwrap());




        let seq = self.read_seq_map.get_or_create(stream_id as u64).read_seq;

        let mut recv_buf = app_bufs.get_or_create(stream_id as u64, None);


        if recv_buf.next_recv_pkt_num != chunk_num {
            return Err(Error::General("Record out of order".to_string()));
        }

        recv_buf.next_recv_pkt_num += 1;
        // output buffer must be at least as big as the input buffer
        if recv_buf.capacity() < payload.len() {
            return Err(Error::General("Buffer too short".to_string()));
        }

        let version = ProtocolVersion::TLSv1_2.to_array();

        let nonce = aead::Nonce::assume_unique_for_key(Nonce::new(&self.iv, seq, stream_id).0);
        let aad = aead::Aad::from(

        [
            ContentType::ApplicationData.into(),
            // Note: this is `legacy_record_version`, i.e. TLS1.2 even for TLS1.3.
            version[0],
            version[1],
            (payload.len() >> 8) as u8,
            (payload.len() & 0xff) as u8,
            (chunk_num >> 24) as u8,
            (chunk_num >> 16) as u8,
            (chunk_num >> 8) as u8,
            (chunk_num & 0xff) as u8,
            (stream_id >> 24) as u8,
            (stream_id >> 16) as u8,
            (stream_id >> 8) as u8,
            (stream_id & 0xff) as u8
        ]
        );



        let plain_len = self
            .dec_key
            .open_in_output(nonce, aad, payload, recv_buf.get_mut(), TCPLS_HEADER_SIZE)
            .map_err(|_| Error::DecryptError)?
            .len();

        if recv_buf.get_mut()[..plain_len].len() > MAX_FRAGMENT_LEN + 1 {
            return Err(Error::PeerSentOversizedRecord);
        }

        let type_pos;
        (msg.typ, type_pos)  = unpad_tls13_from_slice(&mut recv_buf.get_mut()[..plain_len]);

        let payload_len_no_type = recv_buf.get_mut()[..type_pos].len();

        if msg.typ == ContentType::Unknown(0) {
            return Err(PeerMisbehaved::IllegalTlsInnerPlaintext.into());
        }

        if payload_len_no_type > MAX_FRAGMENT_LEN {
            return Err(Error::PeerSentOversizedRecord);
        }

        let current_offset = recv_buf.offset;

        recv_buf.highest_record_sn_received = chunk_num;
        recv_buf.last_decrypted = payload_len_no_type;
        recv_buf.total_decrypted += payload_len_no_type;
        recv_buf.offset += payload_len_no_type as u64;
        recv_buf.last_data_type_decrypted = msg.typ.into();

        Ok((InboundOpaqueMessage::new(msg.typ, ProtocolVersion::TLSv1_3, match msg.typ {
            ContentType::ApplicationData => {
                if recv_buf.get_ref()[current_offset as usize..][type_pos - 1] == 3{
                    recv_buf.complete = true;
                }
                recv_buf.get_mut_consumed()
            },
            ContentType::Handshake => recv_buf.get_mut_at_index(current_offset as usize, payload_len_no_type),
            _ => {
                recv_buf.offset -= payload_len_no_type as u64;
                recv_buf.get_mut_at_index(recv_buf.offset as usize, payload_len_no_type)
            },

        }).into_plain_message(),seq , chunk_num, stream_id))

    }

    fn increase_read_seq(&mut self, stream_id: u32) {
        self.read_seq_map.get_or_create(stream_id as u64).read_seq += 1;
    }

    fn get_read_seq(&self, stream_id: u32) -> u64 {
        self.read_seq_map.get(stream_id as u64).read_seq
    }

    fn get_or_create_read_seq(&mut self, stream_id: u32) -> u64 {
        self.read_seq_map.get_or_create(stream_id as u64).read_seq
    }

    fn reset_read_seq(&mut self) {
        self.read_seq_map.reset_read_seq();
    }
}

struct RingHkdf(hkdf::Algorithm, hmac::Algorithm);

impl Hkdf for RingHkdf {
    fn extract_from_zero_ikm(&self, salt: Option<&[u8]>) -> Box<dyn HkdfExpander> {
        let zeroes = [0u8; OkmBlock::MAX_LEN];
        let salt = match salt {
            Some(salt) => salt,
            None => &zeroes[..self.0.len()],
        };
        Box::new(RingHkdfExpander {
            alg: self.0,
            prk: hkdf::Salt::new(self.0, salt).extract(&zeroes[..self.0.len()]),
        })
    }

    fn extract_from_secret(&self, salt: Option<&[u8]>, secret: &[u8]) -> Box<dyn HkdfExpander> {
        let zeroes = [0u8; OkmBlock::MAX_LEN];
        let salt = match salt {
            Some(salt) => salt,
            None => &zeroes[..self.0.len()],
        };
        Box::new(RingHkdfExpander {
            alg: self.0,
            prk: hkdf::Salt::new(self.0, salt).extract(secret),
        })
    }

    fn expander_for_okm(&self, okm: &OkmBlock) -> Box<dyn HkdfExpander> {
        Box::new(RingHkdfExpander {
            alg: self.0,
            prk: hkdf::Prk::new_less_safe(self.0, okm.as_ref()),
        })
    }

    fn hmac_sign(&self, key: &OkmBlock, message: &[u8]) -> crypto::hmac::Tag {
        crypto::hmac::Tag::new(hmac::sign(&hmac::Key::new(self.1, key.as_ref()), message).as_ref())
    }

    fn fips(&self) -> bool {
        super::fips()
    }
}

struct RingHkdfExpander {
    alg: hkdf::Algorithm,
    prk: hkdf::Prk,
}

impl HkdfExpander for RingHkdfExpander {
    fn expand_slice(&self, info: &[&[u8]], output: &mut [u8]) -> Result<(), OutputLengthError> {
        self.prk
            .expand(info, Len(output.len()))
            .and_then(|okm| okm.fill(output))
            .map_err(|_| OutputLengthError)
    }

    fn expand_block(&self, info: &[&[u8]]) -> OkmBlock {
        let mut buf = [0u8; OkmBlock::MAX_LEN];
        let output = &mut buf[..self.hash_len()];
        self.prk
            .expand(info, Len(output.len()))
            .and_then(|okm| okm.fill(output))
            .unwrap();
        OkmBlock::new(output)
    }

    fn hash_len(&self) -> usize {
        self.alg.len()
    }
}

struct Len(usize);

impl KeyType for Len {
    fn len(&self) -> usize {
        self.0
    }
}
#[derive(Default)]
pub(crate) struct ReadSeqMap {
    map: SimpleIdHashMap<ReadSeq>,
}

impl ReadSeqMap {
    pub(crate) fn get_or_create(&mut self, stream_id: u64) -> &mut ReadSeq {
        match self.map.entry(stream_id) {
            hash_map::Entry::Vacant(v) => {
                v.insert(ReadSeq::new())
            },
            hash_map::Entry::Occupied(v) => v.into_mut(),
        }
    }

    pub(crate) fn get(&self, stream_id: u64) -> & ReadSeq {
        self.map.get(&stream_id).unwrap()
    }

    pub(crate) fn reset_read_seq(&mut self) {
        for seq in self.map.iter_mut() {
            seq.1.read_seq = 0;
        }
    }

}

#[derive(Default)]
pub(crate) struct WriteSeqMap {
    map: SimpleIdHashMap<WriteSeq>,
}

impl WriteSeqMap {
    pub(crate) fn get_or_create(&mut self, stream_id: u64) -> &mut WriteSeq {
        match self.map.entry(stream_id) {
            hash_map::Entry::Vacant(v) => {
                v.insert(WriteSeq::new())
            },
            hash_map::Entry::Occupied(v) => v.into_mut(),
        }
    }

    pub(crate) fn get(&self, stream_id: u64) -> & WriteSeq {
        self.map.get(&stream_id).unwrap()
    }

    pub(crate) fn reset_write_seq(&mut self) {
        for seq in self.map.iter_mut() {
            seq.1.write_seq = 0;
        }
    }

}
#[derive(Default)]
pub(crate) struct WriteSeq {
    write_seq: u64,
}

impl WriteSeq {
    pub(crate) fn new() -> Self {
        Self {
            write_seq: 0,
        }
    }

}
pub(crate) struct ReadSeq {
    read_seq: u64,
}

impl ReadSeq {
    pub(crate) fn new() -> Self {
        Self {
            read_seq: 0,
        }
    }

}