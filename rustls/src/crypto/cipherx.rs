use alloc::boxed::Box;
use alloc::string::ToString;
use core::fmt;

use std::vec;
use aes::Aes128;
use cipher::generic_array::GenericArray;
use cipher::{BlockEncrypt, KeyInit};

use crate::crypto::tls13::HkdfExpander;

use zeroize::Zeroize;
use ring::rand::SecureRandom;
use crate::enums::{ContentType, ProtocolVersion};
use crate::error::Error;
use crate::msgs::codec;
pub use crate::msgs::message::{
    BorrowedPayload, InboundOpaqueMessage, InboundPlainMessage, OutboundChunks,
    OutboundOpaqueMessage, OutboundPlainMessage, PlainMessage, PrefixedPayload,
};
use crate::recvbuf::{RecvBuf, RecvBufMap};
use crate::suites::ConnectionTrafficSecrets;
use crate::tcpls::frame::{Frame, TcplsHeader};

/// Factory trait for building `MessageEncrypter` and `MessageDecrypter` for a TLS1.3 cipher suite.
pub trait Tls13AeadAlgorithm: Send + Sync {
    /// Build a `MessageEncrypter` for the given key/iv.
    fn encrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageEncrypter>;

    /// Build a `MessageDecrypter` for the given key/iv.
    fn decrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageDecrypter>;

    /// The length of key in bytes required by `encrypter()` and `decrypter()`.
    fn key_len(&self) -> usize;

    /// Convert the key material from `key`/`iv`, into a `ConnectionTrafficSecrets` item.
    ///
    /// May return [`UnsupportedOperationError`] if the AEAD algorithm is not a supported
    /// variant of `ConnectionTrafficSecrets`.
    fn extract_keys(
        &self,
        key: AeadKey,
        iv: Iv,
    ) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError>;

    /// Return `true` if this is backed by a FIPS-approved implementation.
    fn fips(&self) -> bool {
        false
    }
}

/// Factory trait for building `MessageEncrypter` and `MessageDecrypter` for a TLS1.2 cipher suite.
pub trait Tls12AeadAlgorithm: Send + Sync + 'static {
    /// Build a `MessageEncrypter` for the given key/iv and extra key block (which can be used for
    /// improving explicit nonce size security, if needed).
    ///
    /// The length of `key` is set by [`KeyBlockShape::enc_key_len`].
    ///
    /// The length of `iv` is set by [`KeyBlockShape::fixed_iv_len`].
    ///
    /// The length of `extra` is set by [`KeyBlockShape::explicit_nonce_len`].
    fn encrypter(&self, key: AeadKey, iv: &[u8], extra: &[u8]) -> Box<dyn MessageEncrypter>;

    /// Build a `MessageDecrypter` for the given key/iv.
    ///
    /// The length of `key` is set by [`KeyBlockShape::enc_key_len`].
    ///
    /// The length of `iv` is set by [`KeyBlockShape::fixed_iv_len`].
    fn decrypter(&self, key: AeadKey, iv: &[u8]) -> Box<dyn MessageDecrypter>;

    /// Return a `KeyBlockShape` that defines how large the `key_block` is and how it
    /// is split up prior to calling `encrypter()`, `decrypter()` and/or `extract_keys()`.
    fn key_block_shape(&self) -> KeyBlockShape;

    /// Convert the key material from `key`/`iv`, into a `ConnectionTrafficSecrets` item.
    ///
    /// The length of `key` is set by [`KeyBlockShape::enc_key_len`].
    ///
    /// The length of `iv` is set by [`KeyBlockShape::fixed_iv_len`].
    ///
    /// The length of `extra` is set by [`KeyBlockShape::explicit_nonce_len`].
    ///
    /// May return [`UnsupportedOperationError`] if the AEAD algorithm is not a supported
    /// variant of `ConnectionTrafficSecrets`.
    fn extract_keys(
        &self,
        key: AeadKey,
        iv: &[u8],
        explicit: &[u8],
    ) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError>;

    /// Return `true` if this is backed by a FIPS-approved implementation.
    fn fips(&self) -> bool {
        false
    }
}

/// An error indicating that the AEAD algorithm does not support the requested operation.
#[derive(Debug, Eq, PartialEq, Clone, Copy)]
pub struct UnsupportedOperationError;

impl From<UnsupportedOperationError> for Error {
    fn from(value: UnsupportedOperationError) -> Self {
        Self::General(value.to_string())
    }
}

impl fmt::Display for UnsupportedOperationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "operation not supported")
    }
}

#[cfg(feature = "std")]
impl std::error::Error for UnsupportedOperationError {}

/// How a TLS1.2 `key_block` is partitioned.
///
/// Note: ciphersuites with non-zero `mac_key_length` are  not currently supported.
pub struct KeyBlockShape {
    /// How long keys are.
    ///
    /// `enc_key_length` terminology is from the standard ([RFC5246 A.6]).
    ///
    /// [RFC5246 A.6]: <https://www.rfc-editor.org/rfc/rfc5246#appendix-A.6>
    pub enc_key_len: usize,

    /// How long the fixed part of the 'IV' is.
    ///
    /// `fixed_iv_length` terminology is from the standard ([RFC5246 A.6]).
    ///
    /// This isn't usually an IV, but we continue the
    /// terminology misuse to match the standard.
    ///
    /// [RFC5246 A.6]: <https://www.rfc-editor.org/rfc/rfc5246#appendix-A.6>
    pub fixed_iv_len: usize,

    /// This is a non-standard extension which extends the
    /// key block to provide an initial explicit nonce offset,
    /// in a deterministic and safe way.  GCM needs this,
    /// chacha20poly1305 works this way by design.
    pub explicit_nonce_len: usize,
}

/// Objects with this trait can decrypt TLS messages.
pub trait MessageDecrypter: Send + Sync {
    /// Decrypt the given TLS message `msg`, using the sequence number
    /// `seq` which can be used to derive a unique [`Nonce`].
    fn decrypt<'a>(
        &mut self,
        msg: InboundOpaqueMessage<'a>,
        seq: u64,
    ) -> Result<InboundPlainMessage<'a>, Error>;
    fn decrypt_tcpls<'a>(
        &mut self,
        msg: InboundOpaqueMessage<'a>,
        app_bufs: &'a mut RecvBufMap,
        header_decrypted: bool,
        header_decrypter: &mut HeaderProtector,
    ) -> Result<(InboundPlainMessage<'a>, u64, u32, u32), Error>;

    fn increase_read_seq(&mut self, stream_id: u32);

    fn get_read_seq(&self, stream_id: u32) -> u64;

    fn get_or_create_read_seq(&mut self, stream_id: u32) -> u64;

    fn reset_read_seq(&mut self);

}

/// Objects with this trait can encrypt TLS messages.
pub trait MessageEncrypter: Send + Sync {
    /// Encrypt the given TLS message `msg`, using the sequence number
    /// `seq` which can be used to derive a unique [`Nonce`].
    fn encrypt(
        &mut self,
        msg: OutboundPlainMessage,
        seq: u64,
    ) -> Result<OutboundOpaqueMessage, Error>;

    /// Return the length of the ciphertext that results from encrypting plaintext of
    /// length `payload_len`
    fn encrypted_payload_len(&self, payload_len: usize) -> usize;
    fn encrypt_tcpls(
        &mut self,
        msg: OutboundPlainMessage,
        seq: u64,
        stream_id: u32,
        tcpls_header: &TcplsHeader,
        frame_header: Option<Frame>,
        header_encrypter: &mut HeaderProtector,
    ) -> Result<OutboundOpaqueMessage, Error>;
    fn encrypted_payload_len_tcpls(&self, payload_len: usize, header_len: usize) -> (usize, usize);

    fn get_tag_length(&self) -> usize;

    fn increase_write_seq(&mut self, stream_id: u32);

    fn get_write_seq(&self, stream_id: u32) -> u64;


    fn reset_write_seq(&mut self);
    fn get_or_create_write_seq(&mut self, stream_id: u32) -> u64;


}

impl dyn MessageEncrypter {
    pub(crate) fn invalid() -> Box<dyn MessageEncrypter> {
        Box::new(InvalidMessageEncrypter {})
    }
}

impl dyn MessageDecrypter {
    pub(crate) fn invalid() -> Box<dyn MessageDecrypter> {
        Box::new(InvalidMessageDecrypter {})
    }
}

/// A write or read IV.
#[derive(Default)]
pub struct Iv([u8; NONCE_LEN]);

impl Iv {
    /// Create a new `Iv` from a byte array, of precisely `NONCE_LEN` bytes.
    #[cfg(feature = "tls12")]
    pub fn new(value: [u8; NONCE_LEN]) -> Self {
        Self(value)
    }

    /// Create a new `Iv` from a byte slice, of precisely `NONCE_LEN` bytes.
    #[cfg(feature = "tls12")]
    pub fn copy(value: &[u8]) -> Self {
        debug_assert_eq!(value.len(), NONCE_LEN);
        let mut iv = Self::new(Default::default());
        iv.0.copy_from_slice(value);
        iv
    }
}

impl From<[u8; NONCE_LEN]> for Iv {
    fn from(bytes: [u8; NONCE_LEN]) -> Self {
        Self(bytes)
    }
}

impl AsRef<[u8]> for Iv {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

/// A nonce.  This is unique for all messages on a connection.
pub struct Nonce(pub [u8; NONCE_LEN]);

impl Nonce {
    /// Combine an `Iv` and sequence number to produce a unique nonce.
    ///
    /// This is `iv ^ seq` where `seq` is encoded as a 96-bit big-endian integer.
    #[inline]
    pub fn new(iv: &Iv, seq: u64, stream_id: u32) -> Self {
        let mut nonce = Self([0u8; NONCE_LEN]);
        codec::put_u64(seq, &mut nonce.0[4..]);
        codec::put_u32(stream_id,&mut nonce.0[..4]);
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

/// Size of TLS nonces (incorrectly termed "IV" in standard) for all supported ciphersuites
/// (AES-GCM, Chacha20Poly1305)
pub const NONCE_LEN: usize = 12;

/// Returns a TLS1.3 `additional_data` encoding.
///
/// See RFC8446 s5.2 for the `additional_data` definition.
#[inline]
pub fn make_tls13_aad(payload_len: usize) -> [u8; 5] {
    let version = ProtocolVersion::TLSv1_2.to_array();
    [
        ContentType::ApplicationData.into(),
        // Note: this is `legacy_record_version`, i.e. TLS1.2 even for TLS1.3.
        version[0],
        version[1],
        (payload_len >> 8) as u8,
        (payload_len & 0xff) as u8,
    ]
}

#[inline]
pub fn make_tls13_aad_tcpls(payload_len: usize, header: &TcplsHeader) -> [u8; 13] {
    let version = ProtocolVersion::TLSv1_2.to_array();
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

/// Returns a TLS1.2 `additional_data` encoding.
///
/// See RFC5246 s6.2.3.3 for the `additional_data` definition.
#[inline]
pub fn make_tls12_aad(
    seq: u64,
    typ: ContentType,
    vers: ProtocolVersion,
    len: usize,
) -> [u8; TLS12_AAD_SIZE] {
    let mut out = [0; TLS12_AAD_SIZE];
    codec::put_u64(seq, &mut out[0..]);
    out[8] = typ.into();
    codec::put_u16(vers.into(), &mut out[9..]);
    codec::put_u16(len as u16, &mut out[11..]);
    out
}



pub struct HeaderProtector{
    aes_cipher: Aes128
}

impl HeaderProtector {
    pub(crate) fn new(expander: &dyn HkdfExpander, aead_key_len: usize) -> Self {

        let mut derived_key= vec![0; aead_key_len]; // 16 or 32 bytes
        expander.expand_slice(&[b"tcpls header protection"], derived_key.as_mut_slice()).unwrap();
        let mut key = [0; 16];
        key.copy_from_slice(&derived_key[..16]);
        let key = GenericArray::from_slice(&key);
        Self{
            aes_cipher: Aes128::new(&key),
        }
    }

    pub fn new_with_key(key: [u8; 16]) -> Self {
        let key = GenericArray::from_slice(&key);
        Self{
            aes_cipher: Aes128::new(&key),
        }
    }

    /// Adds TCPLS Header Protection.
    ///
    /// `input` references the calculated tag bytes
    ///
    /// `header` references the header slice of the encrypted TLS record


    #[inline]
    pub fn decrypt_in_output(
        &mut self,
        sample: &[u8],
        header: &[u8],
    ) -> Result<[u8; 8], Error> {
        self.xor_in_output(sample, header)
    }

    fn xor_in_output(
        &mut self,
        sample: &[u8],
        header: & [u8],
    ) -> Result<[u8; 8], Error> {
        let mut out = [0u8; 8];
        for (i, byte) in self.generate_mask(sample).into_iter().enumerate() {
            out[i] = header[i] ^ byte;
            if i == 7 {break}
        }
        Ok(out)
    }

    pub fn generate_mask(&mut self, input: &[u8]) -> [u8; 16]{
        let mut mask =  GenericArray::default();
        self.aes_cipher.encrypt_block_b2b(GenericArray::from_slice(&input), &mut mask);
        mask.into()
    }

}

const TLS12_AAD_SIZE: usize = 8 + 1 + 2 + 2;

/// A key for an AEAD algorithm.
///
/// This is a value type for a byte string up to `AeadKey::MAX_LEN` bytes in length.
pub struct AeadKey {
    buf: [u8; Self::MAX_LEN],
    used: usize,
}

impl AeadKey {
    #[cfg(feature = "tls12")]
    pub(crate) fn new(buf: &[u8]) -> Self {
        debug_assert!(buf.len() <= Self::MAX_LEN);
        let mut key = Self::from([0u8; Self::MAX_LEN]);
        key.buf[..buf.len()].copy_from_slice(buf);
        key.used = buf.len();
        key
    }

    pub(crate) fn with_length(self, len: usize) -> Self {
        assert!(len <= self.used);
        Self {
            buf: self.buf,
            used: len,
        }
    }

    /// Largest possible AEAD key in the ciphersuites we support.
    pub(crate) const MAX_LEN: usize = 32;
}

impl Drop for AeadKey {
    fn drop(&mut self) {
        self.buf.zeroize();
    }
}

impl AsRef<[u8]> for AeadKey {
    fn as_ref(&self) -> &[u8] {
        &self.buf[..self.used]
    }
}

impl From<[u8; Self::MAX_LEN]> for AeadKey {
    fn from(bytes: [u8; Self::MAX_LEN]) -> Self {
        Self {
            buf: bytes,
            used: Self::MAX_LEN,
        }
    }
}

/// A `MessageEncrypter` which doesn't work.
struct InvalidMessageEncrypter {}

impl MessageEncrypter for InvalidMessageEncrypter {
    fn encrypt(
        &mut self,
        _m: OutboundPlainMessage,
        _seq: u64,
    ) -> Result<OutboundOpaqueMessage, Error> {
        Err(Error::EncryptError)
    }

    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        payload_len
    }

    fn encrypt_tcpls(&mut self, _msg: OutboundPlainMessage, _seq: u64, _stream_id: u32, _tcpls_header: &TcplsHeader, _frame_header: Option<Frame>, _header_encrypter: &mut HeaderProtector) -> Result<OutboundOpaqueMessage, Error> {
        todo!()
    }

    fn encrypted_payload_len_tcpls(&self, _payload_len: usize, _header_len: usize) -> (usize, usize) {
        todo!()
    }

    fn get_tag_length(&self) -> usize {
        0
    }

    fn increase_write_seq(&mut self, _stream_id: u32) {
        todo!()
    }

    fn get_write_seq(&self, stream_id: u32) -> u64 {
        todo!()
    }

    fn reset_write_seq(&mut self) {
        todo!()
    }

    fn get_or_create_write_seq(&mut self, stream_id: u32) -> u64 {
        todo!()
    }
}

/// A `MessageDecrypter` which doesn't work.
struct InvalidMessageDecrypter {}

impl MessageDecrypter for InvalidMessageDecrypter {
    fn decrypt<'a>(
        &mut self,
        _m: InboundOpaqueMessage<'a>,
        _seq: u64,
    ) -> Result<InboundPlainMessage<'a>, Error> {
        Err(Error::DecryptError)
    }

    fn decrypt_tcpls<'a>(&mut self,
                         _msg: InboundOpaqueMessage<'a>,
                         _app_bufs: &'a mut RecvBufMap,
                         _header_decrypted: bool, _header_decrypter: &mut HeaderProtector) -> Result<(InboundPlainMessage<'a>, u64, u32, u32), Error> {
        Err(Error::DecryptError)
    }

    fn increase_read_seq(&mut self, _stream_id: u32) {
        todo!()
    }

    fn get_read_seq(&self, stream_id: u32) -> u64 {
        todo!()
    }

    fn get_or_create_read_seq(&mut self, stream_id: u32) -> u64 {
        todo!()
    }

    fn reset_read_seq(&mut self) {
        todo!()
    }
}
#[test]
fn test_header_enc_dec() {
    use ring::rand::SystemRandom;
    let rng = SystemRandom::new();
    const INPUT_SIZE: usize = 16;
    const HEADER_SIZE: usize = 8;
    let mut sample = [0u8; INPUT_SIZE];
    let mut header = [0u8; HEADER_SIZE];
    let mut output = [0u8; HEADER_SIZE];
    let mut key = [0u8; INPUT_SIZE];
    rng.fill(&mut key).unwrap();

    let mut header_enc_dec = HeaderProtector::new_with_key(key);

    for i in 1..10000 {
        rng.fill(&mut sample).unwrap();
        rng.fill(&mut header).unwrap();

        for (i, byte) in header_enc_dec.generate_mask(&sample).into_iter().enumerate() {
            output[i] = header[i] ^ byte;
            if i == 7 {break}
        }
      assert_eq!(header_enc_dec.decrypt_in_output(&sample, &output).unwrap(), header)

    }
}