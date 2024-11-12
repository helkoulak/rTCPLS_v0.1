use alloc::boxed::Box;
use core::num::NonZeroU64;
use std::collections::hash_map;
use std::ops::Range;
use std::prelude::rust_2015::ToString;
use crate::crypto::cipher::{HeaderProtector, InboundOpaqueMessage, MessageDecrypter, MessageEncrypter};
use crate::error::Error;
#[cfg(feature = "logging")]
use crate::log::trace;
use crate::msgs::message::{InboundPlainMessage, OutboundOpaqueMessage, OutboundPlainMessage};
use crate::recvbuf::{RecvBuf, RecvBufMap};
use crate::tcpls::frame::{Frame, TcplsHeader};
use crate::tcpls::stream::{SimpleIdHashMap, StreamMap};

static SEQ_SOFT_LIMIT: u64 = 0x16909E7; //(((2 as f64).powf(24.5) as i64) - 0xFFFF) as u64; //0xffff_ffff_ffff_0000u64;
static SEQ_HARD_LIMIT: u64 = 0x16A09E6; //((2 as f64).powf(24.5) as i64) as u64; //0xffff_ffff_ffff_fffeu64;


#[derive(PartialEq)]
enum DirectionState {
    /// No keying material.
    Invalid,

    /// Keying material present, but not yet in use.
    Prepared,

    /// Keying material in use.
    Active,
}

/// Record layer that tracks decryption and encryption keys.
pub struct RecordLayer {
    message_encrypter: Box<dyn MessageEncrypter>,
    message_decrypter: Box<dyn MessageDecrypter>,

    encrypt_state: DirectionState,
    decrypt_state: DirectionState,
    // id of currently used stream
    stream_in_use: u32,
    pub streams: StreamMap,
    has_decrypted: bool,



    // Message encrypted with other keys may be encountered, so failures
    // should be swallowed by the caller.  This struct tracks the amount
    // of message size this is allowed for.
    trial_decryption_len: Option<usize>,
    //Encrypts TCPLS header
    header_encrypter: Option<HeaderProtector>,
    //Decrypts TCPLS header
    header_decrypter: Option<HeaderProtector>,

    early_data_requested: bool,
}

impl RecordLayer {
    /// Create new record layer with no keys.
    pub fn new() -> Self {
        Self {
            message_encrypter: <dyn MessageEncrypter>::invalid(),
            message_decrypter: <dyn MessageDecrypter>::invalid(),
            streams: StreamMap::new(),
            /*is_handshaking: true,*/
            has_decrypted: false,
            encrypt_state: DirectionState::Invalid,
            decrypt_state: DirectionState::Invalid,
            stream_in_use: 0,
            trial_decryption_len: None,
            header_encrypter: Default::default(),
            header_decrypter: Default::default(),
            early_data_requested: false,
        }
    }

    /// Decrypt a TLS message.
    ///
    /// `encr` is a decoded message allegedly received from the peer.
    /// If it can be decrypted, its decryption is returned.  Otherwise,
    /// an error is returned.
    pub(crate) fn decrypt_incoming<'a>(
        &mut self,
        encr: InboundOpaqueMessage<'a>,
    ) -> Result<Option<Decrypted<'a>>, Error> {
        if self.decrypt_state != DirectionState::Active {
            return Ok(Some(Decrypted {
                want_close_before_decrypt: false,
                plaintext: encr.into_plain_message(),
            }));
        }

        // Set to `true` if the peer appears to getting close to encrypting
        // too many messages with this key.
        //
        // Perhaps if we send an alert well before their counter wraps, a
        // buggy peer won't make a terrible mistake here?
        //
        // Note that there's no reason to refuse to decrypt: the security
        // failure has already happened.
        let want_close_before_decrypt = 0 == SEQ_SOFT_LIMIT;

        let encrypted_len = encr.payload.len();
        match self
            .message_decrypter
            .decrypt(encr, 0)
        {
            Ok(plaintext) => {
                if !self.has_decrypted {
                    self.has_decrypted = true;
                }
                Ok(Some(Decrypted {
                    want_close_before_decrypt,
                    plaintext,
                }))
            }
            Err(Error::DecryptError) if self.doing_trial_decryption(encrypted_len) => {
                trace!("Dropping undecryptable message after aborted early_data");
                Ok(None)
            }
            Err(err) => Err(err),
        }
    }


    /// Decrypt a TLS message.
    ///
    /// `encr` is a decoded message allegedly received from the peer.
    /// If it can be decrypted, its decryption is returned.  Otherwise,
    /// an error is returned.
    pub(crate) fn decrypt_incoming_tcpls<'a>(
        &mut self,
        encr: InboundOpaqueMessage<'a>,
        app_bufs: &'a mut RecvBufMap,
        header_decrypted: bool,
    ) -> Result<(Option<Decrypted<'a>>, Option<u32>, Option<u32>), Error> {
        if self.decrypt_state != DirectionState::Active {
            return Ok((Some(Decrypted {
                want_close_before_decrypt: false,
                plaintext: encr.into_plain_message(),
            }), None, None));
        }

        let encrypted_len = encr.payload.len();
        match self
            .message_decrypter
            .decrypt_tcpls(encr, app_bufs, header_decrypted, self.header_decrypter.as_mut().unwrap())
        {
            Ok((plaintext, read_seq, chunk_num, stream_id)) => {
                self.stream_in_use = stream_id;
                self.message_decrypter.increase_read_seq(stream_id);
                if !self.has_decrypted {
                    self.has_decrypted = true;
                }
                Ok((Some(Decrypted {
                    want_close_before_decrypt: read_seq == SEQ_SOFT_LIMIT,
                    plaintext,
                }), Some(chunk_num), Some(stream_id)))
            }
            Err(Error::DecryptError) if self.doing_trial_decryption(encrypted_len) => {
                Err(Error::General("Dropping undecryptable message after aborted early_data".to_string()))?
            }
            Err(err) => Err(err),
        }
    }

    /// Encrypt a TLS message.
    ///
    /// `plain` is a TLS message we'd like to send.  This function
    /// panics if the requisite keying material hasn't been established yet.
    pub(crate) fn encrypt_outgoing(
        &mut self,
        plain: OutboundPlainMessage,
    ) -> OutboundOpaqueMessage {
        debug_assert!(self.encrypt_state == DirectionState::Active);
        assert!(!self.encrypt_exhausted());
        let stream_id = self.stream_in_use;
        let seq = self.message_encrypter.get_write_seq(stream_id);
        self.message_encrypter.increase_write_seq(stream_id);
        self.message_encrypter
            .encrypt(plain, seq)
            .unwrap()
    }

    /// Encrypt a TLS message.
    ///
    /// `plain` is a TLS message we'd like to send.  This function
    /// panics if the requisite keying material hasn't been established yet.
    pub(crate) fn encrypt_outgoing_tcpls(
        &mut self,
        plain: OutboundPlainMessage,
        tcpls_header: &TcplsHeader,
        frame_header: Option<Frame>
    ) -> OutboundOpaqueMessage {
        debug_assert!(self.encrypt_state == DirectionState::Active);
        assert!(!self.encrypt_exhausted());
        let stream_id = self.stream_in_use;
        let seq = self.message_encrypter.get_write_seq(stream_id);
        self.message_encrypter.increase_write_seq(stream_id);
        self.message_encrypter
            .encrypt_tcpls(plain, seq, stream_id, tcpls_header, frame_header, self.header_encrypter.as_mut().unwrap())
            .unwrap()
    }

    pub fn get_tag_length(&self) -> usize {
        self.message_encrypter.get_tag_length()
    }

    pub fn set_early_data_request(&mut self, early_requested: bool) {
        self.early_data_requested = early_requested;
    }
    pub fn early_data_request(&self) -> bool {
        self.early_data_requested
    }

    pub fn decrypt_header(&mut self, input: &[u8], header: & [u8]) -> Result<[u8; 8], Error> {
        self.header_decrypter.as_mut().unwrap().decrypt_in_output(input, header)
    }
    pub fn set_header_encrypter(&mut self, hdr_encrypter: HeaderProtector) {
        let _ = self.header_encrypter.insert(hdr_encrypter);
    }

    pub fn set_header_decrypter(&mut self, hdr_decrypter: HeaderProtector) {
        let _ = self.header_decrypter.insert(hdr_decrypter);
    }

    pub fn header_encrypter_is_set(&self) -> bool {
        self.header_encrypter.is_some()
    }

    pub fn header_decrypter_is_set(&self) -> bool {
        self.header_decrypter.is_some()
    }
    /// Prepare to use the given `MessageEncrypter` for future message encryption.
    /// It is not used until you call `start_encrypting`.
    pub(crate) fn prepare_message_encrypter(&mut self, cipher: Box<dyn MessageEncrypter>) {
        self.message_encrypter = cipher;
        self.message_encrypter.reset_write_seq();
        self.encrypt_state = DirectionState::Prepared;
    }

    /// Prepare to use the given `MessageDecrypter` for future message decryption.
    /// It is not used until you call `start_decrypting`.
    pub(crate) fn prepare_message_decrypter(&mut self, cipher: Box<dyn MessageDecrypter>) {
        self.message_decrypter = cipher;
        self.message_decrypter.reset_read_seq();
        self.decrypt_state = DirectionState::Prepared;
    }

    /// Start using the `MessageEncrypter` previously provided to the previous
    /// call to `prepare_message_encrypter`.
    pub(crate) fn start_encrypting(&mut self) {
        debug_assert!(self.encrypt_state == DirectionState::Prepared);
        self.encrypt_state = DirectionState::Active;
    }

    /// Start using the `MessageDecrypter` previously provided to the previous
    /// call to `prepare_message_decrypter`.
    pub(crate) fn start_decrypting(&mut self) {
        debug_assert!(self.decrypt_state == DirectionState::Prepared);
        self.decrypt_state = DirectionState::Active;
    }

    /// Set and start using the given `MessageEncrypter` for future outgoing
    /// message encryption.
    pub(crate) fn set_message_encrypter(&mut self, cipher: Box<dyn MessageEncrypter>) {
        self.prepare_message_encrypter(cipher);
        self.start_encrypting();
    }

    /// Set and start using the given `MessageDecrypter` for future incoming
    /// message decryption.
    pub(crate) fn set_message_decrypter(&mut self, cipher: Box<dyn MessageDecrypter>) {
        self.prepare_message_decrypter(cipher);
        self.start_decrypting();
        self.trial_decryption_len = None;
    }

    /// Set and start using the given `MessageDecrypter` for future incoming
    /// message decryption, and enable "trial decryption" mode for when TLS1.3
    /// 0-RTT is attempted but rejected by the server.
    pub(crate) fn set_message_decrypter_with_trial_decryption(
        &mut self,
        cipher: Box<dyn MessageDecrypter>,
        max_length: usize,
    ) {
        self.prepare_message_decrypter(cipher);
        self.start_decrypting();
        self.trial_decryption_len = Some(max_length);
    }

    pub(crate) fn finish_trial_decryption(&mut self) {
        self.trial_decryption_len = None;
    }

    /// Return true if we are getting close to encrypting too many
    /// messages with our encryption key.
    pub(crate) fn wants_close_before_encrypt(&mut self) -> bool {
        self.message_encrypter.get_or_create_write_seq(self.stream_in_use) == SEQ_SOFT_LIMIT
    }

    /// Return true if we outright refuse to do anything with the
    /// encryption key.
    pub(crate) fn encrypt_exhausted(&mut self) -> bool {
        self.message_encrypter.get_or_create_write_seq(self.stream_in_use) >= SEQ_HARD_LIMIT
    }

    pub(crate) fn is_encrypting(&self) -> bool {
        self.encrypt_state == DirectionState::Active
    }

    pub(crate) fn is_decrypting(&self) -> bool {
        self.decrypt_state == DirectionState::Active
    }

    /// Return true if we have ever decrypted a message. This is used in place
    /// of checking the read_seq since that will be reset on key updates.
    pub(crate) fn has_decrypted(&self) -> bool {
        self.has_decrypted
    }

    pub(crate) fn write_seq(& self) -> u64 {
        self.message_encrypter.get_write_seq(self.stream_in_use)
    }
    ///Get id of stream in use
    pub fn get_stream_id(& self) -> u32 {
        self.stream_in_use
    }
    /// Returns the number of remaining write sequences
    pub(crate) fn remaining_write_seq(&mut self) -> Option<NonZeroU64> {
        SEQ_SOFT_LIMIT
            .checked_sub( self.message_encrypter.get_write_seq(self.stream_in_use))
            .and_then(NonZeroU64::new)
    }

    pub(crate) fn read_seq(& self) -> u64 {
        self.message_decrypter.get_read_seq(self.stream_in_use)
    }

    pub(crate) fn encrypted_len(&self, payload_len: usize) -> usize {
        self.message_encrypter
            .encrypted_payload_len(payload_len)
    }

    fn doing_trial_decryption(&mut self, requested: usize) -> bool {
        match self
            .trial_decryption_len
            .and_then(|value| value.checked_sub(requested))
        {
            Some(remaining) => {
                self.trial_decryption_len = Some(remaining);
                true
            }
            _ => false,
        }
    }

   /* pub(crate) fn set_not_handshaking(&mut self) {
        self.is_handshaking = false;
    }*/

    pub(crate) fn encrypt_for_stream(&mut self, stream_id: u32) {
        self.stream_in_use = stream_id;
    }
}

/// Result of decryption.
#[derive(Debug)]
pub(crate) struct Decrypted<'a> {
    /// Whether the peer appears to be getting close to encrypting too many messages with this key.
    pub(crate) want_close_before_decrypt: bool,
    /// The decrypted message.
    pub(crate) plaintext: InboundPlainMessage<'a>,
}




#[cfg(test)]
mod tests {
    use std::prelude::v1::Vec;
    use crate::ContentType::ApplicationData;
    use crate::recvbuf::RecvBufMap;
    use super::*;

    #[test]
    fn test_has_decrypted() {
        use crate::{ContentType, ProtocolVersion};

        struct PassThroughDecrypter;
        impl MessageDecrypter for PassThroughDecrypter {
            fn decrypt<'a>(
                &mut self,
                m: InboundOpaqueMessage<'a>,
                _: u64,
            ) -> Result<InboundPlainMessage<'a>, Error> {
                Ok(m.into_plain_message())
            }

            fn decrypt_tcpls<'a, 'b>(&mut self,
                                     msg: InboundOpaqueMessage<'a>,
                                     app_bufs: &'a mut RecvBufMap,
                                     header_decrypted: bool) -> Result<(InboundPlainMessage<'a>, u64, u32, u32), Error> {
                Ok(InboundPlainMessage{
                    version: ProtocolVersion::TLSv1_3,
                    payload: &[],
                    typ: ApplicationData,
                })
            }

        }

        let mut app_buffs = RecvBufMap::new();
        let mut rev_buf = app_buffs.get_or_create(0, None);

        // A record layer starts out invalid, having never decrypted.
        let mut record_layer = RecordLayer::new();
        assert!(matches!(
            record_layer.decrypt_state,
            DirectionState::Invalid
        ));
        assert_eq!(record_layer.message_decrypter.get_read_seq(0), 0);
        assert!(!record_layer.has_decrypted());

        // Preparing the record layer should update the decrypt state, but shouldn't affect whether it
        // has decrypted.
        record_layer.prepare_message_decrypter(Box::new(PassThroughDecrypter));
        assert!(matches!(
            record_layer.decrypt_state,
            DirectionState::Prepared
        ));
        assert_eq!(record_layer.message_decrypter.get_read_seq(0), 0);
        assert!(!record_layer.has_decrypted());

        // Starting decryption should update the decrypt state, but not affect whether it has decrypted.
        record_layer.start_decrypting();
        assert!(matches!(record_layer.decrypt_state, DirectionState::Active));
        assert_eq!(record_layer.message_decrypter.get_read_seq(0), 0);
        assert!(!record_layer.has_decrypted());

        // Decrypting a message should update the read_seq and track that we have now performed
        // a decryption.
        record_layer
            .decrypt_incoming_tcpls(InboundOpaqueMessage::new(
                ContentType::Handshake,
                ProtocolVersion::TLSv1_2,
                &mut [0xC0, 0xFF, 0xEE],
            ), &mut rev_buf, &TcplsHeader::default())
            .unwrap();
        assert!(matches!(record_layer.decrypt_state, DirectionState::Active));
        assert_eq!(record_layer.message_decrypter.get_read_seq(0), 1);
        assert!(record_layer.has_decrypted());

        // Resetting the record layer message decrypter (as if a key update occurred) should reset
        // the read_seq number, but not our knowledge of whether we have decrypted previously.
        record_layer.set_message_decrypter(Box::new(PassThroughDecrypter));
        assert!(matches!(record_layer.decrypt_state, DirectionState::Active));
        assert_eq!(record_layer.message_decrypter.get_read_seq(0), 0);
        assert!(record_layer.has_decrypted());
    }
}