
use alloc::boxed::Box;
use alloc::vec::Vec;
use std::collections::hash_map;
use std::time::{Duration, Instant};
use std::vec;
use pki_types::CertificateDer;

use crate::enums::{AlertDescription, ContentType, HandshakeType, ProtocolVersion};
use crate::error::{Error, InvalidMessage, PeerMisbehaved};
#[cfg(feature = "logging")]
use crate::log::{debug, warn};
use crate::msgs::alert::AlertMessagePayload;
use crate::msgs::base::Payload;
use crate::msgs::enums::{AlertLevel, KeyUpdateRequest};
use crate::msgs::fragmenter::MessageFragmenter;
use crate::msgs::handshake::{CertificateChain, TcplsToken};
use crate::msgs::message::{Message, OutboundChunks, OutboundOpaqueMessage, OutboundPlainMessage, PlainMessage};
use crate::suites::{PartiallyExtractedSecrets, SupportedCipherSuite};
#[cfg(feature = "tls12")]
use crate::tls12::ConnectionSecrets;
use crate::unbuffered::{EncryptError, InsufficientSizeError};
use crate::vecbuf::ChunkVecBuffer;
use crate::{quic, record_layer};
use crate::ContentType::ApplicationData;
use crate::ProtocolVersion::TLSv1_2;
use crate::recvbuf::RecvBufMap;
use crate::tcpls::frame::{Frame, TcplsHeader};
use crate::tcpls::outstanding_conn::OutstandingConnMap;
use crate::tcpls::stream::{DEFAULT_STREAM_ID, SimpleIdHashMap};

/// Connection state common to both client and server connections.
pub struct CommonState {
    pub(crate) negotiated_version: Option<ProtocolVersion>,
    pub(crate) side: Side,
    pub(crate) record_layer: record_layer::RecordLayer,
    pub(crate) suite: Option<SupportedCipherSuite>,
    pub(crate) alpn_protocol: Option<Vec<u8>>,
    pub(crate) aligned_handshake: bool,
    pub(crate) may_send_application_data: bool,
    pub(crate) may_receive_application_data: bool,
    pub(crate) early_traffic: bool,
    sent_fatal_alert: bool,
    /// If the peer has signaled end of stream.
    pub(crate) has_received_close_notify: bool,

    #[cfg(feature = "std")]
    pub(crate) has_seen_eof: bool,
    pub(crate) received_middlebox_ccs: u8,
    pub(crate) peer_certificates: Option<CertificateChain<'static>>,
    message_fragmenter: MessageFragmenter,

    pub outstanding_tcp_conns: OutstandingConnMap,

    pub(crate) tcpls_tokens: Vec<TcplsToken>,
    pub(crate) received_plaintext: ChunkVecBuffer,
    /// id of currently used tcp connection
    pub(crate) conn_in_use: u32,

    ///Id of stream to write to
    pub write_to: u32,

    queued_key_update_message: Option<Vec<u8>>,

    pub received_data_processed: bool,
    
    pub enable_ack: bool,

    /// Protocol whose key schedule should be used. Unused for TLS < 1.3.
    pub(crate) protocol: Protocol,
    pub(crate) quic: quic::Quic,
    pub(crate) enable_secret_extraction: bool,
    pub(crate) conns_rtts: SimpleIdHashMap<Duration>
}

impl CommonState {
    pub(crate) fn new(side: Side) -> Self {
        Self {
            negotiated_version: None,
            side,
            record_layer: record_layer::RecordLayer::new(),
            suite: None,
            alpn_protocol: None,
            aligned_handshake: true,
            may_send_application_data: false,
            may_receive_application_data: false,
            early_traffic: false,
            sent_fatal_alert: false,
            has_received_close_notify: false,

            #[cfg(feature = "std")]
            has_seen_eof: false,
            received_middlebox_ccs: 0,
            peer_certificates: None,
            message_fragmenter: MessageFragmenter::default(),

            outstanding_tcp_conns: OutstandingConnMap::default(),

            tcpls_tokens: Vec::new(),
            received_plaintext: ChunkVecBuffer::new(Some(DEFAULT_RECEIVED_PLAINTEXT_LIMIT)),
            conn_in_use: 0,
            write_to: 0,

            queued_key_update_message: None,

            received_data_processed: false,
            enable_ack: false,
            protocol: Protocol::Tcp,
            quic: quic::Quic::default(),
            enable_secret_extraction: false,
            conns_rtts: SimpleIdHashMap::default(),
        }
    }
    /// sets the id of the currently active tcp connection
    pub fn set_connection_in_use(&mut self, conn_id: u32) {
        self.conn_in_use = conn_id;
    }

    /// Turn-off/on acknowledgments
    pub fn activate_ack(&mut self, activate_ack: bool) {
        self.enable_ack = activate_ack;
    }

    pub fn insert_conn_rtt(&mut self, conn_id: u64, rtt: Duration) {
        self.conns_rtts.insert(conn_id, rtt);
    }

    /// Returns true if the caller should call [`send_on_connection`] as soon as possible.
    ///
    /// [`send_on_connection`]: crate::tcpls::s
    pub fn wants_write(&self, id: Option<u32>) -> bool {
        match id {
            Some(id) => !self.record_layer.streams.get(id as u16).unwrap().send.is_empty(),
            None => !self.record_layer.streams.all_empty(),
        }

    }

    /// Returns true if the connection is currently performing the TLS handshake.
    ///
    /// During this time plaintext written to the connection is buffered in memory. After
    /// [`Connection::process_new_packets()`] has been called, this might start to return `false`
    /// while the final handshake packets still need to be extracted from the connection's buffers.
    ///

    /// [`Connection::process_new_packets()`]: crate::Connection::process_new_packets
    pub fn is_handshaking(&self) -> bool {
        !(self.may_send_application_data && self.may_receive_application_data)
    }

    /// Retrieves the certificate chain used by the peer to authenticate.
    ///
    /// The order of the certificate chain is as it appears in the TLS
    /// protocol: the first certificate relates to the peer, the
    /// second certifies the first, the third certifies the second, and
    /// so on.
    ///
    /// This is made available for both full and resumed handshakes.
    ///
    /// For clients, this is the certificate chain of the server.
    ///
    /// For servers, this is the certificate chain of the client,
    /// if client authentication was completed.
    ///
    /// The return value is None until this value is available.

    pub fn peer_certificates(&self) -> Option<&[CertificateDer<'static>]> {
        self.peer_certificates.as_deref()
    }

    /// Retrieves the protocol agreed with the peer via ALPN.
    ///
    /// A return value of `None` after handshake completion
    /// means no protocol was agreed (because no protocols
    /// were offered or accepted by the peer).
    pub fn alpn_protocol(&self) -> Option<&[u8]> {
        self.get_alpn_protocol()
    }

    pub fn tcpls_tokens(&self) -> Option<&Vec<TcplsToken>> {
        self.get_tcpls_tokens()
    }

    pub(crate) fn get_tcpls_tokens(&self) -> Option<&Vec<TcplsToken>> {
        if !self.tcpls_tokens.is_empty() {
            Some(&self.tcpls_tokens)
        } else { None }
    }
    pub(crate) fn get_next_tcpls_token(&mut self) -> Option<TcplsToken> {
        self.tcpls_tokens.pop()
    }
    pub fn next_tcpls_token(&mut self) -> Option<TcplsToken> {
        self.get_next_tcpls_token()
    }
    /// Retrieves the ciphersuite agreed with the peer.
    ///
    /// This returns None until the ciphersuite is agreed.
    pub fn negotiated_cipher_suite(&self) -> Option<SupportedCipherSuite> {
        self.suite
    }

    /// Retrieves the protocol version agreed with the peer.
    ///
    /// This returns `None` until the version is agreed.
    pub fn protocol_version(&self) -> Option<ProtocolVersion> {
        self.negotiated_version
    }

    pub(crate) fn is_tls13(&self) -> bool {
        matches!(self.negotiated_version, Some(ProtocolVersion::TLSv1_3))
    }

    pub(crate) fn process_main_protocol<Data>(
        &mut self,
        msg: Message,
        mut state: Box<dyn State<Data>>,
        data: &mut Data,
        sendable_plaintext: Option<&mut PlainBufsMap>,
    ) -> Result<Box<dyn State<Data>>, Error> {
        // For TLS1.2, outside of the handshake, send rejection alerts for
        // renegotiation requests.  These can occur any time.
        if self.may_receive_application_data && !self.is_tls13() {
            let reject_ty = match self.side {
                Side::Client => HandshakeType::HelloRequest,
                Side::Server => HandshakeType::ClientHello,
            };
            if msg.is_handshake_type(reject_ty) {
                self.send_warning_alert(AlertDescription::NoRenegotiation);
                return Ok(state);
            }
        }


        let mut cx = Context {
            common: self,
            data,
            sendable_plaintext,
        };
        match state.handle(&mut cx, msg) {
            Ok(next) => {
                state = next.into_owned();
                Ok(state)
            }
            Err(e @ Error::InappropriateMessage { .. })
            | Err(e @ Error::InappropriateHandshakeMessage { .. }) => {
                Err(self.send_fatal_alert(AlertDescription::UnexpectedMessage, e))
            }
            Err(e) => Err(e),
        }
    }


    pub(crate) fn write_plaintext(
        &mut self,
        payload: OutboundChunks<'_>,
        outgoing_tls: &mut [u8],
    ) -> Result<usize, EncryptError> {
        if payload.is_empty() {
            return Ok(0);
        }

        let fragments = self
            .message_fragmenter
            .fragment_payload(
                ContentType::ApplicationData,
                ProtocolVersion::TLSv1_2,
                payload.clone(),
            );

        let remaining_encryptions = self
            .record_layer
            .remaining_write_seq()
            .ok_or(EncryptError::EncryptExhausted)?;

        if fragments.len() as u64 > remaining_encryptions.get() {
            return Err(EncryptError::EncryptExhausted);
        }

        self.check_required_size(
            outgoing_tls,
            self.queued_key_update_message
                .as_deref(),
            fragments,
        )?;

        let fragments = self
            .message_fragmenter
            .fragment_payload(
                ContentType::ApplicationData,
                ProtocolVersion::TLSv1_2,
                payload,
            );

        let opt_msg = self.queued_key_update_message.take();
        let written = self.write_fragments(outgoing_tls, opt_msg, fragments);

        Ok(written)
    }

    // Changing the keys must not span any fragmented handshake
    // messages.  Otherwise the defragmented messages will have
    // been protected with two different record layer protections,
    // which is illegal.  Not mentioned in RFC.
    pub(crate) fn check_aligned_handshake(&mut self) -> Result<(), Error> {
        if !self.aligned_handshake {
            Err(self.send_fatal_alert(
                AlertDescription::UnexpectedMessage,
                PeerMisbehaved::KeyEpochWithPendingFragment,
            ))
        } else {
            Ok(())
        }
    }


    /// Fragment `m`, encrypt the fragments, and then queue
    /// the encrypted fragments for sending.
    pub(crate) fn send_msg_encrypt(&mut self, m: PlainMessage, id: u32) {
        let iter = self
            .message_fragmenter
            .fragment_message(&m);
        for m in iter {
            self.send_single_fragment(m, id, false);
        }
    }

    /// Like send_msg_encrypt, but operate on an appdata directly.

    fn send_appdata_encrypt(&mut self, payload: OutboundChunks<'_>, limit: Limit, id: u32) -> usize {
        // Here, the limit on sendable_tls applies to encrypted data,
        // but we're respecting it for plaintext data -- so we'll
        // be out by whatever the cipher+record overhead is.  That's a
        // constant and predictable amount, so it's not a terrible issue.

        let mut fin = false;
        let len = match limit {
            #[cfg(feature = "std")]
            Limit::Yes => self
                .record_layer
                .streams
                .get_or_create(id)
                .unwrap()
                .send
                .apply_limit(payload.len()),
            Limit::No => payload.len(),
        };

        if len == 0 {
            self.record_layer.streams.remove_writable(id as u64);
            // Send buffer is full.
            return 0;
        }

        if len == payload.len() {
            fin = true;
        }

        let iter = self
            .message_fragmenter
            .fragment_payload(
                ContentType::ApplicationData,
                ProtocolVersion::TLSv1_2,
                payload.split_at(len).0,
            );
        let mut count = iter.len();
        for m in iter {
            count -= 1;
            //consider flag fin when reaching last chunk
            let finish = if count == 0 {
                fin
            } else {
                false
            };
            self.send_single_fragment(m, id, finish);
        }

        len
    }


    fn send_single_fragment(&mut self, m: OutboundPlainMessage, id: u32, fin: bool) {
        self.record_layer.streams.get_or_create(id).unwrap();
        // set id of stream to decide on crypto context and record seq space
        self.record_layer.encrypt_for_stream(id);
        // Close connection once we start to run out of
        // sequence space.
        if self
            .record_layer
            .wants_close_before_encrypt()
        {
            self.send_close_notify();
        }

        // Refuse to wrap counter at all costs.  This
        // is basically untestable unfortunately.
        if self.record_layer.encrypt_exhausted() {
            return;
        }

        let tcpls_header = self.record_layer
            .streams
            .get_mut(id)
            .unwrap()
            .build_header(m.payload.len() as u16);

        let stream_frame_header = match m.typ {
            ApplicationData => {
                Some(Frame::Stream {
                    length: m.payload.len() as u16,
                    fin: fin.into(),
                })
            },
            _ => None,
        };

        let typ = m.typ;

        let em = self.record_layer.encrypt_outgoing_tcpls(m, &tcpls_header, stream_frame_header);
        self.queue_message(em.encode(), id, Some(&tcpls_header), typ);
    }

    pub(crate) fn send_single_probe(&mut self, m: OutboundPlainMessage) -> Option<OutboundOpaqueMessage>{

        // set id of stream to decide on crypto context and record seq space
        self.record_layer.encrypt_for_stream(DEFAULT_STREAM_ID);
        // Close connection once we start to run out of
        // sequence space.
        if self
            .record_layer
            .wants_close_before_encrypt()
        {
            self.send_close_notify();
        }

        if self.record_layer.encrypt_exhausted() {
            return None;
        }

        let tcpls_header = self.record_layer
            .streams
            .get_mut(DEFAULT_STREAM_ID)
            .unwrap()
            .build_header(m.payload.len() as u16);


        Some(self.record_layer.encrypt_outgoing_tcpls(m, &tcpls_header, None))

    }

    pub(crate) fn send_ack(&mut self, chunk_num: u64, stream_id: u64) -> Option<OutboundOpaqueMessage>{
        let mut ack = vec![0u8; 17];
        let mut b = octets::OctetsMut::with_slice_at_offset(ack.as_mut(), 0);
        Frame::ACK {
            highest_record_sn_received: chunk_num,
            stream_id,
        }.encode(&mut b).expect("encoding ack frame failed");
        // set id of stream to decide on crypto context and record seq space
        self.record_layer.encrypt_for_stream(DEFAULT_STREAM_ID);
        // Close connection once we start to run out of
        // sequence space.
        if self
            .record_layer
            .wants_close_before_encrypt()
        {
            self.send_close_notify();
        }

        if self.record_layer.encrypt_exhausted() {
            return None;
        }

        let tcpls_header = self.record_layer
            .streams
            .get_mut(DEFAULT_STREAM_ID)
            .unwrap()
            .build_header(ack.len() as u16);


        Some(self.record_layer.encrypt_outgoing_tcpls(OutboundPlainMessage {
            typ: ApplicationData,
            version: TLSv1_2,
            payload: OutboundChunks::Single(&ack),
        }, &tcpls_header, None))

    }

    pub fn calculate_conn_shares(&mut self, chunks_num: usize, conn_ids: &Vec<u64>, stream_id: u64)  {
        let mut weights: SimpleIdHashMap<f64> = SimpleIdHashMap::default();
        let mut weight_sum: f64 = 0.0;

        // Calculate weights and their sum
        for id in conn_ids {
            if let Some(conn_rtt) = self.conns_rtts.get(&id) {
                let latency_ns = conn_rtt.as_nanos() as f64;

                let weight = if latency_ns > 0.0 { 1.0 / latency_ns } else { 1.0 };

                weights.insert(*id, weight);
                weight_sum += weight;
            }
        }

        // Distribute chunks proportionally based on weights
        for id in conn_ids {
            if let Some(&weight) = weights.get(&id) {
                // Calculate proportion and allocate chunks
                let proportion = weight / weight_sum;
                let share = (proportion * chunks_num as f64).ceil() as usize; // ensure each connection gets at least one chunk
                self.record_layer.streams.get_mut(stream_id as u32).unwrap().insert_conn_share(*id, share);
            }
        }
    }

    fn send_plain_non_buffering(&mut self, payload: OutboundChunks<'_>, limit: Limit, id: u32) -> usize {
        debug_assert!(self.may_send_application_data);
        debug_assert!(self.record_layer.is_encrypting());

        if payload.is_empty() {
            // Don't send empty fragments.
            return 0;
        }


        self.send_appdata_encrypt(payload, limit, id)
    }

    /// Mark the connection as ready to send application data.
    ///
    /// Also flush `sendable_plaintext` if it is `Some`.  
    pub(crate) fn start_outgoing_traffic(
        &mut self,
        sendable_plaintext: &mut Option<&mut PlainBufsMap>,
    ) {
        self.may_send_application_data = true;
        if let Some(sendable_plaintext) = sendable_plaintext {
            self.flush_plaintext(sendable_plaintext);
        }
    }

    /// Mark the connection as ready to send and receive application data.
    ///
    /// Also flush `sendable_plaintext` if it is `Some`.  
    pub(crate) fn start_traffic(&mut self, sendable_plaintext: &mut Option<&mut PlainBufsMap>) {
        self.may_receive_application_data = true;
        self.start_outgoing_traffic(sendable_plaintext);
    }

    /// Send any buffered plaintext.  Plaintext is buffered if
    /// written during handshake.
    fn flush_plaintext(&mut self, sendable_plaintext: &mut PlainBufsMap) {
        if !self.may_send_application_data {
            return;
        }

        if sendable_plaintext.plain_map.is_empty() {
            return;
        }

        let keys: Vec<_> = sendable_plaintext.plain_map.keys().cloned().collect();

        for key in keys   {
            let mut stream = sendable_plaintext.plain_map.remove(&key).unwrap();
            while let Some(buf) = stream.send_plain_buf.pop() {
                self.send_plain(buf.as_slice().into(), Limit::No, Some(sendable_plaintext), stream.id);
            }
        }
    }

    // Put m into sendable_tls for writing.

   /* fn queue_tls_message(&mut self, m: OutboundOpaqueMessage) {
        self.record_layer.streams.get_or_create(DEFAULT_STREAM_ID).unwrap().send.append(m.encode());
    }*/

    /// Send a raw TLS message, fragmenting it if needed.
    pub(crate) fn send_msg(&mut self, m: Message, must_encrypt: bool, id: u32) {
      let typ = m.payload.content_type();
        if !must_encrypt {
            let msg = &m.into();
            let iter = self
                .message_fragmenter
                .fragment_message(msg);
            for m in iter {
                self.queue_message(m.to_unencrypted_opaque().encode(), id, None, typ);
            }
        } else {
            self.send_msg_encrypt(m.into(), id);
        }
    }

    pub(crate) fn take_received_plaintext(&mut self, bytes: Payload) {
        self.received_plaintext
            .append(bytes.into_vec(), None, ApplicationData);
    }

    #[cfg(feature = "tls12")]
    pub(crate) fn start_encryption_tls12(&mut self, secrets: &ConnectionSecrets, side: Side) {
        let (dec, enc) = secrets.make_cipher_pair(side);
        self.record_layer
            .prepare_message_encrypter(enc);
        self.record_layer
            .prepare_message_decrypter(dec);
    }


    pub(crate) fn missing_extension(&mut self, why: PeerMisbehaved) -> Error {
        self.send_fatal_alert(AlertDescription::MissingExtension, why)
    }

    fn send_warning_alert(&mut self, desc: AlertDescription) {
        warn!("Sending warning alert {:?}", desc);
        self.send_warning_alert_no_log(desc);
    }

    pub(crate) fn process_alert(&mut self, alert: &AlertMessagePayload) -> Result<(), Error> {
        // Reject unknown AlertLevels.
        if let AlertLevel::Unknown(_) = alert.level {
            return Err(self.send_fatal_alert(
                AlertDescription::IllegalParameter,
                Error::AlertReceived(alert.description),
            ));
        }

        // If we get a CloseNotify, make a note to declare EOF to our
        // caller.
        if alert.description == AlertDescription::CloseNotify {
            self.has_received_close_notify = true;
            return Ok(());
        }

        // Warnings are nonfatal for TLS1.2, but outlawed in TLS1.3
        // (except, for no good reason, user_cancelled).

        let err = Error::AlertReceived(alert.description);
        if alert.level == AlertLevel::Warning {
            if self.is_tls13() && alert.description != AlertDescription::UserCanceled {
                return Err(self.send_fatal_alert(AlertDescription::DecodeError, err));
            } else {
                warn!("TLS alert warning received: {:?}", alert);
                return Ok(());
            }
        }


        Err(err)
    }

    pub(crate) fn send_cert_verify_error_alert(&mut self, err: Error) -> Error {
        self.send_fatal_alert(
            match &err {
                Error::InvalidCertificate(e) => e.clone().into(),
                Error::PeerMisbehaved(_) => AlertDescription::IllegalParameter,
                _ => AlertDescription::HandshakeFailure,
            },
            err,
        )
    }

    pub(crate) fn send_fatal_alert(
        &mut self,
        desc: AlertDescription,
        err: impl Into<Error>,
    ) -> Error {
        debug_assert!(!self.sent_fatal_alert);
        let m = Message::build_alert(AlertLevel::Fatal, desc);
        self.send_msg(m, self.record_layer.is_encrypting(), DEFAULT_STREAM_ID);
        self.sent_fatal_alert = true;
        err.into()
    }

    /// Queues a close_notify warning alert to be sent in the next
    /// [`Connection::write_tls`] call.  This informs the peer that the
    /// connection is being closed.
    ///
    /// [`Connection::write_tls`]: crate::Connection::write_tls
    pub fn send_close_notify(&mut self) {
        debug!("Sending warning alert {:?}", AlertDescription::CloseNotify);
        self.send_warning_alert_no_log(AlertDescription::CloseNotify);
    }


    pub(crate) fn eager_send_close_notify(
        &mut self,
        outgoing_tls: &mut [u8],
    ) -> Result<usize, EncryptError> {
        debug_assert!(self.record_layer.is_encrypting());

        let m = Message::build_alert(AlertLevel::Warning, AlertDescription::CloseNotify).into();

        let iter = self
            .message_fragmenter
            .fragment_message(&m);

        self.check_required_size(outgoing_tls, None, iter)?;

        debug!("Sending warning alert {:?}", AlertDescription::CloseNotify);

        let iter = self
            .message_fragmenter
            .fragment_message(&m);

        let written = self.write_fragments(outgoing_tls, None, iter);

        Ok(written)
    }

    fn send_warning_alert_no_log(&mut self, desc: AlertDescription) {
        let m = Message::build_alert(AlertLevel::Warning, desc);
        self.send_msg(m, self.record_layer.is_encrypting(), DEFAULT_STREAM_ID);
    }

    fn check_required_size<'a>(
        &self,
        outgoing_tls: &mut [u8],
        opt_msg: Option<&[u8]>,
        fragments: impl Iterator<Item=OutboundPlainMessage<'a>>,
    ) -> Result<(), EncryptError> {
        let mut required_size = 0;
        if let Some(message) = opt_msg {
            required_size += message.len();
        }

        for m in fragments {
            required_size += m.encoded_len(&self.record_layer);
        }

        if required_size > outgoing_tls.len() {
            return Err(EncryptError::InsufficientSize(InsufficientSizeError {
                required_size,
            }));
        }

        Ok(())
    }

    fn write_fragments<'a>(
        &mut self,
        outgoing_tls: &mut [u8],
        opt_msg: Option<Vec<u8>>,
        fragments: impl Iterator<Item=OutboundPlainMessage<'a>>,
    ) -> usize {
        let mut written = 0;

        if let Some(message) = opt_msg {
            let len = message.len();
            outgoing_tls[written..written + len].copy_from_slice(&message);
            written += len;
        }

        for m in fragments {
            let em = self
                .record_layer
                .encrypt_outgoing(m)
                .encode();

            let len = em.len();
            outgoing_tls[written..written + len].copy_from_slice(&em);
            written += len;
        }

        written
    }

    pub(crate) fn set_max_fragment_size(&mut self, new: Option<usize>) -> Result<(), Error> {
        self.message_fragmenter
            .set_max_fragment_size(new)
    }

    pub(crate) fn get_alpn_protocol(&self) -> Option<&[u8]> {
        self.alpn_protocol
            .as_ref()
            .map(AsRef::as_ref)
    }


    /// Returns true if the caller should call [`tcpls::TcplsSession::recv_on_connection`] as soon
    /// as possible.


    pub fn wants_read(&self, app_buf: &RecvBufMap) -> bool {
        // We want to read more data all the time, except when we have unprocessed plaintext.
        // This provides back-pressure to the TCP buffers. We also don't want to read more after
        // the peer has sent us a close notification.
        //
        // In the handshake case we don't have readable plaintext before the handshake has
        // completed, but also don't want to read if we still have sendable tls.
        app_buf.all_empty()
            && !self.has_received_close_notify
            && (self.may_send_application_data || self.record_layer.streams.all_empty())
    }

    pub fn shuffle_records(&mut self, id: u32, n: usize) {
        self.record_layer.streams.get_mut(id).unwrap().send.shuffle_records(n);
    }

    pub(crate) fn current_io_state(&self, app_buf: Option<&RecvBufMap>) -> IoState {
        IoState {
            tls_bytes_to_write: self.record_layer.streams.total_to_write(),
            plaintext_bytes_to_read: app_buf.unwrap().bytes_to_read(),
            peer_has_closed: self.has_received_close_notify,
        }
    }

    pub(crate) fn is_quic(&self) -> bool {
        self.protocol == Protocol::Quic
    }

    pub(crate) fn should_update_key(
        &mut self,
        key_update_request: &KeyUpdateRequest,
    ) -> Result<bool, Error> {
        match key_update_request {
            KeyUpdateRequest::UpdateNotRequested => Ok(false),
            KeyUpdateRequest::UpdateRequested => Ok(self.queued_key_update_message.is_none()),

            _ => Err(self.send_fatal_alert(
                AlertDescription::IllegalParameter,
                InvalidMessage::InvalidKeyUpdate,
            )),
        }
    }

    pub(crate) fn enqueue_key_update_notification(&mut self) {
        let message = PlainMessage::from(Message::build_key_update_notify());
        self
            .record_layer
            .streams
            .get_or_create(DEFAULT_STREAM_ID)
            .unwrap();
        self.record_layer.encrypt_for_stream(DEFAULT_STREAM_ID);
        let header = &self
            .record_layer
            .streams
            .get_mut(DEFAULT_STREAM_ID)
            .unwrap()
            .build_header(message.payload.bytes().len() as u16);
        self.queued_key_update_message =
            Some(self
                     .record_layer
                     .encrypt_outgoing_tcpls(message.borrow_outbound(), header, None)
                     .encode(),
            );
    }
}

#[cfg(feature = "std")]
impl CommonState {
    /// Send plaintext application data, fragmenting and
    /// encrypting it as it goes out.
    ///
    /// If internal buffers are too small, this function will not accept
    /// all the data.
    pub(crate) fn buffer_plaintext(
        &mut self,
        payload: OutboundChunks<'_>,
        sendable_plaintext: &mut PlainBufsMap,
        id: u32,
    ) -> usize {
        self.perhaps_write_key_update();
        self.send_plain(payload, Limit::No, Some(sendable_plaintext), id)
    }

    pub(crate) fn send_early_plaintext(&mut self, data: &[u8], id: u32) -> usize {
        debug_assert!(self.early_traffic);
        debug_assert!(self.record_layer.is_encrypting());

        if data.is_empty() {
            // Don't send empty fragments.
            return 0;
        }

        self.send_appdata_encrypt(data.into(), Limit::Yes, id)
    }

    /// Encrypt and send some plaintext `data`.  `limit` controls
    /// whether the per-connection buffer limits apply.
    ///
    /// Returns the number of bytes written from `data`: this might
    /// be less than `data.len()` if buffer limits were exceeded.
    fn send_plain(
        &mut self,
        payload: OutboundChunks<'_>,
        limit: Limit,
        sendable_plaintext: Option<&mut PlainBufsMap>,
        id: u32,
    ) -> usize {
        if !self.may_send_application_data {
            // If we haven't completed handshaking, buffer
            // plaintext to send once we do.
            let len = match limit {
                Limit::Yes => sendable_plaintext
                    .expect("Sendable plaintext map not provided")
                    .get_or_create_plain_buf(id)
                    .unwrap()
                    .send_plain_buf
                    .append_limited_copy(payload),
                Limit::No => sendable_plaintext
                    .expect("Sendable plaintext map not provided")
                    .get_or_create_plain_buf(id)
                    .unwrap()
                    .send_plain_buf
                    .append(payload.to_vec(), None, ApplicationData),
            };
            return len;
        }

        self.send_plain_non_buffering(payload, limit, id)
    }

    pub(crate) fn perhaps_write_key_update(&mut self) {
        if let Some(message) = self.queued_key_update_message.take() {
            self.queue_message(message, DEFAULT_STREAM_ID, None, ContentType::Alert);
        }
    }
    // Put m into sendable_tls for writing.
    pub(crate) fn queue_message(&mut self, msg: Vec<u8>, id: u32, tcpls_header: Option<&TcplsHeader>, data_type: ContentType) {
        self.record_layer.streams.get_or_create(id).unwrap().send.append(msg, tcpls_header, data_type);
        self.record_layer.streams.insert_flushable(id as u64);
    }

}

pub(crate) struct SendPlainTextBuf {
    pub(crate) send_plain_buf: ChunkVecBuffer,
    pub(crate) id: u32,
}
#[derive(Default)]
pub(crate) struct PlainBufsMap {
    pub(crate) plain_map: SimpleIdHashMap<SendPlainTextBuf>
}

impl PlainBufsMap {
    pub(crate) fn get_or_create_plain_buf(
        &mut self, stream_id: u32,
    ) -> Result<&mut SendPlainTextBuf, Error> {
        let stream = match self.plain_map.entry(stream_id as u64) {
            hash_map::Entry::Vacant(v) => {

                let s = SendPlainTextBuf {
                    send_plain_buf: ChunkVecBuffer::new(Some(DEFAULT_BUFFER_LIMIT)),
                    id: stream_id,
                };

                v.insert(s)
            },

            hash_map::Entry::Occupied(v) => v.into_mut(),
        };

        Ok(stream)
    }
}

/// Values of this structure are returned from [`Connection::process_new_packets`]
/// and tell the caller the current I/O state of the TLS connection.
///
/// [`Connection::process_new_packets`]: crate::Connection::process_new_packets
#[derive(Debug, Eq, PartialEq)]
pub struct IoState {
    tls_bytes_to_write: usize,
    plaintext_bytes_to_read: usize,
    peer_has_closed: bool,
}

impl IoState {
    pub fn new() -> Self {
        Self {
            tls_bytes_to_write: 0,
            plaintext_bytes_to_read: 0,
            peer_has_closed: false,
        }
    }
    /// How many bytes could be written by [`Connection::write_tls`] if called
    /// right now.  A non-zero value implies [`CommonState::wants_write`].
    ///
    /// [`Connection::write_tls`]: crate::Connection::write_tls
    pub fn tls_bytes_to_write(&self) -> usize {
        self.tls_bytes_to_write
    }

    /// How many plaintext bytes could be obtained via [`std::io::Read`]
    /// without further I/O.
    pub fn plaintext_bytes_to_read(&self) -> usize {
        self.plaintext_bytes_to_read
    }

    /// True if the peer has sent us a close_notify alert.  This is
    /// the TLS mechanism to securely half-close a TLS connection,
    /// and signifies that the peer will not send any further data
    /// on this connection.
    ///
    /// This is also signalled via returning `Ok(0)` from
    /// [`std::io::Read`], after all the received bytes have been
    /// retrieved.
    pub fn peer_has_closed(&self) -> bool {
        self.peer_has_closed
    }
}

pub(crate) trait State<Data>: Send + Sync {

    fn handle<'m>(
        self: Box<Self>,
        cx: &mut Context<'_, Data>,
        message: Message<'m>,
    ) -> Result<Box<dyn State<Data> + 'm>, Error>
    where
        Self: 'm;

    fn export_keying_material(
        &self,
        _output: &mut [u8],
        _label: &[u8],
        _context: Option<&[u8]>,
    ) -> Result<(), Error> {
        Err(Error::HandshakeNotComplete)
    }


    fn extract_secrets(&self) -> Result<PartiallyExtractedSecrets, Error> {
        Err(Error::HandshakeNotComplete)
    }

    fn handle_decrypt_error(&self) {}

    fn into_owned(self: Box<Self>) -> Box<dyn State<Data> + 'static>;
}

pub(crate) struct Context<'a, Data> {
    pub(crate) common: &'a mut CommonState,
    pub(crate) data: &'a mut Data,

    /// Buffered plaintext. This is `Some` if any plaintext was written during handshake and `None`
    /// otherwise.
    pub(crate) sendable_plaintext: Option<&'a mut PlainBufsMap>,
}

/// Side of the connection.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Side {
    /// A client initiates the connection.
    Client,
    /// A server waits for a client to connect.
    Server,
}

impl Side {
    pub(crate) fn peer(&self) -> Self {
        match self {
            Self::Client => Self::Server,
            Self::Server => Self::Client,
        }
    }
}

#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub(crate) enum Protocol {
    Tcp,
    Quic,
    Tcpls,
}

enum Limit {

    #[cfg(feature = "std")]
    Yes,
    No,
}

pub(crate)  struct OutboundTlsMessage {
    pub(crate) data: Vec<u8>,
    pub(crate) send_time: Option<Instant>,
    pub(crate) chunk_num: u32,
    pub(crate) typ: ContentType,
}

impl OutboundTlsMessage {
    pub(crate) fn new(data: Vec<u8>, chunk_num: u32, sent_at: Option<Instant>, typ: ContentType) -> Self {
        Self {
            data,
            send_time: sent_at,
            chunk_num,
            typ,
        }
    }

    /*pub(crate) fn get_payload_as_ref(&self) -> Option<&Vec<u8>> {
        match self.data.len() {
            0 => None,
            _ => Some(self.data.as_ref())
        }
    }*/

    pub(crate) fn get_payload(&self) -> Option<Vec<u8>> {
        match self.data.len() {
            0 => None,
            _ => Some(self.data.clone())
        }
    }
}

const DEFAULT_RECEIVED_PLAINTEXT_LIMIT: usize = 16 * 1024;

pub(crate) const DEFAULT_BUFFER_LIMIT: usize = 64 * 1024;
