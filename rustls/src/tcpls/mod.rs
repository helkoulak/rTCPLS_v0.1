#![allow(missing_docs)]
#![allow(unused_qualifications)]

/// This module contains optional APIs for implementing TCPLS.
use std::{io, println, u32, vec};

use std::io::Write;
use std::net::{Shutdown, SocketAddr};

use std::prelude::rust_2021::{ToString, Vec};
use std::sync::Arc;
use std::time::{Duration, Instant};
use log::trace;

use mio::net::{TcpListener, TcpStream};
use rand::Rng;
use ring::rand::{SecureRandom, SystemRandom};
use crate::{CipherSuite, ClientConfig, ClientConnection,
            Connection, ContentType, Error, HandshakeType, InvalidMessage, IoState,
            NamedGroup, PeerMisbehaved, ProtocolVersion, ServerConfig, ServerConnection, Side, SignatureScheme};
use crate::AlertDescription::IllegalParameter;
use crate::ContentType::ApplicationData;
use crate::crypto::cipherx::OutboundChunks;
use crate::InvalidMessage::{InvalidContentType, InvalidEmptyPayload};
use crate::msgs::codec;
use crate::msgs::enums::{Compression, ECPointFormat, ExtensionType};
use crate::msgs::handshake::{ClientExtension, ClientHelloPayload,
                             HandshakeMessagePayload, HandshakePayload,
                             KeyShareEntry, Random,
                             ServerExtension, ServerHelloPayload, SessionId};
use crate::msgs::message::{InboundOpaqueMessage, Message, MessageError, MessagePayload, OutboundPlainMessage, PlainMessage};
use crate::PeerMisbehaved::{InvalidTcplsJoinToken, TcplsJoinExtensionNotFound};
use crate::ProtocolVersion::TLSv1_2;
use crate::recvbuf::RecvBufMap;
use crate::tcpls::network_address::AddressMap;
use crate::tcpls::outstanding_conn::OutstandingTcpConn;
use crate::tcpls::stream::{SimpleIdHashMap, SimpleIdHashSet, StreamIter};

pub mod frame;
pub mod network_address;
pub mod ranges;
pub mod stream;
pub mod outstanding_conn;

pub const DEFAULT_CONNECTION_ID:u32 = 0;

pub struct TcplsSession {
    pub tls_config: Option<TlsConfig>,
    pub tls_conn: Option<Connection>,
    pub tcp_connections: SimpleIdHashMap<TcpConnection>,
    pub next_conn_id: u32,
    pub address_map: AddressMap,
    pub is_server: bool,
    pub is_closed: bool,
    pub tls_hs_completed: bool,
    pub timeout: Duration,
}

impl TcplsSession {
    pub fn new(is_server: bool) -> Self {
        Self {
            tls_config: None,
            tls_conn: None,
            tcp_connections: SimpleIdHashMap::default(),
            next_conn_id: DEFAULT_CONNECTION_ID,
            address_map: AddressMap::new(),
            is_server,
            is_closed: false,
            tls_hs_completed: false,
            timeout: Duration::from_secs(5),
        }
    }

    pub fn set_timeout(&mut self, timeout: Duration) {
        self.timeout = timeout;
    }

    pub fn tcpls_connect(
        &mut self,
        dest_address: SocketAddr,
        config: Option<Arc<ClientConfig>>,
        server_name: Option<pki_types::ServerName<'static>>,
        is_server: bool,
    ) {
        assert_ne!(is_server, true);

        let socket = TcpStream::connect(dest_address).expect("TCP connection establishment failed");

        if self.next_conn_id == DEFAULT_CONNECTION_ID {
            match config {
                Some(ref _client_config) => (),
                None => panic!("No ClientConfig supplied"),
            };
            let client_conn = ClientConnection::new(config.as_ref().unwrap().clone(), server_name.unwrap())
                .expect("Establishment of TLS session failed");
            let _ = self.tls_conn.insert(Connection::from(client_conn));
            let _ = self.tls_config.insert(TlsConfig::Client(config.unwrap()));

            self.create_tcpls_connection_object(socket);
        } else {

            self.tls_conn.as_mut()
                .unwrap()
                .outstanding_tcp_conns
                .as_mut_ref()
                .insert(self.next_conn_id as u64, OutstandingTcpConn::new(socket));

        }
        self.tls_conn.as_mut().unwrap().conns_rtts.insert(self.next_conn_id as u64, Duration::default());
        self.next_conn_id += 1;
    }

    pub fn join_tcp_connection(&mut self,  id: u64) -> Result<(), Error> {
        assert_eq!(self.tls_conn.as_ref().unwrap().side, Side::Client);
        assert!(!self.tls_conn.as_ref().unwrap().is_handshaking());

        // Check if request to join not already sent
        match self.tls_conn.as_mut()
            .unwrap()
            .outstanding_tcp_conns
            .as_mut_ref()
            .get_mut(&id)
            .unwrap()
            .request_sent {
            true => return Ok(()),
            false => (),
        };

        let client_conn = match self.tls_conn.as_mut().unwrap() {
            Connection::Client(conn) => conn,
            Connection::Server(_conn) => panic!("Server connection found. Client connection required")
        };

        // Emit fake client hello containing the TcplsJoin extension

        let mut ch_payload = get_sample_ch_payload();

        //Get next available token and push TcplsJoin Extension in ch payload
        let tcpls_token = match client_conn.next_tcpls_token() {
            Some(token) => token,
            None => return Err(Error::General("No tcpls token found".to_string())),
        };
        ch_payload.extensions.push(ClientExtension::TcplsJoin(tcpls_token));


        let  chp = HandshakeMessagePayload {
            typ: HandshakeType::ClientHello,
            payload: HandshakePayload::ClientHello(ch_payload)
        };

        let ch = Message {
            version: ProtocolVersion::TLSv1_0,
            payload: MessagePayload::handshake(chp),
        };

            trace!("Sending fake ClientHello {:#?}", ch);

        let request = PlainMessage::from(ch)
            .into_unencrypted_opaque()
            .encode();


          match self.tls_conn.as_mut()
                .unwrap()
                .outstanding_tcp_conns
                .as_mut_ref()
                .get_mut(&id)
                .unwrap()
                .socket
                .write(request.as_slice()) {
              Ok(_n) => {
                  self.tls_conn.as_mut()
                      .unwrap()
                      .outstanding_tcp_conns
                      .as_mut_ref()
                      .get_mut(&id)
                      .unwrap()
                      .request_sent = true;
              }
              Err(ref err) if err.kind() == io::ErrorKind::WouldBlock => return Ok(()),
              Err(_err) => {
                  return Err(Error::General("Send fake CH failed".to_string()));
              }
          };


        Ok(())
    }


    pub fn create_tcpls_connection_object(&mut self, socket: TcpStream) -> u32 {
        let mut tcp_conn = TcpConnection::new(socket, self.next_conn_id, TcplsConnectionState::CONNECTED);

        let new_id = self.next_conn_id;
        tcp_conn.local_address_id = self.address_map.next_local_address_id;
        tcp_conn.remote_address_id = self.address_map.next_peer_address_id;

        if tcp_conn.connection_id == DEFAULT_CONNECTION_ID {
            tcp_conn.is_primary = true;
        }

        self.tcp_connections.insert(new_id as u64, tcp_conn);

        self.address_map.next_local_address_id += 1;
        self.address_map.next_peer_address_id += 1;

        new_id
    }

    pub fn server_accept_connection(
        &mut self,
        listener: &mut TcpListener,
        config: Arc<ServerConfig>,
    ) -> Result<u32, io::Error> {
        let conn_id;
        let (socket, _remote_add) = match listener.accept() {
            Ok((socket, remote_add)) => {
                (socket, remote_add)
            },
            Err(err) => return Err(err),
        };

        if self.next_conn_id == DEFAULT_CONNECTION_ID {
            self.is_server = true;

            let server_conn = ServerConnection::new(config.clone())
                .expect("Establishing a TLS session has failed");
            let _ = self.tls_conn.insert(Connection::from(server_conn));
            let _ = self.tls_config.insert(TlsConfig::from(config));
            conn_id = self.create_tcpls_connection_object(socket);
        }else {
            self.tls_conn
                .as_mut()
                .unwrap()
                .outstanding_tcp_conns.as_mut_ref().insert(self.next_conn_id as u64, OutstandingTcpConn::new(socket));
            conn_id = self.next_conn_id;

        }
        self.tls_conn.as_mut().unwrap().conns_rtts.insert(self.next_conn_id as u64, Duration::default());
        self.next_conn_id += 1;
        Ok(conn_id)
    }
    /// Store data in send buffer
    pub fn stream_send(&mut self, str_id: u32, input: &[u8]) -> Result<usize, Error> {

        self.tls_conn.as_mut().unwrap().write_to = str_id;
        let buffered = self.tls_conn.as_mut().unwrap().writer().write(input).expect("Could not write data to stream");
        Ok(buffered)
    }

    /// Flush bytes of a certain stream or a set of streams on specified byte-oriented sink.
    pub fn send_on_connection(&mut self, ids: Option<Vec<u64>>, flushable_streams: Option<SimpleIdHashSet>) -> Result<usize, Error> {
        let tls_conn = self.tls_conn.as_mut().unwrap();

        let conn_ids: Vec<u64> = match ids {
            None => self.tcp_connections.keys().cloned().collect(),
            Some(ids) => ids,
        };



        //Flush streams selected by the app or flush all
        let stream_ids = match flushable_streams {
            Some(set) => StreamIter::from(&set),
            None => tls_conn.record_layer.streams.flushable(),
        };

        let mut done = 0;
       /* let mut chunk_num: usize = 0;*/



        for id in stream_ids {
            match tls_conn.record_layer.streams.get_mut(id as u32) {
                Some(_stream) => {},
                None => return Err(Error::BufNotFound),
            };


            let mut len = tls_conn.record_layer.streams.get_mut(id as u32).unwrap().send.len();
            let chunk_count = tls_conn.record_layer.streams.get_mut(id as u32).unwrap().send.chunks_num();
            let mut sent;

            if !tls_conn.record_layer.streams.get_mut(id as u32).unwrap().shares_already_calculated() {
                tls_conn.calculate_conn_shares(chunk_count, &conn_ids, id);
                println!("Shares {:?}", tls_conn.record_layer.streams.get_mut(id as u32).unwrap().conn_shares);

            }


            while len > 0 {
                for conn_id in &conn_ids {
                    let conn_to_use = match tls_conn.record_layer.streams.get_mut(id as u32).unwrap().get_conn() {
                        Some(id) => id,
                        None => *conn_id,
                    };

                    if *tls_conn.record_layer.streams.get_mut(id as u32).unwrap().get_share(conn_to_use) == 0 {
                        continue
                    }
                    let socket = &mut self.tcp_connections.get_mut(&conn_to_use).unwrap().socket;
                    let chunk = match tls_conn.record_layer.streams.get_mut(id as u32).unwrap().send.get_chunk() {
                        Some(ch) => ch,
                        None => {
                            break
                        },
                    };
                    let chunk_len = chunk.data.len();
                    sent = match socket.write(chunk.data.as_slice()) {
                        Ok(0) => return Ok(done),
                        Ok(sent) => {
                            tls_conn.record_layer.streams.get_mut(id as u32).unwrap().send.consume_chunk(sent, chunk);
                            if sent < chunk_len {
                                tls_conn.record_layer.streams.get_mut(id as u32).unwrap().set_conn(Some(conn_to_use));
                            } else {
                                *tls_conn.record_layer.streams.get_mut(id as u32).unwrap().get_share(conn_to_use) -= 1;
                                tls_conn.record_layer.streams.get_mut(id as u32).unwrap().set_conn(None);
                            }
                            sent
                        },

                        Err(ref err) if err.kind() == io::ErrorKind::WouldBlock => {
                            sent = 0;
                            tls_conn.record_layer.streams.get_mut(id as u32).unwrap().send.consume_chunk(sent, chunk);
                            return Ok(done)
                        },
                        _error => {
                            return Err(Error::General("Data sending on socket failed".to_string()))
                        },
                    };


                    len -= sent;
                    if len == 0 { break }
                    done += sent;
                }
            }

            if len == 0 {
                tls_conn.record_layer.streams.reset_stream(id as u32);
            }
        }

        Ok(done)
    }

    /// Receive data on specified TCP socket
    pub fn recv_on_connection(&mut self, id: u32) -> Result<usize, io::Error> {
        let socket = match self.tcp_connections.get_mut(&(id as u64)) {
            Some(conn) => &mut conn.socket,
            None => panic!("Socket of specified TCP connection does not exist")
        };
        self.tls_conn.as_mut().unwrap().set_connection_in_use(id);
       self.tls_conn.as_mut().unwrap().read_tls(socket)
    }


    pub fn process_received(
        &mut self,
        app_buffers: &mut RecvBufMap,
    ) -> Result<IoState, Error> {
        let mut io_state = IoState::new();
        let def_ids: Vec<u64> = self.tls_conn.as_mut().unwrap().get_deframer_ids();
        // Loop over deframer buffers that have data received
        loop {
            for def_id in &def_ids {
                self.tls_conn.as_mut().unwrap().set_connection_in_use(*def_id as u32);
                io_state = match self.tls_conn.as_mut().unwrap().process_new_packets(&mut self.tcp_connections, app_buffers) {
                    Ok(io_state) => io_state,
                    Err(err) => return Err(err),
                };
            }
            if self.tls_conn.as_mut().unwrap().received_data_processed {
                self.tls_conn.as_mut().unwrap().received_data_processed = false;
                continue
            } else {
                break
            }
        }

        Ok(io_state)
    }
    pub fn process_join_request(&mut self, id: u64) -> Result<(), Error> {

        assert!(!self.tls_conn.as_ref().unwrap().is_handshaking());
        let bytes_to_process = self.tls_conn.as_mut().unwrap().outstanding_tcp_conns.as_mut_ref().get_mut(&id).unwrap().used;

        let mut bytes: Vec<u8> = vec![0u8; bytes_to_process];
            bytes.clone_from_slice(&self.tls_conn.as_mut()
                .unwrap()
                .outstanding_tcp_conns
                .as_mut_ref()
                .get_mut(&id).unwrap().rcv_buf[..bytes_to_process]);
        let mut rd = codec::ReaderMut::init(&mut bytes);

        let m = match InboundOpaqueMessage::read(&mut rd) {
            Ok(m) => m,
            Err(msg_err) => {
                let err_kind = match msg_err {
                    MessageError::TooShortForHeader | MessageError::TooShortForLength => {
                        return Ok(())
                    }
                    MessageError::InvalidEmptyPayload => InvalidMessage::InvalidEmptyPayload,
                    MessageError::MessageTooLarge => InvalidMessage::MessageTooLarge,
                    MessageError::InvalidContentType => InvalidMessage::InvalidContentType,
                    MessageError::UnknownProtocolVersion => {
                        InvalidMessage::UnknownProtocolVersion
                    }
                };

                return Err(Error::from(err_kind));
            }
        };

        if m.typ != ContentType::Handshake {
            return Err(Error::InvalidMessage(InvalidContentType))
        }

        let msg = Message::try_from(m.into_plain_message()).unwrap();

        //Validate token received and send fake sh
        match self.tls_conn.as_ref().unwrap().side {
            Side::Client => {
                //
                 if !msg.is_handshake_type(HandshakeType::ServerHello) {
                     self.tls_conn.as_mut()
                         .unwrap().outstanding_tcp_conns.as_mut_ref().remove(&id).unwrap()
                         .socket.shutdown(Shutdown::Both).expect("Error while shutting connection down");
                     return Err(Error::General("Expected Server Hello".to_string()))
                 }
            },
            Side::Server => {
                if msg.is_handshake_type(HandshakeType::ClientHello) {
                    self.handle_fake_client_hello(&msg, id).expect("Processing ch failed");
                } else {
                    self.tls_conn.as_mut()
                        .unwrap().outstanding_tcp_conns.as_mut_ref().remove(&id).unwrap()
                        .socket.shutdown(Shutdown::Both).expect("Error while shutting connection down");
                    return Err(Error::General("Expected Client Hello".to_string()))
                }

            },
        };


        //Upon successful token validation join socket into tcpls session
        self.join_conn_to_session(id);

        Ok(())

    }

    fn join_conn_to_session(&mut self, id: u64) {
        let socket = self.tls_conn.as_mut()
            .unwrap().outstanding_tcp_conns.as_mut_ref().remove(&id).unwrap().socket;
        self.tcp_connections.insert(id, TcpConnection {
            connection_id: id as u32,
            socket,
            local_address_id: 0,
            remote_address_id: 0,
            nbr_bytes_received: 0,
            nbr_records_received: 0,
            is_primary: false,
            state: TcplsConnectionState::CONNECTED,
            probe_initiated: false,
            probe_rand: None,
            probe_sent_at: None,
        });
    }
    fn handle_fake_client_hello(&mut self,  m: &Message, id: u64) -> Result<(), Error>{
        let client_hello = match self.process_fake_client_hello(m) {
            Ok(chp) => chp,
            Err(e) => return Err(e),
        };
        self.emit_fake_server_hello(client_hello, id);
        Ok(())
    }

    fn emit_fake_server_hello(&mut self, client_hello: &ClientHelloPayload, id: u64) {
        let mut rng = rand::thread_rng();
        let random: [u8; 32] = rng.gen();
        let mut extensions = Vec::new();

        let kse = client_hello.keyshare_extension().unwrap();
        extensions.push(ServerExtension::KeyShare(kse[0].clone()));
        extensions.push(ServerExtension::SupportedVersions(ProtocolVersion::TLSv1_3));



        let sh = Message {
            version: ProtocolVersion::TLSv1_2,
            payload: MessagePayload::handshake(HandshakeMessagePayload {
                typ: HandshakeType::ServerHello,
                payload: HandshakePayload::ServerHello(ServerHelloPayload {
                    legacy_version: ProtocolVersion::TLSv1_2,
                    random: Random::from(random),
                    session_id: SessionId::empty(),
                    cipher_suite: self.tls_conn.as_ref().unwrap().suite.unwrap().suite(),
                    compression_method: Compression::Null,
                    extensions,
                }),
            }),
        };

        trace!("sending fake server hello {:?}", sh);
        self.tls_conn.as_mut()
            .unwrap().outstanding_tcp_conns.as_mut_ref().get_mut(&id).unwrap().socket.write(PlainMessage::from(sh)
            .into_unencrypted_opaque()
            .encode()
            .as_slice())
            .expect("Sending fake server hello failed");
    }

    fn process_fake_client_hello<'a>(
        &mut self,
        m: &'a Message,
    ) -> Result<&'a ClientHelloPayload, Error>{
        let client_hello =
            require_handshake_msg!(m, HandshakeType::ClientHello, HandshakePayload::ClientHello)?;
        trace!("we got a clienthello {:?}", client_hello);


        if client_hello.has_duplicate_extension() {
            return Err(Error::from(PeerMisbehaved::DuplicateClientHelloExtensions));
        }

        let tcpls_join_ext = match client_hello.find_extension(ExtensionType::TcplsJoin) {
            Some(tcpls_join) => tcpls_join,
            None =>  return Err(Error::PeerMisbehaved(TcplsJoinExtensionNotFound))
        };

        let token = match tcpls_join_ext {
            ClientExtension::TcplsJoin(ref token) => token,
            _ => return Err(Error::InvalidMessage(InvalidEmptyPayload))
        };

        //Validate token
        if let Some(index) = self.tls_conn.as_mut().unwrap().tcpls_tokens.iter().position(|&x| x == *token) {
            self.tls_conn.as_mut().unwrap().tcpls_tokens.remove(index);
            /*cx.common.join_msg_received = true;*/
        } else {
            self.tls_conn.as_mut().unwrap()
                .send_fatal_alert(IllegalParameter, Error::PeerMisbehaved(InvalidTcplsJoinToken));
            return Err(Error::PeerMisbehaved(InvalidTcplsJoinToken));
        };

        Ok(client_hello)
    }

    pub fn get_socket(&mut self, id: u64) -> &mut TcpStream {
        match self.tcp_connections.get_mut(&id) {
            Some(socket) => &mut socket.socket,
            None => match self.tls_conn.as_mut()
                .unwrap().outstanding_tcp_conns.as_mut_ref().get_mut(&id) {
                Some(socket) => &mut socket.socket,
                None => panic!("No socket found for the provided token"),
            },
        }
    }

    pub fn probe_rtt(&mut self) -> Result<(), Error> {
        if self.tls_conn.as_ref().unwrap().is_handshaking(){
            return Err(Error::General("Still handshaking".to_string()))
        }
        let rng = SystemRandom::new();
        let mut buf = [0u8; 5];
        buf[4] = 0x0a;

        for conn in self.tcp_connections.iter_mut(){
            rng.fill(&mut buf[0..4]).unwrap();
            match self.tls_conn.as_mut().unwrap().send_single_probe(OutboundPlainMessage{
                typ: ApplicationData,
                version: TLSv1_2,
                payload: OutboundChunks::Single(&buf)
            }){
                Some(enc_probe) => {
                    conn.1.probe_rand = Some(u32::from_be_bytes([buf[0],buf[1],buf[2],buf[3]]));
                    conn.1.probe_initiated = true;
                    conn.1.probe_sent_at = Some(Instant::now());
                    conn.1.socket.write(&enc_probe.encode()).unwrap();
                },
                None => {},
            };
        }

       Ok(())

    }

    pub fn free_session_resources(&mut self) {
        self.tls_config = None;
        self.tls_conn = None;
        self.tcp_connections = SimpleIdHashMap::default();
        self.next_conn_id = DEFAULT_CONNECTION_ID;
        self.address_map = AddressMap::new();
        self.is_closed = false;
        self.tls_hs_completed = false;
    }

    pub fn on_timeout(&mut self) {
        let conn_id = *self.tls_conn.as_ref().unwrap().conns_rtts.iter().min_by_key(|(_, &value)| value).unwrap().0;
        for str in self.tls_conn.as_mut().unwrap().record_layer.streams.mut_iter() {
            for un_ack_chunk in str.1.send.mut_iter_not_ack(){
                let time_elapsed  = un_ack_chunk.1.send_time.unwrap().elapsed();
                if time_elapsed >= self.timeout {
                    println!("Resending packet {} of stream {}", un_ack_chunk.1.chunk_num, str.1.id);
                    self.tcp_connections.get_mut(&conn_id).unwrap().socket.write(&un_ack_chunk.1.data).unwrap();
                }
            }
        }
    }


}




pub enum TlsConfig {
    Client(Arc<ClientConfig>),
    Server(Arc<ServerConfig>),
}

impl From<Arc<ClientConfig>> for TlsConfig {
    fn from(c: Arc<ClientConfig>) -> Self {
        Self::Client(c)
    }
}

impl From<Arc<ServerConfig>> for TlsConfig {
    fn from(s: Arc<ServerConfig>) -> Self {
        Self::Server(s)
    }
}

pub struct TcpConnection {
    pub connection_id: u32,
    pub socket: TcpStream,
    pub local_address_id: u8,
    pub remote_address_id: u8,
    pub nbr_bytes_received: u32,
    // nbr records received on this con since the last ack sent
    pub nbr_records_received: u32,
    // nbr records received on this con since the last ack sent
    pub is_primary: bool,
    // Is this connection the default one?
    pub state: TcplsConnectionState,
    pub probe_initiated: bool,
    pub probe_rand: Option<u32>,
    pub probe_sent_at: Option<Instant>,

}

impl TcpConnection {
    pub fn new(socket: TcpStream, id: u32, state: TcplsConnectionState) -> Self {
        Self {
            connection_id: id,
            socket,
            local_address_id: 0,
            remote_address_id: 0,
            nbr_bytes_received: 0,
            nbr_records_received: 0,
            is_primary: false,
            state,
            probe_initiated: false,
            probe_rand: None,
            probe_sent_at: None,
        }
    }
}

pub enum TcplsConnectionState {
    CLOSED,
    INITIALIZED,
    STARTED, // Handshake started.
    FAILED,
    CONNECTING,
    CONNECTED, // Handshake completed.
    JOINED,
}







pub fn server_create_listener(local_address: &str, port: Option<u16>) -> TcpListener {
    let mut addr: SocketAddr = local_address.parse().unwrap();

    if let Some(port) = port { addr.set_port(port) }

    TcpListener::bind(addr).expect("cannot listen on port")
}



fn get_sample_ch_payload() -> ClientHelloPayload {
    let mut rng = rand::thread_rng();
    let random: [u8; 32] = rng.gen();
    ClientHelloPayload {
        client_version: ProtocolVersion::TLSv1_2,
        random: Random::from(random),
        session_id: SessionId::empty(),
        cipher_suites: vec![CipherSuite::TLS_DH_anon_WITH_AES_256_CBC_SHA256],
        compression_methods: vec![Compression::Null],
        extensions: vec![
            ClientExtension::EcPointFormats(ECPointFormat::SUPPORTED.to_vec()),
            ClientExtension::NamedGroups(vec![NamedGroup::X25519]),
            ClientExtension::SignatureAlgorithms(vec![SignatureScheme::ECDSA_NISTP256_SHA256]),
            ClientExtension::SupportedVersions(vec![ProtocolVersion::TLSv1_3]),
            ClientExtension::KeyShare(vec![KeyShareEntry::new(NamedGroup::X25519, &[1, 2, 3])]),

        ],
    }
}
