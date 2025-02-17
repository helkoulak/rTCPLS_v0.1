#[macro_use]
extern crate serde_derive;

use std::{io, net, thread};
use std::io::BufReader;
use std::net::ToSocketAddrs;
use std::io::Write;

use std::str;
use std::sync::Arc;
use std::{fs, process};
use std::fs::{File, OpenOptions};
use std::ops::DerefMut;
use std::time::{Duration, Instant};
use docopt::Docopt;
use log::LevelFilter;
use mio::net::TcpStream;
use mio::Token;
use pki_types::{CertificateDer, PrivateKeyDer, ServerName};


use rustls::crypto::{ring as provider, CryptoProvider};
use rustls::recvbuf::RecvBufMap;
use rustls::tcpls::{TcplsSession, TlsConfig};
use rustls::{ClientConnection, Connection, RootCertStore};
use rustls::tcpls::outstanding_conn::OutstandingTcpConn;

const CONNECTION1: mio::Token = mio::Token(0);


struct TlsClient {
    closing: bool,
    clean_closure: bool,
    tcpls_session: TcplsSession,
    all_joined: bool,
    data_sent: bool,
    poll: mio::Poll,
    down_req_sent: bool,
    download_time: Instant,
    reg_conns: Vec<usize>,
    output_file: File,
}

impl TlsClient {
    fn new( ) -> Self {
        Self {
            closing: false,
            clean_closure: false,
            tcpls_session: TcplsSession::new(false),
            all_joined: false,
            data_sent: false,
            poll: mio::Poll::new().unwrap(),
            down_req_sent:false,
            download_time: Instant::now(),
            reg_conns: Vec::default(),
            output_file: OpenOptions::new()
                .write(true)
                .truncate(true)
                .create(true)
                .open("output.txt").unwrap(),
        }
    }

    /// Handles events sent to the TlsClient by mio::Poll
    fn handle_event(&mut self, ev: &mio::event::Event, recv_map: &mut RecvBufMap) {

        let token = &ev.token();

        if ev.is_readable() {
            self.do_read(recv_map, token.0 as u64);
            if !self.tcpls_session.tls_conn.as_ref().unwrap().is_handshaking() {
                if self.tcpls_session.tls_conn.as_mut().unwrap().outstanding_tcp_conns.has_otustanding_requests() {
                    let keys: Vec<u64> = self.tcpls_session.tls_conn.as_mut().unwrap().outstanding_tcp_conns.as_mut_ref().keys().cloned().collect();
                    for id in keys {
                        if !self.reg_conns.contains(&token.0){
                            self.register(recv_map, Token(id as usize));
                            self.reg_conns.push(token.0);
                        }

                        self.join_outstanding(id);

                    }
                }

                if self.tcpls_session.tcp_connections.len() == 2 && !self.down_req_sent {
                    println!("Send download request");
                    self.tcpls_session.stream_send(1, b"GET DATA".as_slice()).expect("buffering failed");
                    self.download_time.clone_from(&Instant::now());
                    self.tcpls_session.send_on_connection(None, None).expect("Sending on connection failed");
                    self.down_req_sent = true;

                }


            }
        }

        if ev.is_writable() {
            self.do_write(token.0 as u64);
        }

        if self.is_closed() {
            println!("Connection closed");
            process::exit(if self.clean_closure { 0 } else { 1 });
        }
    }

    /// We're ready to do a read.
    fn do_read(&mut self, app_buffers: &mut RecvBufMap, id: u64) {
        if self.tcpls_session.tls_conn.as_mut().unwrap().outstanding_tcp_conns.as_mut_ref().contains_key(&id) {
            if !self.tcpls_session.tls_conn.as_mut().unwrap().is_handshaking() {
                self.process_join_response(id);
            }
            return;
        }
        // Read TLS data.  This fails if the underlying TCP connection
        // is broken.

        match self.tcpls_session.recv_on_connection(id as u32) {
            Err(error) => {
                if error.kind() == io::ErrorKind::WouldBlock {
                    return;
                }
                println!("TLS read error: {:?}", error);
                self.closing = true;
                return;
            }

            // If we're ready but there's no data: EOF.
            Ok(0) => {
                println!("EOF");
                self.closing = true;
                self.clean_closure = true;
                return;
            }

            Ok(_) => {}
        };

        // Reading some TLS data might have yielded new TLS
        // messages to process.  Errors from this indicate
        // TLS protocol problems and are fatal.
        let io_state = match self.tcpls_session.process_received(app_buffers) {
            Ok(io_state) => io_state,
            Err(err) => {
                println!("TLS error: {:?}", err);
                self.closing = true;
                return;
            }
        };

        if app_buffers.get(1).unwrap().complete {
            let t = self.download_time.elapsed().as_secs_f64();
            let mut file =

            // Write the formatted string to the file
            writeln!(
                self.output_file,
                "Time taken to download {} Bytes is {:?}",
                app_buffers.get(1).unwrap().offset , t
            ).unwrap();
            self.close_connection();
        }

        // If wethat fails, the peer might have started a clean TLS-level
        // session closure.
        if io_state.peer_has_closed() {
            self.clean_closure = true;
            self.closing = true;
        }
    }

    fn do_write(&mut self, id: u64) {

        if self.tcpls_session.tcp_connections.contains_key(&id) {
            self.tcpls_session.send_on_connection(None, None).expect("Send on connection failed");
        }

    }

    fn close_connection(&mut self) {
        for conn in self.tcpls_session.tcp_connections.iter_mut() {
            conn.1.socket.shutdown(net::Shutdown::Both).expect("TODO: panic message");
        }
    }

    /// Registers self as a 'listener' in mio::Registry
    fn register(&mut self, recv_map: &RecvBufMap, token: Token) {
        let interest = self.event_set(recv_map, token.0 as u64);
        let  socket = self.tcpls_session.get_socket(token.0 as u64);
        self.poll.registry()
            .register(socket, token, interest)
            .unwrap();
    }

    /// Reregisters self as a 'listener' in mio::Registry.
    fn reregister(&mut self, recv_map: & RecvBufMap, token: Token) {

        let interest = self.event_set(recv_map, token.0 as u64);
        let  socket = self.tcpls_session.get_socket(token.0 as u64);
        self.poll.registry()
            .reregister(socket, token, interest)
            .unwrap();
    }

    /// Use wants_read/wants_write to register for different mio-level
    /// IO readiness events.
    fn event_set(&mut self, app_buf: & RecvBufMap, id: u64) -> mio::Interest {

        let rd = match self.tcpls_session.tls_conn.as_mut().unwrap().outstanding_tcp_conns.as_mut_ref().contains_key(&id) {
            true => self.tcpls_session.tls_conn.as_mut().unwrap().outstanding_tcp_conns.wants_read(id),
            false => self.tcpls_session.tls_conn.as_mut().unwrap().wants_read(app_buf),
        };
        let wr = match self.tcpls_session.tls_conn.as_mut().unwrap().outstanding_tcp_conns.as_mut_ref().contains_key(&id) {
            true => self.tcpls_session.tls_conn.as_mut().unwrap().outstanding_tcp_conns.wants_write(id),
            false => self.tcpls_session.tls_conn.as_mut().unwrap().wants_write(None),
        };

        if rd && wr {
            mio::Interest::READABLE | mio::Interest::WRITABLE
        } else if wr {
            mio::Interest::WRITABLE
        } else {
            mio::Interest::READABLE
        }
    }

    fn is_closed(&self) -> bool {
        self.closing
    }



    pub(crate) fn join_outstanding(&mut self, id: u64) {
        self.tcpls_session.join_tcp_connection(id).expect("sending join request failed");
    }

    pub(crate) fn process_join_response(&mut self, id: u64) {
        match self.tcpls_session.tls_conn.as_mut()
            .unwrap()
            .outstanding_tcp_conns
            .as_mut_ref()
            .get_mut(&id)
            .unwrap()
            .receive_join_request() {
            Ok(_bytes) => (),
            Err(ref error) => if error.kind() == io::ErrorKind::WouldBlock {
                return;
            } else {
                panic!("{:?}", error)
            },

        }

        match self.tcpls_session.process_join_request(id) {
            Ok(()) => {
                self.all_joined = self.tcpls_session.tls_conn.as_mut()
                    .unwrap()
                    .outstanding_tcp_conns
                    .as_mut_ref().is_empty();
                return
            },
            Err(err) => panic!("{:?}", err),
        };
    }

}


const USAGE: &str = "
Connects to the TCPLS server at hostname:PORT.  The default PORT
is 443.  By default, this reads a request from stdin (to EOF)
before making the connection.

If --cafile is not supplied, a built-in set of CA certificates
are used from the webpki-roots crate.

Usage:
  client_tcpls_mp [options] [--suite SUITE ...] [--proto PROTO ...] [--protover PROTOVER ...] <hostname>
  client_tcpls_mp (--version | -v)
  client_tcpls_mp (--help | -h)

Options:
    -p, --port PORT     Connect to PORT [default: 443].
    --http              Send a basic HTTP GET request for /.
    --cafile CAFILE     Read root certificates from CAFILE.
    --auth-key KEY      Read client authentication key from KEY.
    --auth-certs CERTS  Read client authentication certificates from CERTS.
                        CERTS must match up with KEY.
    --protover VERSION  Disable default TLS version list, and use
                        VERSION instead.  May be used multiple times.
    --suite SUITE       Disable default cipher suite list, and use
                        SUITE instead.  May be used multiple times.
    --proto PROTOCOL    Send ALPN extension containing PROTOCOL.
                        May be used multiple times to offer several protocols.
    --no-tickets        Disable session ticket support.
    --no-sni            Disable server name indication support.
    --insecure          Disable certificate verification.
    --verbose           Emit log output.
    --max-frag-size M   Limit outgoing messages to M bytes.
    --version, -v       Show tool version.
    --help, -h          Show this screen.
";

#[derive(Debug, Deserialize)]
struct Args {
    flag_port: Option<u16>,
    flag_verbose: bool,
    flag_protover: Vec<String>,
    flag_suite: Vec<String>,
    flag_proto: Vec<String>,
    flag_max_frag_size: Option<usize>,
    flag_cafile: Option<String>,
    flag_no_tickets: bool,
    flag_no_sni: bool,
    flag_insecure: bool,
    flag_auth_key: Option<String>,
    flag_auth_certs: Option<String>,
    arg_hostname: String,
}


fn find_suite(name: &str) -> Option<rustls::SupportedCipherSuite> {
    for suite in provider::ALL_CIPHER_SUITES {
        let sname = format!("{:?}", suite.suite()).to_lowercase();

        if sname == name.to_string().to_lowercase() {
            return Some(*suite);
        }
    }

    None
}

/// Make a vector of ciphersuites named in `suites`
fn lookup_suites(suites: &[String]) -> Vec<rustls::SupportedCipherSuite> {
    let mut out = Vec::new();

    for csname in suites {
        let scs = find_suite(csname);
        match scs {
            Some(s) => out.push(s),
            None => panic!("cannot look up ciphersuite '{}'", csname),
        }
    }

    out
}

/// Make a vector of protocol versions named in `versions`
fn lookup_versions(versions: &[String]) -> Vec<&'static rustls::SupportedProtocolVersion> {
    let mut out = Vec::new();

    for vname in versions {
        let version = match vname.as_ref() {
            "1.2" => &rustls::version::TLS12,
            "1.3" => &rustls::version::TLS13,
            _ => panic!(
                "cannot look up version '{}', valid are '1.2' and '1.3'",
                vname
            ),
        };
        out.push(version);
    }

    out
}

fn load_certs(filename: &str) -> Vec<CertificateDer<'static>> {
    let certfile = fs::File::open(filename).expect("cannot open certificate file");
    let mut reader = BufReader::new(certfile);
    rustls_pemfile::certs(&mut reader)
        .map(|result| result.unwrap())
        .collect()
}

fn load_private_key(filename: &str) -> PrivateKeyDer<'static> {
    let keyfile = fs::File::open(filename).expect("cannot open private key file");
    let mut reader = BufReader::new(keyfile);

    loop {
        match rustls_pemfile::read_one(&mut reader).expect("cannot parse private key .pem file") {
            Some(rustls_pemfile::Item::Pkcs1Key(key)) => return key.into(),
            Some(rustls_pemfile::Item::Pkcs8Key(key)) => return key.into(),
            Some(rustls_pemfile::Item::Sec1Key(key)) => return key.into(),
            None => break,
            _ => {}
        }
    }

    panic!(
        "no keys found in {:?} (encrypted keys not supported)",
        filename
    );
}

mod danger {
    use pki_types::{CertificateDer, ServerName, UnixTime};

    use rustls::client::danger::HandshakeSignatureValid;
    use rustls::crypto::{verify_tls12_signature, verify_tls13_signature, CryptoProvider};
    use rustls::DigitallySignedStruct;

    #[derive(Debug)]
    pub struct NoCertificateVerification(CryptoProvider);

    impl NoCertificateVerification {
        pub fn new(provider: CryptoProvider) -> Self {
            Self(provider)
        }
    }

    impl rustls::client::danger::ServerCertVerifier for NoCertificateVerification {
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp: &[u8],
            _now: UnixTime,
        ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            verify_tls12_signature(
                message,
                cert,
                dss,
                &self.0.signature_verification_algorithms,
            )
        }

        fn verify_tls13_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            verify_tls13_signature(
                message,
                cert,
                dss,
                &self.0.signature_verification_algorithms,
            )
        }

        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            self.0
                .signature_verification_algorithms
                .supported_schemes()
        }
    }
}

/// Build a `ClientConfig` from our arguments
fn make_config(args: &Args) -> Arc<rustls::ClientConfig> {
    let mut root_store = RootCertStore::empty();

    if args.flag_cafile.is_some() {
        let cafile = args.flag_cafile.as_ref().unwrap();

        let certfile = fs::File::open(cafile).expect("Cannot open CA file");
        let mut reader = BufReader::new(certfile);
        root_store.add_parsable_certificates(
            rustls_pemfile::certs(&mut reader).map(|result| result.unwrap()),
        );
    } else {
        root_store.extend(
            webpki_roots::TLS_SERVER_ROOTS
                .iter()
                .cloned(),
        );
    }

    let suites = if !args.flag_suite.is_empty() {
        lookup_suites(&args.flag_suite)
    } else {
        provider::DEFAULT_CIPHER_SUITES.to_vec()
    };

    let versions = if !args.flag_protover.is_empty() {
        lookup_versions(&args.flag_protover)
    } else {
        rustls::DEFAULT_VERSIONS.to_vec()
    };

    let config = rustls::ClientConfig::builder_with_provider(
        CryptoProvider {
            cipher_suites: suites,
            ..provider::default_provider()
        }
            .into(),
    )
        .with_protocol_versions(&versions)
        .expect("inconsistent cipher-suite/versions selected")
        .with_root_certificates(root_store);

    let mut config = match (&args.flag_auth_key, &args.flag_auth_certs) {
        (Some(key_file), Some(certs_file)) => {
            let certs = load_certs(certs_file);
            let key = load_private_key(key_file);
            config
                .with_client_auth_cert(certs, key)
                .expect("invalid client auth certs/key")
        }
        (None, None) => config.with_no_client_auth(),
        (_, _) => {
            panic!("must provide --auth-certs and --auth-key together");
        }
    };

    config.key_log = Arc::new(rustls::KeyLogFile::new());

    if args.flag_no_tickets {
        config.resumption = config
            .resumption
            .tls12_resumption(rustls::client::Tls12Resumption::SessionIdOnly);
    }

    if args.flag_no_sni {
        config.enable_sni = false;
    }

    config.alpn_protocols = args
        .flag_proto
        .iter()
        .map(|proto| proto.as_bytes().to_vec())
        .collect();
    config.max_fragment_size = args.flag_max_frag_size;

    if args.flag_insecure {
        config
            .dangerous()
            .set_certificate_verifier(Arc::new(danger::NoCertificateVerification::new(
                provider::default_provider(),
            )));
    }
    config.enable_ack = true;

    Arc::new(config)
}


/// Parse some arguments, then make a TLS client connection
/// somewhere.
fn main() {

    let version = env!("CARGO_PKG_NAME").to_string() + ", version: " + env!("CARGO_PKG_VERSION");

    let args: Args = Docopt::new(USAGE)
        .map(|d| d.help(true))
        .map(|d| d.version(Some(version)))
        .and_then(|d| d.deserialize())
        .unwrap_or_else(|e| e.exit());

    if args.flag_verbose {
        env_logger::builder()
            .filter_level(LevelFilter::Trace)   // Set global log level to Trace
            .filter_module("mio", LevelFilter::Info) // Set specific level for mio
            .init();
    }

    let mut recv_map = RecvBufMap::new();
    recv_map.get_or_create(1, Some(200 * 1024 * 1024));

    let dest_add1 = (args.arg_hostname.as_str(), args.flag_port.unwrap())
        .to_socket_addrs()
        .unwrap()
        .next()
        .unwrap();
    let dest_add2 = ("0.0.0.0", args.flag_port.unwrap() + 1)
        .to_socket_addrs()
        .unwrap()
        .next()
        .unwrap();


    let mut client = TlsClient::new();

    let config = make_config(&args);

    let server_name = ServerName::try_from(args.arg_hostname.as_str())
        .expect("invalid DNS name")
        .to_owned();

    let socket1 = TcpStream::connect(dest_add1).expect("TCP connection establishment failed");
    let socket2 = TcpStream::connect(dest_add2).expect("TCP connection establishment failed");

    thread::sleep(Duration::from_secs(1));

    let client_conn = ClientConnection::new(config.clone(), server_name)
        .expect("Establishment of TLS session failed");

    let _ = client.tcpls_session.tls_conn.insert(Connection::from(client_conn));
    let _ = client.tcpls_session.tls_config.insert(TlsConfig::Client(config));

    let conn_id = client.tcpls_session.create_tcpls_connection_object(socket1);
    client.tcpls_session.tls_conn.as_mut()
            .unwrap()
            .outstanding_tcp_conns
            .as_mut_ref()
            .insert((conn_id + 1) as u64, OutstandingTcpConn::new(socket2));


    client.tcpls_session.tls_conn.as_mut().unwrap().insert_conn_rtt(conn_id as u64, Duration::default());
    client.tcpls_session.tls_conn.as_mut().unwrap().insert_conn_rtt((conn_id + 1) as u64, Duration::default());


    let mut events = mio::Events::with_capacity(50);
    client.register(&recv_map, CONNECTION1);

    loop {
        match client.poll.poll(&mut events, None){
            Ok(_) => {}
            // Polling can be interrupted (e.g. by a debugger) - retry if so.
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => {
                panic!("poll failed: {:?}", e)
            }
        }

        for ev in events.iter() {
            client.handle_event(ev, &mut recv_map);
            client.reregister(&recv_map, ev.token());
        }

    }
}
