#[macro_use]
extern crate log;

use std::{fs, io, thread};
use std::io::{BufReader, Read};
use std::net;
use std::sync::Arc;
use std::time::Duration;

#[macro_use]
extern crate serde_derive;
extern crate core;

use docopt::Docopt;
use log::LevelFilter;
use mio::net::{TcpListener, TcpStream};
use mio::Token;
use pki_types::{CertificateDer, CertificateRevocationListDer, PrivateKeyDer};

use ring::digest;

use rustls::crypto::{ring as provider, CryptoProvider};

use rustls::{self, Connection, RootCertStore, ServerConnection};

use rustls::recvbuf::RecvBufMap;
use rustls::server::WebPkiClientVerifier;
use rustls::tcpls::{server_create_listener, TcplsSession, TlsConfig, DEFAULT_CONNECTION_ID};
use rustls::tcpls::outstanding_conn::OutstandingTcpConn;
use rustls::tcpls::stream::{SimpleIdHashMap, DEFAULT_STREAM_ID};

// Token for our listening socket.
const LISTENER1: mio::Token = mio::Token(100);
const LISTENER2: mio::Token = mio::Token(101);


// Which mode the server operates in.


/// This binds together a TCP listening socket, some outstanding
/// connections, and a TLS server configuration.
struct TlsServer {
    tls_config: Arc<rustls::ServerConfig>,

    closing: bool,
    closed: bool,
    back: Option<TcpStream>,
    tcpls_session: TcplsSession,
    poll: mio::Poll,
    total_streams_received: usize,
    download_req_received: bool,
    conns_probed: bool,
}

impl TlsServer {
    fn new(cfg: Arc<rustls::ServerConfig>) -> Self {
        Self {
            tls_config: cfg,
            back: None,
            closing: false,
            closed: false,
            tcpls_session: TcplsSession::new(true),
            poll: mio::Poll::new().unwrap(),
            total_streams_received: 0,
            download_req_received: false,
            conns_probed: false,
        }
    }



    fn conn_event(&mut self, event: &mio::event::Event, recv_map: &mut RecvBufMap) {
        self.handle_event(event, recv_map);

    }

    fn handle_event(&mut self, ev: &mio::event::Event, recv_map: &mut RecvBufMap) {
        // If we're readable: read some TLS.  Then
        // see if that yielded new plaintext.  Then
        // see if the backend is readable too.
        let token = ev.token();
        if ev.is_readable() {
            self.do_read(recv_map, token.0 as u64);

            if !self.tcpls_session.tls_conn.as_ref().unwrap().is_handshaking() && self.tcpls_session.tcp_connections.len() == 2 {

                if !self.conns_probed && !self.download_req_received {
                    println!("Probing connections");
                    self.tcpls_session.probe_rtt().unwrap();
                    self.conns_probed = true;
                    return;
                }

                 if self.download_req_received {
                     println!("Sending data");
                     self.tcpls_session.stream_send(1, vec![2u8; 70000000].as_slice()).unwrap();
                     self.tcpls_session.send_on_connection(None, None).expect("Sending on connection failed");
                     self.download_req_received = false;
                 }

            }


        }

        if ev.is_writable() {
            self.do_tls_write_and_handle_error();
        }

        if ev.is_read_closed() {
            let _ = self
                .tcpls_session
                .tcp_connections
                .get_mut(&(token.0 as u64))
                .unwrap()
                .socket
                .shutdown(net::Shutdown::Both);
            self.deregister(token.0 as u64);
            self.closing = true;
            return;
        } else {
            self.reregister(recv_map, token);
        }
    }

    /// Close the backend connection for forwarded sessions.
    fn close_back(&mut self) {
        if self.back.is_some() {
            let back = self.back.as_mut().unwrap();
            back.shutdown(net::Shutdown::Both)
                .unwrap();
        }
        self.back = None;
    }

    fn do_read(&mut self, app_buffers: &mut RecvBufMap, id: u64) {
        if self.tcpls_session.tls_conn.as_mut().unwrap().outstanding_tcp_conns.as_mut_ref().contains_key(&id) {

            if !self.tcpls_session.tls_conn.as_mut().unwrap().is_handshaking() {
                self.process_join_reponse(id);
            }
            return;
        }

        match self.tcpls_session.recv_on_connection(id as u32) {
            Err(err) => {
                if let io::ErrorKind::WouldBlock = err.kind() {
                    return;
                }

                error!("read error {:?}", err);
                self.closing = true;
                return;
            }
            Ok(0) => {
                debug!("eof");
                self.closing = true;
                return;
            }
            Ok(_) => {},
        };

        // Reading some TLS data might have yielded new TLS
        // messages to process.  Errors from this indicate
        // TLS protocol problems and are fatal.
        let _io_state = match self.tcpls_session.process_received(app_buffers) {
            Ok(io_state) => io_state,
            Err(err) => {
                println!("TLS error: {:?}", err);
                self.closing = true;
                return;
            }
        };

        if app_buffers.get_or_create(1, None).complete {
            println!("Download request received");
            self.download_req_received = true;
            app_buffers.get_mut(1).unwrap().reset_stream();
        }



    }


    fn do_tls_write_and_handle_error(&mut self) {
        self.tcpls_session.send_on_connection(None, None).expect("Sending on connection failed");
    }

    fn register(&mut self, socket: TcpStream, app_buf: &RecvBufMap) {
       let mut conn_id: u32 = 0;

        if self.tcpls_session.next_conn_id == DEFAULT_CONNECTION_ID {
            self.tcpls_session.is_server = true;

            println!("create a TLS server connection");
            let server_conn = ServerConnection::new(self.tls_config.clone())
                .expect("Establishing a TLS session has failed");
            let _ = self.tcpls_session.tls_conn.insert(Connection::from(server_conn));
            let _ = self.tcpls_session.tls_config.insert(TlsConfig::from(self.tls_config.clone()));

            conn_id = self.tcpls_session.create_tcpls_connection_object(socket);
        }else {
            self.tcpls_session.tls_conn
                .as_mut()
                .unwrap()
                .outstanding_tcp_conns.as_mut_ref().insert(self.tcpls_session.next_conn_id as u64, OutstandingTcpConn::new(socket));
            conn_id = self.tcpls_session.next_conn_id;

        }
        self.tcpls_session.tls_conn.as_mut().unwrap().insert_conn_rtt(self.tcpls_session.next_conn_id as u64, Duration::default());
        self.tcpls_session.next_conn_id += 1;


        let event_set = self.event_set(app_buf, conn_id as u64);

        let socket = self.tcpls_session.get_socket(conn_id as u64);

        match self.poll.registry()
            .register(socket, Token(conn_id as usize), event_set) {
            Ok(()) => (),
            Err(ref err) if err.kind() == io::ErrorKind::AlreadyExists => return (),
            Err(_err) => { panic!("encountered error while registering source") }
        }



    }

    fn reregister(&mut self, app_buf: &RecvBufMap, token: Token) {
        let event_set = self.event_set(app_buf, token.0 as u64);

        let socket = self.tcpls_session.get_socket(token.0 as u64);
        self.poll.registry()
            .reregister(socket, token, event_set)
            .unwrap();
    }

    fn deregister(&mut self, id: u64) {
        self.poll.registry()
            .deregister(&mut self.tcpls_session.tcp_connections.get_mut(&id).unwrap().socket)
            .unwrap();

        if self.back.is_some() {
            self.poll.registry()
                .deregister(self.back.as_mut().unwrap())
                .unwrap();
        }
    }

    /// What IO events we're currently waiting for,
    /// based on wants_read/wants_write.
    fn event_set(&mut self, app_buf: &RecvBufMap, id: u64) -> mio::Interest {
        let rd = match self.tcpls_session.tls_conn.as_mut().unwrap().outstanding_tcp_conns.as_mut_ref().contains_key(&id) {
            true => self.tcpls_session.tls_conn.as_mut().unwrap().outstanding_tcp_conns.wants_read(id),
            false => self.tcpls_session.tls_conn.as_mut().unwrap().wants_read(app_buf),
        };
        let wr = match self.tcpls_session.tls_conn.as_mut().unwrap().outstanding_tcp_conns.as_mut_ref().contains_key(&id) {
            true => false,
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


    pub(crate) fn process_join_reponse(&mut self, id: u64) {
        match self.tcpls_session
            .tls_conn
            .as_mut()
            .unwrap()
            .outstanding_tcp_conns
            .as_mut_ref()
            .get_mut(&id)
            .unwrap()
            .receive_join_request() {
            Ok(_bytes) => (),
            Err(ref error) => if error.kind() == io::ErrorKind::WouldBlock {
                return;
            } else { panic!("{:?}", error) },
        }

        match self.tcpls_session.process_join_request(id) {
            Ok(()) => return,
            Err(err) => panic!("{:?}", err),
        };
    }
}


struct MainServer {
    listeners: SimpleIdHashMap<TcpListener>,
    incoming_sockets: Option<SimpleIdHashMap<TcpStream>>,
    next_id: u64,
}

impl MainServer {
    fn new() -> Self{
        Self {
            listeners: SimpleIdHashMap::default(),
            incoming_sockets: Some(SimpleIdHashMap::default()),
            next_id: 0,
        }
    }
    fn accept_main(&mut self, listener: Token, args: &Args) -> Result<(), io::Error> {
        loop {
            match self.listeners.get_mut(&(listener.0 as u64)).unwrap().accept() {
                Ok((sock, add)) => {
                    println!("Accepting new connection from {:?}", add);
                    self.incoming_sockets.as_mut().unwrap().insert(self.next_id, sock);
                    self.next_id +=1;
                    if self.incoming_sockets.as_ref().unwrap().len() == self.listeners.len() {
                        let incoming = self.incoming_sockets.take();
                        self.incoming_sockets = Some(SimpleIdHashMap::default());
                        let arg_cloned = args.clone();
                        // Spawn a thread for the client
                        thread::spawn(move || {
                            run_server(incoming.unwrap(), arg_cloned);
                        });
                    }
                }
                Err(ref err) if err.kind() == io::ErrorKind::WouldBlock => return Ok(()),
                Err(err) => {
                    println!(
                        "encountered error while accepting connection; err={:?}",
                        err
                    );
                    return Err(err);
                }
            }
        }
    }
}



pub fn find_pattern(data: &[u8], pattern: &[u8]) -> Option<usize> {
    for i in 0..data.len() {
        if data[i..].starts_with(pattern) {
            return Some(i);
        }
    }
    None
}


/// This used to be conveniently exposed by mio: map EWOULDBLOCK
/// errors to something less-errory.
pub fn try_read(r: io::Result<usize>) -> io::Result<Option<usize>> {
    match r {
        Ok(len) => Ok(Some(len)),
        Err(e) => {
            if e.kind() == io::ErrorKind::WouldBlock {
                Ok(None)
            } else {
                Err(e)
            }
        }
    }
}



const USAGE: &str = "
Runs a TLS server on :PORT.  The default PORT is 443.


`--certs' names the full certificate chain, `--key' provides the
RSA private key.

Usage:

  tlsserver-mio --certs CERTFILE --key KEYFILE [--suite SUITE ...] \
     [--proto PROTO ...] [--protover PROTOVER ...] [options]
  tlsserver-mio (--version | -v)
  tlsserver-mio (--help | -h)

Options:
    -p, --port PORT     Listen on PORT [default: 443].
    --certs CERTFILE    Read server certificates from CERTFILE.
                        This should contain PEM-format certificates
                        in the right order (the first certificate should
                        certify KEYFILE, the last should be a root CA).
    --key KEYFILE       Read private key from KEYFILE.  This should be a RSA
                        private key or PKCS8-encoded private key, in PEM format.
    --ocsp OCSPFILE     Read DER-encoded OCSP response from OCSPFILE and staple
                        to certificate.  Optional.
    --auth CERTFILE     Enable client authentication, and accept certificates
                        signed by those roots provided in CERTFILE.
    --require-auth      Send a fatal alert if the client does not complete client
                        authentication.
    --resumption        Support session resumption.
    --tickets           Support tickets.
    --protover VERSION  Disable default TLS version list, and use
                        VERSION instead.  May be used multiple times.
    --suite SUITE       Disable default cipher suite list, and use
                        SUITE instead.  May be used multiple times.
    --proto PROTOCOL    Negotiate PROTOCOL using ALPN.
                        May be used multiple times.
    --verbose           Emit log output.
    --version, -v       Show tool version.
    --help, -h          Show this screen.
";

#[derive(Debug, Deserialize, Clone)]
pub struct Args {
    flag_port: Option<u16>,
    flag_verbose: bool,
    flag_protover: Vec<String>,
    flag_suite: Vec<String>,
    flag_proto: Vec<String>,
    flag_certs: Option<String>,
    flag_key: Option<String>,
    flag_ocsp: Option<String>,
    flag_auth: Option<String>,
    flag_require_auth: bool,
    flag_resumption: bool,
    flag_tickets: bool,
    flag_crl: Vec<String>,
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

fn load_ocsp(filename: &Option<String>) -> Vec<u8> {
    let mut ret = Vec::new();

    if let Some(name) = filename {
        fs::File::open(name)
            .expect("cannot open ocsp file")
            .read_to_end(&mut ret)
            .unwrap();
    }

    ret
}

fn load_crls(filenames: &[String]) -> Vec<CertificateRevocationListDer<'static>> {
    filenames
        .iter()
        .map(|filename| {
            let mut der = Vec::new();
            fs::File::open(filename)
                .expect("cannot open CRL file")
                .read_to_end(&mut der)
                .unwrap();
            CertificateRevocationListDer::from(der)
        })
        .collect()
}

fn take_vec_ownership(socks: Vec<TcpStream>) -> Vec<TcpStream> {
    let sock_clone: Vec<TcpStream> = socks;
    sock_clone
}
fn make_config(args: &Args, num_of_tokens: usize) -> Arc<rustls::ServerConfig> {
    let client_auth = if args.flag_auth.is_some() {
        let roots = load_certs(args.flag_auth.as_ref().unwrap());
        let mut client_auth_roots = RootCertStore::empty();
        for root in roots {
            client_auth_roots.add(root).unwrap();
        }
        let crls = load_crls(&args.flag_crl);
        if args.flag_require_auth {
            WebPkiClientVerifier::builder(client_auth_roots.into())
                .with_crls(crls)
                .build()
                .unwrap()
        } else {
            WebPkiClientVerifier::builder(client_auth_roots.into())
                .with_crls(crls)
                .allow_unauthenticated()
                .build()
                .unwrap()
        }
    } else {
        WebPkiClientVerifier::no_client_auth()
    };

    let suites = if !args.flag_suite.is_empty() {
        lookup_suites(&args.flag_suite)
    } else {
        provider::ALL_CIPHER_SUITES.to_vec()
    };

    let versions = if !args.flag_protover.is_empty() {
        lookup_versions(&args.flag_protover)
    } else {
        rustls::ALL_VERSIONS.to_vec()
    };

    let certs = load_certs(
        args.flag_certs
            .as_ref()
            .expect("--certs option missing"),
    );
    let privkey = load_private_key(
        args.flag_key
            .as_ref()
            .expect("--key option missing"),
    );
    let ocsp = load_ocsp(&args.flag_ocsp);

    let mut config = rustls::ServerConfig::builder_with_provider(
        CryptoProvider {
            cipher_suites: suites,
            ..provider::default_provider()
        }
            .into(),
    )
        .with_protocol_versions(&versions)
        .expect("inconsistent cipher-suites/versions specified")
        .with_client_cert_verifier(client_auth)
        .with_single_cert_with_ocsp(certs, privkey, ocsp)
        .expect("bad certificates/private key");

    config.key_log = Arc::new(rustls::KeyLogFile::new());

    config.max_tcpls_tokens_cap = num_of_tokens;

    if args.flag_resumption {
        config.session_storage = rustls::server::ServerSessionMemoryCache::new(256);
    }

    if args.flag_tickets {
        config.ticketer = provider::Ticketer::new().unwrap();
    }

    config.alpn_protocols = args
        .flag_proto
        .iter()
        .map(|proto| proto.as_bytes().to_vec())
        .collect::<Vec<_>>();
    config.enable_ack = true;

    Arc::new(config)
}




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


    let mut main_server = MainServer::new();

    let mut listener1 = server_create_listener("0.0.0.0:8443", Some(args.flag_port.unwrap()));
    let mut listener2 = server_create_listener("0.0.0.0:8444", Some(args.flag_port.unwrap() + 1));

    let mut poll = mio::Poll::new().unwrap();
    poll.registry()
        .register(&mut listener1, LISTENER1, mio::Interest::READABLE)
        .unwrap();

    poll.registry()
        .register(&mut listener2, LISTENER2, mio::Interest::READABLE)
        .unwrap();

    main_server.listeners.insert(LISTENER1.0 as u64, listener1);
    main_server.listeners.insert(LISTENER2.0 as u64, listener2);

    let mut events = mio::Events::with_capacity(256);

    loop {
        match poll.poll(&mut events, None) {
            Ok(_) => {}
            // Polling can be interrupted (e.g. by a debugger) - retry if so.
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => {
                panic!("poll failed: {:?}", e)
            }
        }
        'Evenloop: for event in events.iter() {
            match event.token() {
                LISTENER1 | LISTENER2  => {
                    main_server
                        .accept_main(event.token(), &args)
                        .expect("error accepting socket");
                }
                _ => break 'Evenloop
            }
        }
    }

   
}


fn run_server(mut socks: SimpleIdHashMap<TcpStream>, arg: Args) {
    println!("New server started");
    let mut recv_map = RecvBufMap::new();

    let config = make_config(&arg, 5);

    let mut tcpls_server = TlsServer::new(config);

    for sock in socks.drain(){
        tcpls_server.register(sock.1, &recv_map);
    }


    let mut events = mio::Events::with_capacity(256);
    loop {
        if tcpls_server.closing {return;}
        match tcpls_server.poll.poll(&mut events, None){
            Ok(_) => {}
            // Polling can be interrupted (e.g. by a debugger) - retry if so.
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => {
                panic!("poll failed: {:?}", e)
            }
        }

        for event in events.iter() {
            match event.token() {
                _ => {
                    tcpls_server.conn_event(event, &mut recv_map);
                },
            }
        }
    }

}

