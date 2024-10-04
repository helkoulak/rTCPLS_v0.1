use std::sync::Arc;

use mio::net::{TcpListener, TcpStream};

#[macro_use]
extern crate log;

use std::{fs, io};
use std::io::{BufReader, Read, Write};
use std::net;
use std::time::Duration;

#[macro_use]
extern crate serde_derive;
extern crate core;

use docopt::Docopt;
use log::LevelFilter;
use mio::Token;
use pki_types::{CertificateDer, CertificateRevocationListDer, PrivateKeyDer};

use ring::digest;

use rustls::crypto::{ring as provider, CryptoProvider};

use rustls::{self, Error, RootCertStore, tcpls};

use rustls::recvbuf::RecvBufMap;
use rustls::server::WebPkiClientVerifier;
use rustls::tcpls::{server_create_listener, TcplsSession};

// Token for our listening socket.
const LISTENER: Token = Token(100);



/// This binds together a TCP listening socket, some outstanding
/// connections, and a TLS server configuration.
struct TlsServer {
    listener: TcpListener,
    tls_config: Arc<rustls::ServerConfig>,

    closing: bool,
    closed: bool,
    back: Option<TcpStream>,
    sent_http_response: bool,
    tcpls_session: TcplsSession,

}

impl TlsServer {
    fn new(listener: TcpListener, cfg: Arc<rustls::ServerConfig>) -> Self {
        Self {
            listener,
            tls_config: cfg,
            back: None,
            sent_http_response: false,

            closing: false,
            closed: false,
            tcpls_session: TcplsSession::new(true),
        }
    }

    fn accept(&mut self, registry: &mio::Registry, recv_map: &RecvBufMap) -> Result<(), io::Error> {
        loop {
            match self.tcpls_session.server_accept_connection(&mut self.listener, self.tls_config.clone()) {
                Ok(conn_id) => {
                    debug!("Accepting new connection of id {:?}", conn_id);

                    let token = Token(conn_id as usize);

                    self.register(registry, recv_map, token)
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

    fn conn_event(&mut self, registry: &mio::Registry, event: &mio::event::Event, recv_map: &mut RecvBufMap) {

        self.handle_event(registry, event, recv_map);

    }
    fn handle_event(&mut self, registry: &mio::Registry, ev: &mio::event::Event, recv_map: &mut RecvBufMap) {
        // If we're readable: read some TLS.  Then
        // see if that yielded new plaintext.  Then
        // see if the backend is readable too.
        let token = &ev.token();
        if ev.is_readable() {
            self.do_read(recv_map, token.0 as u64);

            self.try_back_read();

        }


        if ev.is_writable() {
            self.do_tls_write_and_handle_error(token);
        }

        if self.closing {
            let _ = self
                .tcpls_session
                .tcp_connections
                .get_mut(&0)
                .unwrap()
                .socket
                .shutdown(net::Shutdown::Both);
            self.close_back();
            self.closed = true;
            self.deregister(registry);
        } else {
            self.reregister(registry, recv_map, *token);
        }
    }

    pub fn verify_received(&mut self, recv_map: &mut RecvBufMap ) {

        let mut hash_index= 0;


        for id in recv_map.readable() {
            let mut stream = recv_map.get_mut(id as u16).unwrap();


            if !stream.complete {
                continue
            }

            hash_index = match find_pattern(&stream.as_ref_consumed(), vec![0x0f, 0x0f, 0x0f, 0x0f].as_slice()) {
                Some(n) => n + 4,
                None => panic!("hash prefix does not exist"),
            };

            assert_eq!(&stream.as_ref_consumed()[hash_index..], self.calculate_sha256_hash(&stream.as_ref_consumed()[..hash_index - 4]).as_ref());
            print!("\n \n Bytes received on stream {:?} : \n \n SHA-256 Hash {:?} \n Total length: {:?} \n",
                id,
                &stream.as_ref_consumed()[hash_index..].iter().map(|b| format!("{:02X}", b)).collect::<Vec<_>>(),
                   stream.as_ref_consumed()[..hash_index - 4].len());
            stream.empty_stream();
            recv_map.remove_readable(id);
        }
    }

    fn calculate_sha256_hash(&mut self, data: &[u8]) -> digest::Digest {
        let algorithm = &digest::SHA256;
        digest::digest(algorithm, data)
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
        // Read some TLS data.
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
            Ok(_) => {}
        };

        // Reading some TLS data might have yielded new TLS
        // messages to process.  Errors from this indicate
        // TLS protocol problems and are fatal.
        match self.tcpls_session.process_received(app_buffers) {
            Ok(io_state) => io_state,
            Err(err) => {
                println!("TLS error: {:?}", err);
                self.closing = true;
                return;
            }
        };

    }



    fn try_back_read(&mut self) {
        if self.back.is_none() {
            return;
        }

        // Try a non-blocking read.
        let mut buf = [0u8; 1024];
        let back = self.back.as_mut().unwrap();
        let rc = try_read(back.read(&mut buf));

        if rc.is_err() {
            error!("backend read failed: {:?}", rc);
            self.closing = true;
            return;
        }

        let maybe_len = rc.unwrap();

        // If we have a successful but empty read, that's an EOF.
        // Otherwise, we shove the data into the TLS session.
        match maybe_len {
            Some(len) if len == 0 => {
                debug!("back eof");
                self.closing = true;
            }
            Some(len) => {
                self.tcpls_session.
                    tls_conn
                    .as_mut()
                    .unwrap()
                    .writer()
                    .write_all(&buf[..len])
                    .unwrap();
            }
            None => {}
        };
    }


    fn tcpls_write(&mut self, token: &Token) -> Result<usize, Error> {
        let mut conn_ids = Vec::new();
        conn_ids.push(token.0 as u64);
        self.tcpls_session.send_on_connection(conn_ids, None)
    }

    fn do_tls_write_and_handle_error(&mut self, token: &Token) {
        let rc = self.tcpls_write(token);
        if rc.is_err() {
            error!("write failed {:?}", rc);
            self.closing = true;
        }
    }

    fn register(&mut self, registry: &mio::Registry, app_buf: &RecvBufMap, token: Token) {
        let event_set = self.event_set(app_buf);
        registry
            .register(&mut self.tcpls_session.tcp_connections.get_mut(&0).unwrap().socket, token, event_set)
            .unwrap();

        if self.back.is_some() {
            registry
                .register(
                    self.back.as_mut().unwrap(),
                    token,
                    mio::Interest::READABLE,
                )
                .unwrap();
        }
    }

    fn reregister(&mut self, registry: &mio::Registry, app_buf: &RecvBufMap, token: Token) {
        let event_set = self.event_set(app_buf);
        registry
            .reregister(&mut self.tcpls_session.tcp_connections.get_mut(&0).unwrap().socket, token, event_set)
            .unwrap();
    }

    fn deregister(&mut self, registry: &mio::Registry) {
        registry
            .deregister(&mut self.tcpls_session.tcp_connections.get_mut(&0).unwrap().socket)
            .unwrap();

        if self.back.is_some() {
            registry
                .deregister(self.back.as_mut().unwrap())
                .unwrap();
        }
    }

    /// What IO events we're currently waiting for,
    /// based on wants_read/wants_write.
    fn event_set(&self, app_buf: &RecvBufMap) -> mio::Interest {
        let rd = self.tcpls_session.tls_conn.as_ref().unwrap().wants_read(app_buf);
        let wr = self.tcpls_session.tls_conn.as_ref().unwrap().wants_write(None);

        if rd && wr {
            mio::Interest::READABLE | mio::Interest::WRITABLE
        } else if wr {
            mio::Interest::WRITABLE
        } else {
            mio::Interest::READABLE
        }
    }

    fn is_closed(&self) -> bool {
        self.closed
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
fn try_read(r: io::Result<usize>) -> io::Result<Option<usize>> {
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
  server_tcpls --certs CERTFILE --key KEYFILE [--suite SUITE ...] \
     [--proto PROTO ...] [--protover PROTOVER ...] [options]

  server_tcpls (--version | -v)
  server_tcpls (--help | -h)

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

#[derive(Debug, Deserialize)]
struct Args {
    flag_port: Option<u16>,
    flag_verbose: bool,
    flag_protover: Vec<String>,
    flag_suite: Vec<String>,
    flag_proto: Vec<String>,
    flag_certs: Option<String>,
    flag_crl: Vec<String>,
    flag_key: Option<String>,
    flag_ocsp: Option<String>,
    flag_auth: Option<String>,
    flag_require_auth: bool,
    flag_resumption: bool,
    flag_tickets: bool,
    arg_fport: Option<u16>,
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

    //Map of application controlled receive buffers
    let mut recv_map = RecvBufMap::new();

    let config = make_config(&args, 5);

    let mut listener = server_create_listener("0.0.0.0:443", Some(args.flag_port.unwrap()));

    let mut poll = mio::Poll::new().unwrap();

    poll.registry()
        .register(&mut listener, LISTENER, mio::Interest::READABLE)
        .unwrap();


    let mut tcpls_server = TlsServer::new(listener, config);

    let mut events = mio::Events::with_capacity(256);
    loop {
       match poll.poll(&mut events, None){
            Ok(_) => {}
            // Polling can be interrupted (e.g. by a debugger) - retry if so.
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => {
                panic!("poll failed: {:?}", e)
            }
        }
        for event in events.iter() {
            match event.token() {
                LISTENER => {
                    tcpls_server
                        .accept(poll.registry(), &recv_map)
                        .expect("error accepting socket");
                }
                _ => {
                    tcpls_server.conn_event(poll.registry(), event, &mut recv_map);
                    if !tcpls_server
                        .tcpls_session
                        .tls_conn
                        .as_ref()
                        .unwrap().is_handshaking() {
                        tcpls_server
                            .verify_received(&mut recv_map);
                    }
                }
            }
        }
    }
}

