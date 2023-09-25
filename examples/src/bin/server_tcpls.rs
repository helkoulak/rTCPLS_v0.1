use std::sync::Arc;

use mio::net::{TcpListener, TcpStream};

#[macro_use]
extern crate log;

use std::collections::HashMap;
use std::fs;
use std::io;
use std::io::{BufReader, Read, Write};
use std::net;
use std::ops::DerefMut;
use std::str::from_utf8;
use std::time::Duration;

#[macro_use]
extern crate serde_derive;
extern crate core;

use docopt::Docopt;
use mio::Token;
use ring::digest;

use rustls::server::{
    AllowAnyAnonymousOrAuthenticatedClient, AllowAnyAuthenticatedClient, NoClientAuth,
};
use rustls::{self, Connection, RootCertStore, ServerConnection, tcpls};
use rustls::tcpls::{load_certs, load_private_key, lookup_suites, lookup_versions, server_create_listener, TcplsSession};

// Token for our listening socket.
const LISTENER: mio::Token = mio::Token(0);

// Which mode the server operates in.
#[derive(Clone)]
enum ServerMode {
    /// Write back received bytes
    Echo,

    /// Do one read, then write a bodged HTTP response and
    /// cleanly close the connection.
    Http,

    /// Forward traffic to/from given port on localhost.
    Forward(u16),
}

/// This binds together a TCP listening socket, some outstanding
/// connections, and a TLS server configuration.
struct TlsServer {
    server: TcpListener,
    connections: HashMap<mio::Token, OpenConnection>,
    next_id: usize,
    tls_config: Arc<rustls::ServerConfig>,
    mode: ServerMode,

}

impl TlsServer {
    fn new(server: TcpListener, mode: ServerMode, cfg: Arc<rustls::ServerConfig>) -> Self {
        Self {
            server,
            connections: HashMap::new(),
            next_id: 2,
            tls_config: cfg,
            mode,
        }
    }

    fn accept(&mut self, registry: &mio::Registry) -> Result<(), io::Error> {
        loop {
            match self.server.accept() {
                Ok((socket, addr)) => {
                    debug!("Accepting new connection from {:?}", addr);

                    let tls_conn =
                        Connection::from(tcpls::server_new_tls_connection(Arc::clone(&self.tls_config)));
                    let mode = self.mode.clone();

                    let token = mio::Token(self.next_id);
                    self.next_id += 1;

                    let mut connection = OpenConnection::new(socket, token, mode, tls_conn);
                    connection.register(registry);
                    self.connections
                        .insert(token, connection);
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

    fn conn_event(&mut self, registry: &mio::Registry, event: &mio::event::Event) {
        let token = event.token();

        if self.connections.contains_key(&token) {
            self.connections
                .get_mut(&token)
                .unwrap()
                .handle_event(registry, event);

            if self.connections[&token].is_closed() {
                self.connections.remove(&token);
            }
        }
    }
}

/// This is a connection which has been accepted by the server,
/// and is currently being served.
///
/// It has a TCP-level stream, a TLS-level connection state, and some
/// other state/metadata.
struct OpenConnection {
    socket: TcpStream,
    token: mio::Token,
    closing: bool,
    closed: bool,
    mode: ServerMode,
    tls_conn: Connection,
    back: Option<TcpStream>,
    sent_http_response: bool,
    tcpls_session: TcplsSession,
    buffer: Vec<u8>,
}

/// Open a plaintext TCP-level connection for forwarded connections.
fn open_back(mode: &ServerMode) -> Option<TcpStream> {
    match *mode {
        ServerMode::Forward(ref port) => {
            let addr = net::SocketAddrV4::new(net::Ipv4Addr::new(127, 0, 0, 1), *port);
            let conn = TcpStream::connect(net::SocketAddr::V4(addr)).unwrap();
            Some(conn)
        }
        _ => None,
    }
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

impl OpenConnection {
    fn new(
        socket: TcpStream,
        token: mio::Token,
        mode: ServerMode,
        tls_conn: Connection,
    ) -> Self {
        let back = open_back(&mode);
        Self {
            socket,
            token,
            closing: false,
            closed: false,
            mode,
            tls_conn,
            back,
            sent_http_response: false,
            tcpls_session: TcplsSession::new(),
            buffer: Vec::new(),
        }
    }

    /// We're a connection, and we have something to do.
    fn handle_event(&mut self, registry: &mio::Registry, ev: &mio::event::Event) {
        // If we're readable: read some TLS.  Then
        // see if that yielded new plaintext.  Then
        // see if the backend is readable too.
        if ev.is_readable() && !self.tls_conn.is_handshaking() {
            self.do_tls_read();
            self.try_back_read();

        }


        if ev.is_readable() && self.tls_conn.is_handshaking(){

           self.do_tls_read();
            self.try_back_read();
        }




        if ev.is_writable() {
            self.do_tls_write_and_handle_error();
        }

        if self.closing {
            self.verify_received();
            let _ = self
                .socket
                .shutdown(net::Shutdown::Both);
            self.close_back();
            self.closed = true;
            self.deregister(registry);
        } else {
            self.reregister(registry);
        }
    }

    pub fn verify_received(&mut self) {

        let mut hash_index= 0;

        match OpenConnection::find_pattern(self.buffer.as_slice(), vec![0x0f, 0x0f, 0x0f, 0x0f].as_slice()){
            Some(n) => hash_index = n,
            None => debug!("hash prefix does not exist"),
        }

        let mut received_data = Vec::new();
        received_data.extend_from_slice(&self.buffer[..hash_index]);
        let mut received_hash = Vec::new();
        received_hash.extend_from_slice(&self.buffer[(hash_index + 4)..]);

        assert_eq!(received_hash, self.calculate_sha256_hash(received_data.as_slice()).as_ref() );
        assert_eq!(received_data.len(), self.buffer[..hash_index].len());
        debug!("\n \n Bytes received are {:?} \n \n with total length {:?}", received_data, received_data.len() + received_hash.len() + 4);
    }

    fn calculate_sha256_hash(&mut self, data: &[u8]) -> digest::Digest {
        let algorithm = &digest::SHA256;
        digest::digest(algorithm, data)
    }
    pub fn find_pattern(data: &[u8], pattern: &[u8]) -> Option<usize> {
        for i in 0..data.len() {
            if data[i..].starts_with(pattern) {
                return Some(i);
            }
        }
        None
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

    fn do_tls_read(&mut self) {
        // Read some TLS data.
        match self.tcpls_session.
            recv_on_connection(0, &mut self.socket, &mut self.tls_conn, None) {
            Err(err) => {
                if let io::ErrorKind::WouldBlock = err.kind() {
                    return;
                }

                error!("read error {:?}", err);
                self.closing = true;
                return;
            }
            Ok((0, _)) => {
                debug!("eof");
                self.closing = true;
                return;
            }
            Ok((_ , state )) => {
                if state.plaintext_bytes_to_read() > 0 {
                    let recv = self.tls_conn.recv_buffer_as_mut_ref(0);
                    self.buffer.extend_from_slice(recv.pop().unwrap().as_slice());
                    self.verify_received();
                }
            }
        };
    }

    fn try_plain_read(&mut self) {
        // Read and process all available plaintext.
        if let Ok(io_state) = self.tls_conn.process_received() {
            if io_state.plaintext_bytes_to_read() > 0 {
                let mut buf = Vec::new();
                buf.resize(io_state.plaintext_bytes_to_read(), 0u8);

                self.tls_conn
                    .reader()
                    .read_exact(&mut buf)
                    .unwrap();

                debug!("plaintext read {:?}", buf.len());
                debug!("plaintext read {:?}", from_utf8(buf.as_slice()).unwrap());
                self.incoming_plaintext(&buf);
            }
        }
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
                self.tls_conn
                    .writer()
                    .write_all(&buf[..len])
                    .unwrap();
            }
            None => {}
        };
    }

    /// Process some amount of received plaintext.
    fn incoming_plaintext(&mut self, buf: &[u8]) {
        match self.mode {
            ServerMode::Echo => {
                self.tls_conn
                    .writer()
                    .write_all(buf)
                    .unwrap();
            }
            ServerMode::Http => {
                self.send_http_response_once();
            }
            ServerMode::Forward(_) => {
                self.back
                    .as_mut()
                    .unwrap()
                    .write_all(buf)
                    .unwrap();
            }
        }
    }

    fn send_http_response_once(&mut self) {
        let response =
            b"HTTP/1.0 200 OK\r\nConnection: close\r\n\r\nHello world from rustls tlsserver\r\n";
        if !self.sent_http_response {
            self.tls_conn
                .writer()
                .write_all(response)
                .unwrap();
            self.sent_http_response = true;
            self.tls_conn.send_close_notify();
        }
    }

    fn tls_write(&mut self) -> io::Result<usize> {
        self.tls_conn
            .write_tls(&mut self.socket)
    }

    fn do_tls_write_and_handle_error(&mut self) {
        let rc = self.tls_write();
        if rc.is_err() {
            error!("write failed {:?}", rc);
            self.closing = true;
        }
    }

    fn register(&mut self, registry: &mio::Registry) {
        let event_set = self.event_set();
        registry
            .register(&mut self.socket, self.token, event_set)
            .unwrap();

        if self.back.is_some() {
            registry
                .register(
                    self.back.as_mut().unwrap(),
                    self.token,
                    mio::Interest::READABLE,
                )
                .unwrap();
        }
    }

    fn reregister(&mut self, registry: &mio::Registry) {
        let event_set = self.event_set();
        registry
            .reregister(&mut self.socket, self.token, event_set)
            .unwrap();
    }

    fn deregister(&mut self, registry: &mio::Registry) {
        registry
            .deregister(&mut self.socket)
            .unwrap();

        if self.back.is_some() {
            registry
                .deregister(self.back.as_mut().unwrap())
                .unwrap();
        }
    }

    /// What IO events we're currently waiting for,
    /// based on wants_read/wants_write.
    fn event_set(&self) -> mio::Interest {
        let rd = self.tls_conn.wants_read();
        let wr = self.tls_conn.wants_write();

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

const USAGE: &str = "
Runs a TLS server on :PORT.  The default PORT is 443.

`echo' mode means the server echoes received data on each connection.

`http' mode means the server blindly sends a HTTP response on each
connection.

`forward' means the server forwards plaintext to a connection made to
localhost:fport.

`--certs' names the full certificate chain, `--key' provides the
RSA private key.

Usage:
  tlsserver-mio --certs CERTFILE --key KEYFILE [--suite SUITE ...] \
     [--proto PROTO ...] [--protover PROTOVER ...] [options] echo
  tlsserver-mio --certs CERTFILE --key KEYFILE [--suite SUITE ...] \
     [--proto PROTO ...] [--protover PROTOVER ...] [options] http
  tlsserver-mio --certs CERTFILE --key KEYFILE [--suite SUITE ...] \
     [--proto PROTO ...] [--protover PROTOVER ...] [options] forward <fport>
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

#[derive(Debug, Deserialize)]
pub struct Args {
    cmd_echo: bool,
    cmd_http: bool,
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
    arg_fport: Option<u16>,
}


pub fn build_tls_server_config_args(args: &Args) -> Arc<rustls::ServerConfig> {
    tcpls::build_tls_server_config(args.flag_auth.clone(), args.flag_require_auth, args.flag_suite.clone(),
                                   args.flag_protover.clone(),  args.flag_certs.clone(), args.flag_key.clone(),
                                   args.flag_ocsp.clone(), args.flag_resumption, args.flag_tickets, args.flag_proto.clone())
}

fn main() {
    let version = env!("CARGO_PKG_NAME").to_string() + ", version: " + env!("CARGO_PKG_VERSION");

    let args: Args = Docopt::new(USAGE)
        .map(|d| d.help(true))
        .map(|d| d.version(Some(version)))
        .and_then(|d| d.deserialize())
        .unwrap_or_else(|e| e.exit());

    if args.flag_verbose {
        env_logger::Builder::new()
            .parse_filters("trace")
            .init();
    }

    let config = build_tls_server_config_args(&args);

    let mut listener = server_create_listener("0.0.0.0:443", args.flag_port.unwrap());
    let mut poll = mio::Poll::new().unwrap();
    poll.registry()
        .register(&mut listener, LISTENER, mio::Interest::READABLE | mio::Interest::WRITABLE)
        .unwrap();

    let mode = if args.cmd_echo {
        ServerMode::Echo
    } else if args.cmd_http {
        ServerMode::Http
    } else {
        ServerMode::Forward(args.arg_fport.expect("fport required"))
    };

    let mut tlsserv = TlsServer::new(listener, mode, config);

    let mut events = mio::Events::with_capacity(256);
    let timeout = Duration::new(5, 0);
    loop {
        poll.poll(&mut events, Option::from(timeout)).unwrap();

        for event in events.iter() {
            match event.token() {
                LISTENER => {
                    tlsserv
                        .accept(poll.registry())
                        .expect("error accepting socket");
                }
                _ => tlsserv.conn_event(poll.registry(), event),
            }
        }
    }
   
}

