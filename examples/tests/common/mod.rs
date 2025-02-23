use std::env;
use std::net;

use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::str;
use std::thread;
use std::time;

use ring::rand::SecureRandom;

pub struct DeleteFilesOnDrop {
    path: PathBuf,
}

impl DeleteFilesOnDrop {
    pub fn path(&self) -> &PathBuf {
        &self.path
    }
}

impl Drop for DeleteFilesOnDrop {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.path).unwrap();
    }
}

macro_rules! embed_files {
    (
        $(
            ($name:ident, $keytype:expr, $path:expr);
        )+
    ) => {
        $(
            const $name: &'static [u8] = include_bytes!(
                concat!("../../../test-ca/", $keytype, "/", $path));
        )+

        pub fn bytes_for(keytype: &str, path: &str) -> &'static [u8] {
            match (keytype, path) {
                $(
                    ($keytype, $path) => $name,
                )+
                _ => panic!("unknown keytype {} with path {}", keytype, path),
            }
        }

        pub fn new_test_ca() -> DeleteFilesOnDrop {
            let mut rand = [0u8; 4];
            ring::rand::SystemRandom::new()
                .fill(&mut rand)
                .unwrap();

            let dir = env::temp_dir()
                .join(format!("rustls-{:02x}{:02x}{:02x}{:02x}",
                              rand[0], rand[1], rand[2], rand[3]));
            let deleter = DeleteFilesOnDrop {
                path: dir,
            };

            fs::create_dir(&deleter.path).unwrap();
            fs::create_dir(deleter.path.join("ecdsa")).unwrap();
            fs::create_dir(deleter.path.join("eddsa")).unwrap();
            fs::create_dir(deleter.path.join("rsa")).unwrap();

            $(
                let filename = deleter.path.join($keytype).join($path);
                let mut f = File::create(&filename).unwrap();
                f.write_all($name).unwrap();
            )+

            deleter
        }
    }
}

embed_files! {
    (ECDSA_CA_CERT, "ecdsa", "ca.cert");
    (ECDSA_CA_DER, "ecdsa", "ca.der");
    (ECDSA_CA_KEY, "ecdsa", "ca.key");
    (ECDSA_CLIENT_CERT, "ecdsa", "client.cert");
    (ECDSA_CLIENT_CHAIN, "ecdsa", "client.chain");
    (ECDSA_CLIENT_FULLCHAIN, "ecdsa", "client.fullchain");
    (ECDSA_CLIENT_KEY, "ecdsa", "client.key");
    (ECDSA_CLIENT_REQ, "ecdsa", "client.req");
    (ECDSA_END_CERT, "ecdsa", "end.cert");
    (ECDSA_END_CHAIN, "ecdsa", "end.chain");
    (ECDSA_END_FULLCHAIN, "ecdsa", "end.fullchain");
    (ECDSA_END_KEY, "ecdsa", "end.key");
    (ECDSA_END_REQ, "ecdsa", "end.req");
    (ECDSA_INTER_CERT, "ecdsa", "inter.cert");
    (ECDSA_INTER_KEY, "ecdsa", "inter.key");
    (ECDSA_INTER_REQ, "ecdsa", "inter.req");
    (ECDSA_NISTP256_PEM, "ecdsa", "nistp256.pem");
    (ECDSA_NISTP384_PEM, "ecdsa", "nistp384.pem");

    (EDDSA_CA_CERT, "eddsa", "ca.cert");
    (EDDSA_CA_DER, "eddsa", "ca.der");
    (EDDSA_CA_KEY, "eddsa", "ca.key");
    (EDDSA_CLIENT_CERT, "eddsa", "client.cert");
    (EDDSA_CLIENT_CHAIN, "eddsa", "client.chain");
    (EDDSA_CLIENT_FULLCHAIN, "eddsa", "client.fullchain");
    (EDDSA_CLIENT_KEY, "eddsa", "client.key");
    (EDDSA_CLIENT_REQ, "eddsa", "client.req");
    (EDDSA_END_CERT, "eddsa", "end.cert");
    (EDDSA_END_CHAIN, "eddsa", "end.chain");
    (EDDSA_END_FULLCHAIN, "eddsa", "end.fullchain");
    (EDDSA_END_KEY, "eddsa", "end.key");
    (EDDSA_END_REQ, "eddsa", "end.req");
    (EDDSA_INTER_CERT, "eddsa", "inter.cert");
    (EDDSA_INTER_KEY, "eddsa", "inter.key");
    (EDDSA_INTER_REQ, "eddsa", "inter.req");

    (RSA_CA_CERT, "rsa", "ca.cert");
    (RSA_CA_DER, "rsa", "ca.der");
    (RSA_CA_KEY, "rsa", "ca.key");
    (RSA_CLIENT_CERT, "rsa", "client.cert");
    (RSA_CLIENT_CHAIN, "rsa", "client.chain");
    (RSA_CLIENT_FULLCHAIN, "rsa", "client.fullchain");
    (RSA_CLIENT_KEY, "rsa", "client.key");
    (RSA_CLIENT_REQ, "rsa", "client.req");
    (RSA_CLIENT_RSA, "rsa", "client.rsa");
    (RSA_END_CERT, "rsa", "end.cert");
    (RSA_END_CHAIN, "rsa", "end.chain");
    (RSA_END_FULLCHAIN, "rsa", "end.fullchain");
    (RSA_END_KEY, "rsa", "end.key");
    (RSA_END_REQ, "rsa", "end.req");
    (RSA_END_RSA, "rsa", "end.rsa");
    (RSA_INTER_CERT, "rsa", "inter.cert");
    (RSA_INTER_KEY, "rsa", "inter.key");
    (RSA_INTER_REQ, "rsa", "inter.req");
}

// Wait until we can connect to localhost:port.
fn wait_for_port(port: u16) -> Option<()> {
    let mut count = 0;
    loop {
        thread::sleep(time::Duration::from_millis(500));
        if net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
            return Some(());
        }
        count += 1;
        if count == 10 {
            return None;
        }
    }
}

// Find an unused port
fn unused_port(mut port: u16) -> u16 {
    loop {
        if net::TcpStream::connect(("127.0.0.1", port)).is_err() {
            return port;
        }

        port += 1;
    }
}

pub fn tlsserver_find() -> &'static str {
    "../target/debug/tlsserver-mio"
}

pub fn tlsclient_find() -> &'static str {
    "../target/debug/tlsclient-mio"
}

pub struct TlsClient {
    pub hostname: String,
    pub port: u16,
    pub http: bool,
    pub cafile: Option<PathBuf>,
    pub cache: Option<String>,
    pub suites: Vec<String>,
    pub no_sni: bool,
    pub insecure: bool,
    pub verbose: bool,
    pub max_fragment_size: Option<usize>,
    pub expect_fails: bool,
    pub expect_output: Vec<String>,
    pub expect_log: Vec<String>,
}

impl TlsClient {
    pub fn new(hostname: &str) -> Self {
        Self {
            hostname: hostname.to_string(),
            port: 443,
            http: true,
            cafile: None,
            cache: None,
            no_sni: false,
            insecure: false,
            verbose: false,
            max_fragment_size: None,
            suites: Vec::new(),
            expect_fails: false,
            expect_output: Vec::new(),
            expect_log: Vec::new(),
        }
    }

    pub fn cafile(&mut self, cafile: &Path) -> &mut Self {
        self.cafile = Some(cafile.to_path_buf());
        self
    }

    pub fn cache(&mut self, cache: &str) -> &mut Self {
        self.cache = Some(cache.to_string());
        self
    }

    pub fn no_sni(&mut self) -> &mut Self {
        self.no_sni = true;
        self
    }

    pub fn insecure(&mut self) -> &mut Self {
        self.insecure = true;
        self
    }

    pub fn verbose(&mut self) -> &mut Self {
        self.verbose = true;
        self
    }

    pub fn max_fragment_size(&mut self, max_fragment_size: usize) -> &mut Self {
        self.max_fragment_size = Some(max_fragment_size);
        self
    }

    pub fn port(&mut self, port: u16) -> &mut Self {
        self.port = port;
        self
    }

    pub fn expect(&mut self, expect: &str) -> &mut Self {
        self.expect_output
            .push(expect.to_string());
        self
    }

    pub fn expect_log(&mut self, expect: &str) -> &mut Self {
        self.verbose = true;
        self.expect_log.push(expect.to_string());
        self
    }

    pub fn suite(&mut self, suite: &str) -> &mut Self {
        self.suites.push(suite.to_string());
        self
    }

    pub fn fails(&mut self) -> &mut Self {
        self.expect_fails = true;
        self
    }


}
