#![no_main]
#[macro_use]
extern crate libfuzzer_sys;
extern crate rustls;
<<<<<<< HEAD
extern crate webpki;
=======
>>>>>>> 5bd3300 (Add files of rustls v0.23.1)

use rustls::{ClientConfig, ClientConnection, RootCertStore};
use std::io;
use std::sync::Arc;

fuzz_target!(|data: &[u8]| {
    let root_store = RootCertStore::empty();
    let config = Arc::new(
        ClientConfig::builder()
<<<<<<< HEAD
            .with_safe_defaults()
=======
>>>>>>> 5bd3300 (Add files of rustls v0.23.1)
            .with_root_certificates(root_store)
            .with_no_client_auth(),
    );
    let example_com = "example.com".try_into().unwrap();
    let mut client = ClientConnection::new(config, example_com).unwrap();
    let _ = client.read_tls(&mut io::Cursor::new(data));
    let _ = client.process_new_packets();
});
