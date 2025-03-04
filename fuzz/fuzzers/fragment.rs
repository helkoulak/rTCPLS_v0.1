#![no_main]
#[macro_use]
extern crate libfuzzer_sys;
extern crate rustls;

use rustls::internal::msgs::base::Payload;
use rustls::internal::msgs::codec::Reader;
use rustls::internal::msgs::fragmenter::MessageFragmenter;
<<<<<<< HEAD
use rustls::internal::msgs::message::{Message, OpaqueMessage, PlainMessage};

fuzz_target!(|data: &[u8]| {
    let mut rdr = Reader::init(data);
    let msg = match OpaqueMessage::read(&mut rdr) {
=======
use rustls::internal::msgs::message::{Message, OutboundOpaqueMessage, PlainMessage};

fuzz_target!(|data: &[u8]| {
    let mut rdr = Reader::init(data);
    let msg = match OutboundOpaqueMessage::read(&mut rdr) {
>>>>>>> 5bd3300 (Add files of rustls v0.23.1)
        Ok(msg) => msg,
        Err(_) => return,
    };

    let msg = match Message::try_from(msg.into_plain_message()) {
        Ok(msg) => msg,
        Err(_) => return,
    };

    let mut frg = MessageFragmenter::default();
    frg.set_max_fragment_size(Some(32))
        .unwrap();
    for msg in frg.fragment_message(&PlainMessage::from(msg)) {
        Message::try_from(PlainMessage {
            typ: msg.typ,
            version: msg.version,
<<<<<<< HEAD
            payload: Payload(msg.payload.to_vec()),
=======
            payload: Payload::Owned(msg.payload.to_vec()),
>>>>>>> 5bd3300 (Add files of rustls v0.23.1)
        })
        .ok();
    }
});
