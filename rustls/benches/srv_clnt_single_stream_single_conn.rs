use std::io;
use std::io::Write;
use std::ops::{Deref, DerefMut};


#[path = "../tests/common/mod.rs"]
mod test_utils;
use test_utils::*;

struct OtherSession<C, S>
    where
        C: DerefMut + Deref<Target = ConnectionCommon<S>>,
        S: SideData,
{
    sess: C,
    pub reads: usize,
    pub writevs: Vec<Vec<usize>>,
    fail_ok: bool,
    pub short_writes: bool,
    pub last_error: Option<rustls::Error>,
    pub recv_map: RecvBufMap,
}

impl<C, S> OtherSession<C, S>
    where
        C: DerefMut + Deref<Target = ConnectionCommon<S>>,
        S: SideData,
{
    fn new(sess: C) -> OtherSession<C, S> {
        OtherSession {
            sess,
            reads: 0,
            writevs: vec![],
            fail_ok: false,
            short_writes: false,
            last_error: None,
            recv_map: RecvBufMap::new(),
        }
    }

    fn new_fails(sess: C) -> OtherSession<C, S> {
        let mut os = OtherSession::new(sess);
        os.fail_ok = true;
        os
    }
    fn write_all(&mut self, mut buf: &[u8]) -> usize {
        let mut sent = 0;
        while !buf.is_empty() {
            match self.write(buf) {
                Ok(0) => {
                    sent = 0;
                }
                Ok(n) => {
                    buf = &buf[n..];
                    sent += n;
                },
                Err(e) => panic!("Something wrong"),
            }
        }
        sent
    }
}

impl<C, S> io::Read for OtherSession<C, S>
    where
        C: DerefMut + Deref<Target = ConnectionCommon<S>>,
        S: SideData,
{
    fn read(&mut self, mut b: &mut [u8]) -> io::Result<usize> {
        self.reads += 1;
        self.sess.write_tls(b.by_ref(), 0)
    }
}

impl<C, S> io::Write for OtherSession<C, S>
    where
        C: DerefMut + Deref<Target = ConnectionCommon<S>>,
        S: SideData,
{
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        let mut buf = input.clone();
        self.sess.read_tls(&mut buf)

    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }

    fn write_vectored<'b>(&mut self, b: &[io::IoSlice<'b>]) -> io::Result<usize> {
        let mut total = 0;
        let mut lengths = vec![];
        for bytes in b {
            let write_len = if self.short_writes {
                if bytes.len() > 5 {
                    bytes.len() / 2
                } else {
                    bytes.len()
                }
            } else {
                bytes.len()
            };

            let l = self
                .sess
                .read_tls(&mut io::Cursor::new(&bytes[..write_len]))?;
            lengths.push(l);
            total += l;
            if bytes.len() != l {
                break;
            }
        }

        self.writevs.push(lengths);
        Ok(total)
    }
}

use criterion::{criterion_group, criterion_main, Criterion, Throughput, BenchmarkId, BatchSize};
use pprof::criterion::{Output, PProfProfiler};
use rustls::{Connection, ConnectionCommon, ServerConnection, SideData};
use rustls::recvbuf::RecvBufMap;
use rustls::tcpls::stream::{SimpleIdHashMap, SimpleIdHashSet};
use rustls::tcpls::TcplsSession;
use crate::bench_util::CPUTime;
use rustls::crypto::{ring as provider, CryptoProvider};
use rustls::server::ServerConnectionData;
use rustls::tcpls::frame::MAX_TCPLS_FRAGMENT_LEN;

mod bench_util;


pub(crate) fn process_received(pipe: &mut OtherSession<ServerConnection,
    ServerConnectionData>, app_bufs: &mut RecvBufMap) {
    loop {
            pipe.sess.process_new_packets(&mut SimpleIdHashMap::default(), app_bufs).unwrap();
        if app_bufs.get(1u16 as u32).unwrap().complete { break; }
    }
}
fn criterion_benchmark(c: &mut Criterion<CPUTime>) {
    let data_len= 56000;;
    let sendbuf = vec![1u8; data_len];
    let mut group = c.benchmark_group("Data_recv");
    group.throughput(Throughput::Bytes(data_len as u64));
    group.bench_with_input(BenchmarkId::new("Data_recv_single_stream_single_connection", data_len), &sendbuf,
                           |b, sendbuf| {

                               b.iter_batched_ref(|| {
                                   // Finish handshake
                                   let (mut client, mut server, mut recv_svr, mut recv_clnt) =
                                       make_pair(KeyType::Rsa);
                                   do_handshake(&mut client, &mut server, &mut recv_svr, &mut recv_clnt);
                                   client.activate_ack(false);
                                   server.activate_ack(false);
                                   server.set_deframer_cap(0, 100 * MAX_TCPLS_FRAGMENT_LEN);
                                   let mut tcpls_client = TcplsSession::new(false);
                                   let _ = tcpls_client.tls_conn.insert(Connection::from(client));
                                   tcpls_client.tls_conn.as_mut().unwrap().set_buffer_limit(None, 1);
                                   //Encrypt data and buffer it in send buffer
                                   tcpls_client.stream_send(1, sendbuf.as_slice()).expect("Buffering in send buffer failed");
                                   let mut pipe = OtherSession::new(server);
                                   let mut sent: usize = 0;

                                   while tcpls_client.tls_conn.as_mut().unwrap().wants_write(Some(1)) {
                                       sent += tcpls_client.tls_conn.as_mut().unwrap().write_tls(&mut pipe, 1).unwrap();
                                   };

                                   // Create app receive buffer
                                   recv_svr.get_or_create(1, Some(100 * MAX_TCPLS_FRAGMENT_LEN));
                                   (pipe, recv_svr)
                               },

                                                  |(ref mut pipe, recv_svr)| pipe.sess.process_new_packets(&mut SimpleIdHashMap::default(), recv_svr).unwrap(),
                                                  BatchSize::SmallInput)
                           });
    group.finish();
}


/*criterion_group!{
    name = benches;
    config = Criterion::default()
        .with_profiler(PProfProfiler::new(100, Output::Flamegraph(None)))
        .measurement_time(std::time::Duration::from_secs(15))
        .sample_size(9000);
    targets = criterion_benchmark
}
criterion_main!(benches);*/

criterion_group! {
    name = benches;
    config = Criterion::default()
        .measurement_time(std::time::Duration::from_secs(1))
        .with_measurement(CPUTime)
        .sample_size(5000);
    targets = criterion_benchmark
}
criterion_main!(benches);