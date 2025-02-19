<p align="center">

  <img width="460" height="300" src="./rTCPLS.png">
</p>


rTCPLS is a Rust implementation of the protocol TCPLS atop the TLS library [Rustls](https://github.com/rustls/rustls). It follows the 
[TCPLS IETF draft](https://datatracker.ietf.org/doc/draft-piraux-tcpls/) with some additional improvements.


# Status

rTCPLS is an ongoing implementation of the protocol TCPLS. In this version new improvements have been added to enhance the 
performance in multipath scenario. For instance, a new header, we call it TCPLS Header, has been added to enable a zero-copy receive path from transport
layer till application buffers. In addition to that, the round-robin packet scheduler has been replaced with a dynamic-latency-aware scheduler.
This has, according to tests, reduced the download time by 20 percent. A mechanism for acknowledgments has been implemented also to realize the feature 
of failover.


# Building the code
To build the code, simply execute the following commands:
```
git clone https://forge.infosec.unamur.be/phd-elkoulak/r-tcpls-v-0-1.git
cd r-tcpls-v-0-1
git checkout master
$ cargo build --release
```

# Example code
 
Our [examples] directory contains demos that show different client-server scenarios as a proof of concept. 
To run them use the following commands for the following examples:

### Client sends multiple streams to the server via a single tcp connection
```
$ cargo run --bin server_tcpls -- --verbose --certs test-ca/rsa/end.fullchain --key test-ca/rsa/end.rsa -p 8443
$ cargo run --bin client_tcpls -- --cafile test-ca/rsa/ca.cert -p 8443 localhost --verbose
```

### Client sends multiple streams to the server via two tcp connections 
```
$ cargo run --bin server_tcpls_mp -- --verbose --certs test-ca/rsa/end.fullchain --key test-ca/rsa/end.rsa -p 8443
$ cargo run --bin client_tcpls_mp --  --cafile test-ca/rsa/ca.cert -p 8443 localhost --verbose
```

### Client sends 10000 streams each containing 64k Bytes to the server via two tcp connections
```
$ cargo run --bin server_tcpls_mp -- --verbose --certs test-ca/rsa/end.fullchain --key test-ca/rsa/end.rsa -p 8443
$ cargo run --bin client_tcpls_stress_mp --  --cafile test-ca/rsa/ca.cert -p 8443 localhost --verbose
```

### Client downloads 70 MBs from server and the download time is measured and stored in 'output.txt'
```
$ cargo run --bin server_tcpls_mp_dt -- --verbose --certs test-ca/rsa/end.fullchain --key test-ca/rsa/end.rsa -p 8443 
$ cargo run --bin client_tcpls_mp_dt --  --cafile test-ca/rsa/ca.cert -p 8443 localhost --verbose
```

### Client sends a single stream of 1 GB to the server via a single tcp connection. Please allow the example few minutes to run. It ends once the server console shows the hash and the amount of bytes received.
```
$ cargo run --bin server_tcpls_stress_single_stream_single_connection -- --verbose --certs test-ca/rsa/end.fullchain --key test-ca/rsa/end.rsa -p 8443
$ cargo run --bin client_tcpls_stress_single_stream_single_connection --  --cafile test-ca/rsa/ca.cert -p 8443 localhost --verbose
```

# Testing
 To run the API tests, execute the following command
```
$ cargo test --package rustls --test api
```

# Benchmarking
 There are several benchmark tests to measure the CPU time taken to accomplish several tasks. Execute the following commands to run the 
following tests:

### Measuring the average CPU time spent on decrypting into the application buffer two received streams, of 300 TCPLS full records each, sent over three connections.
```
$ cargo bench --bench srv_clnt_multi_stream_multi_connection
```

### Measuring the average CPU time spent on decrypting into the application buffers one stream, of 600 TCPLS full records, sent over a single connection.
```
$ cargo bench --bench srv_clnt_single_stream_single_conn
```


### Measuring the overhead resulting from adding a TCPLS header when encrypting a full TCPLS record.
```
$ cargo bench --bench encryption_tcpls_header_benchmark
```

### Measuring the average CPU time spent on decrypting TCPLS header using three different Crypto algorithms, namely SipHash24, HMAC_SHA256, and AES-128. 
```
$ cargo bench --bench tcpls_header_decryption_benchmark
```

# License


As rTCPLS is built atop Rustls, it is distributed under the following three licenses:

- Apache License version 2.0.
- MIT license.
- ISC license.

These are included as LICENSE-APACHE, LICENSE-MIT and LICENSE-ISC
respectively.  You may use this software under the terms of any
of these licenses, at your option.


