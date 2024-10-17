use std::eprintln;
use std::net::IpAddr;
use std::prelude::rust_2021::Vec;
use if_addrs::get_if_addrs;
use crate::tcpls::frame::Frame;

pub struct AddressMap {
    /// a collection of local addresses of type Frame::NewAddress
    pub local_addresses: Vec<Frame>,
    /// a collection of peer addresses of type Frame::NewAddress
    pub peer_addresses: Vec<Frame>,
    pub next_local_address_id: u8,
    pub next_peer_address_id: u8,
    /// List of ids of local addresses that should be advertised to the peer
    pub addresses_to_advertise: Vec<u8>,
    /// List of ids of local addresses currently involved in a tcp connection
    pub active_local_address: Vec<u8>,
}

impl AddressMap {
    pub fn new() -> Self {
        Self {
            local_addresses: Vec::new(),
            peer_addresses: Vec::new(),
            next_local_address_id: 0,
            next_peer_address_id: 0,
            addresses_to_advertise: Vec::new(),
            active_local_address: Vec::new(),
        }
    }

    pub fn build_local_address_list(&mut self) {
        let mut v;
        match get_if_addrs() {
            Ok(ifaces) => {
                for iface in ifaces {
                    if iface.ip().is_ipv4() {
                        v = 4;
                    } else {
                        v = 6;
                    }
                    let bytes_add = Self::ip_addr_to_bytes(iface.ip()).unwrap();
                    let new_add = Frame::NewAddress {
                        port: 0,
                        address: bytes_add,
                        address_version: v,
                        address_id: 0,
                    };
                    self.local_addresses.push(new_add);
                }
            }
            Err(err) => {
                eprintln!("Error: {}", err);
            }
        }
    }

    pub fn ip_addr_to_bytes(ip: IpAddr) -> Option<Vec<u8>> {
            match ip {
                IpAddr::V4(v4) => {
                    Some(v4.octets().to_vec())
                }
                IpAddr::V6(v6) => {
                    Some(v6.octets().to_vec())
                }
            }
        }



    /*fn is_private_ip(ip: &IpAddr) -> bool {
        match ip {
            IpAddr::V4(v4) => {
                let octets = v4.octets();
                // Check if it's within the IPv4 private address ranges
                (octets[0] == 10)
                    || (octets[0] == 172 && octets[1] >= 16 && octets[1] <= 31)
                    || (octets[0] == 192 && octets[1] == 168)
            }
            IpAddr::V6(v6) => {
                // Check if it's an IPv6 Unique Local Address (ULA)
                v6.segments()[0] & 0xfe00 == 0xfc00
            }
        }
    }*/

    pub fn add_new_peer_address(&mut self, address: Frame) {
        if !self.peer_addresses.contains(&address) {
            self.peer_addresses.push(address);
        }
    }
}

#[test]
fn test_build_local_address_list() {
    let mut v = 0;
    let mut local_addresses: Vec<Frame> = Vec::new();
    match get_if_addrs() {
        Ok(ifaces) => {
            for iface in ifaces {
                if iface.ip().is_ipv4() {
                    v = 4;
                } else {
                    v = 6;
                }
                let bytes_add = AddressMap::ip_addr_to_bytes(iface.ip()).unwrap();
                let new_add = Frame::NewAddress {
                    port: 0,
                    address: bytes_add,
                    address_version: v,
                    address_id: 0,
                };
                local_addresses.push(new_add);
            }
        }
        Err(err) => {
            eprintln!("Error: {}", err);
        }
    }
}
