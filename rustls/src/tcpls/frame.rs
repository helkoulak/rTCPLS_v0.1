use std::prelude::rust_2021::Vec;
use std::vec;
use octets::varint_len;
use crate::{Error, InvalidMessage};
use crate::msgs::fragmenter::MAX_FRAGMENT_LEN;

/// chunk_num = 4 Bytes + Offset_step = 2 Bytes + Stream Id = 2 Bytes.
pub const TCPLS_HEADER_SIZE: usize = 8;

pub const SAMPLE_PAYLOAD_LENGTH: usize = 16;

pub const STREAM_FRAME_HEADER_SIZE: usize = 3;

pub const PROBE_FRAME_SIZE: usize = 5;

pub const MAX_TCPLS_FRAGMENT_LEN: usize = MAX_FRAGMENT_LEN - TCPLS_OVERHEAD;

pub const TCPLS_OVERHEAD: usize = TCPLS_HEADER_SIZE + STREAM_FRAME_HEADER_SIZE;

pub const TCPLS_PAYLOAD_OFFSET: usize = 13;

#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Frame {
    Padding,

    Ping,

    Stream {
        length: u16,
        fin: u8,
    },

    ACK {
        highest_record_sn_received: u64,
        connection_id: u64,
    },

    NewToken {
        token: [u8; 32],
        sequence: u64,
    },

    ConnectionReset {
        connection_id: u64,
    },

    NewAddress {
        port: u64,
        address: Vec<u8>,
        address_version: u64,
        address_id: u64,
    },

    RemoveAddress {
        address_id: u64,
    },

    StreamChange {
        next_record_stream_id: u64,
        next_offset: u64,
    },

    Probe {
        random: u32,
    }
}

impl Frame {
    pub fn parse(b: &mut octets::Octets) -> Result<Self, InvalidMessage> {
        let frame_type = b.get_u8_reverse().expect("failed");

        let frame = match frame_type {
            0x00 => Self::Padding,

            0x01 => Self::Ping,

            0x02..=0x03 => parse_stream_frame(frame_type, b).unwrap(),

            0x04 => parse_ack_frame(b).unwrap(),

            0x05 => parse_new_token_frame(b).unwrap(),

            0x06 => parse_connection_reset_frame(b).unwrap(),

            0x07 => parse_new_address_frame(b).unwrap(),

            0x08 => parse_remove_address_frame(b).unwrap(),

            0x09 => parse_stream_change_frame(b).unwrap(),

            0x0a => parse_probe_frame(b).unwrap(),

            _ => return Err(InvalidMessage::InvalidFrameType),
        };

        Ok(frame)
    }

    pub fn encode(&self, b: &mut octets::OctetsMut) -> Result<usize, InvalidMessage> {
        let before = b.cap();

        match self {
            Self::Padding => {
                b.put_varint(0x00).unwrap();
            }
            Self::Ping => {
                b.put_varint(0x01).unwrap();
            }
            Self::Stream {
                length,
                fin,
            } => {
                b.put_u16(*length).unwrap();
                match fin {
                    1 => b.put_u8(0x03).unwrap(),
                    0 => b.put_u8(0x02).unwrap(),
                    _ => panic!("invalid value for flag fin"),

                };
            }

            Self::ACK {
                highest_record_sn_received,
                connection_id,
            } => {
                b.put_varint_reverse(*highest_record_sn_received).unwrap();
                b.put_varint_reverse(*connection_id).unwrap();
                b.put_varint(0x04).unwrap();
            }

            Self::NewToken { token, sequence } => {
                b.put_bytes(token).unwrap();
                b.put_varint_reverse(*sequence).unwrap();
                b.put_varint(0x05).unwrap();
            }

            Self::ConnectionReset { connection_id } => {
                b.put_varint_reverse(*connection_id).unwrap();
                b.put_varint(0x06).unwrap();
            }
            Self::NewAddress {
                port,
                address,
                address_version,
                address_id,
            } => {
                b.put_varint_reverse(*port).unwrap();
                b.put_bytes(address.as_ref()).unwrap();
                b.put_varint_reverse(*address_version).unwrap();
                b.put_varint_reverse(*address_id).unwrap();
                b.put_varint(0x07).unwrap();
            }

            Self::RemoveAddress { address_id } => {
                b.put_varint_reverse(*address_id).unwrap();
                b.put_varint(0x08).unwrap();
            }

            Self::StreamChange {
                next_record_stream_id,
                next_offset,
            } => {
                b.put_varint_reverse(*next_record_stream_id).unwrap();
                b.put_varint_reverse(*next_offset).unwrap();
                b.put_varint(0x09).unwrap();
            }

            Self::Probe {
                random,
            } => {
                b.put_u32(*random).unwrap();
                b.put_u8(0x0a).unwrap();
            }
        }

        Ok(before - b.cap())
    }

    pub fn get_frame_size_reverse(b: &mut octets::Octets) -> Result<usize, InvalidMessage> {

        let frame_type = b.get_u8_reverse().expect("failed");

        let frame_size = match frame_type {
            0x00 => 1 ,

            0x01 => 1 ,

            0x02..=0x03 => 3,

            0x04 => {
                1 + varint_len(b.get_varint_reverse().unwrap()) +
                    varint_len(b.get_varint_reverse().unwrap())
            },


            0x05 => {
                1 + varint_len(b.get_varint_reverse().unwrap()) + 32
            },

            0x06 => {
                1 + varint_len(b.get_varint_reverse().unwrap())
            },

            0x07 => {
                let mut frame_len = 1 + varint_len(b.get_varint_reverse().unwrap());
                let address_len = match b.get_varint_reverse().unwrap() {
                    4 => {
                        b.rewind(4).unwrap();
                        4
                    },
                    6 => {
                        b.rewind(16).unwrap();
                        16
                    },
                    _ => panic!("Wrong ip address version"),
                };
                // one byte for address version + address length + length of port encoding
                   frame_len += 1 + address_len + varint_len(b.get_varint_reverse().unwrap());
                frame_len

            },

            0x08 => { 1 + varint_len(b.get_varint_reverse().unwrap()) },

            0x09 => { 1 + varint_len(b.get_varint_reverse().unwrap())
                        + varint_len(b.get_varint_reverse().unwrap())
            },

            _ => return Err(InvalidMessage::InvalidFrameType),
        };

        Ok(frame_size)
    }



}

fn parse_stream_frame(frame_type: u8, b: &mut octets::Octets) -> octets::Result<Frame> {

    let length = b.get_u16_reverse()?;

    let fin = match frame_type {
        2 => 0,
        3 => 1,
        _ => panic!("Invalid frame type"),
    };

    Ok(Frame::Stream {
        length,
        fin,
    })
}

fn parse_ack_frame(b: &mut octets::Octets) -> octets::Result<Frame> {
    let connection_id = b.get_varint_reverse()?;

    let highest_record_seq_received = b.get_varint_reverse()?;

    Ok(Frame::ACK {
        highest_record_sn_received: highest_record_seq_received,
        connection_id,
    })
}

fn parse_new_token_frame(b: &mut octets::Octets) -> octets::Result<Frame> {
    let sequence = b.get_varint_reverse()?;

    let token = b.get_bytes_reverse(32)?.buf();

    Ok(Frame::NewToken {
        token: <[u8; 32]>::try_from(token).unwrap(),
        sequence,
    })
}

fn parse_connection_reset_frame(b: &mut octets::Octets) -> octets::Result<Frame> {
    let connection_id = b.get_varint_reverse()?;

    Ok(Frame::ConnectionReset { connection_id })
}

fn parse_new_address_frame(b: &mut octets::Octets) -> octets::Result<Frame> {
    let address_id = b.get_varint_reverse()?;

    let address_version = b.get_varint_reverse()?;

    let address = match address_version {
        4 => b.get_bytes_reverse(4)?.to_vec(),
        6 => b.get_bytes_reverse(16)?.to_vec(),
        _ => panic!("Wrong ip address version"),
    };

    let port = b.get_varint_reverse()?;

    Ok(Frame::NewAddress {
        port,
        address,
        address_version,
        address_id,
    })
}

fn parse_remove_address_frame(b: &mut octets::Octets) -> octets::Result<Frame> {
    let address_id = b.get_varint_reverse()?;

    Ok(Frame::RemoveAddress { address_id })
}

fn parse_probe_frame(b: &mut octets::Octets) -> octets::Result<Frame> {
    let random = b.get_u32_reverse()?;

    Ok(Frame::Probe {random})
}

fn parse_stream_change_frame(b: &mut octets::Octets) -> octets::Result<Frame> {
    let next_offset = b.get_varint_reverse()?;

    let next_record_stream_id = b.get_varint_reverse()?;

    Ok(Frame::StreamChange {
        next_record_stream_id,
        next_offset,
    })
}
#[derive(Default, PartialEq, Debug)]
pub struct TcplsHeader {
    pub chunk_num: u32,
    pub stream_id: u32,
}

impl TcplsHeader {
    pub fn new(chunk_num: u32, stream_id: u32) -> Self {
        Self {
            chunk_num,
            stream_id,
        }
    }

    pub fn encode_tcpls_header(
        &mut self,
        b: &mut octets::OctetsMut,
    ) -> Result<(), Error> {
        b.put_u32(self.chunk_num).unwrap();
        b.put_u32(self.stream_id).unwrap();

        Ok(())
    }

    pub fn decode_tcpls_header(b: &mut octets::Octets) -> Self {
        Self{
            chunk_num: b.get_u32().unwrap(),
            stream_id: b.get_u32().unwrap(),
        }
    }

    pub fn decode_tcpls_header_from_slice(b: &[u8]) -> Self {
        Self{
            chunk_num: u32::from_be_bytes(b[0..4].try_into().unwrap()),
            stream_id: u32::from_be_bytes(b[4..8].try_into().unwrap()),
        }
    }

   /* pub fn get_header_size_reverse(b: &mut octets::Octets) -> usize {
        b.rewind(1).unwrap();
        1 + varint_len(b.get_varint_reverse().unwrap()) +
            varint_len(b.get_varint_reverse().unwrap()) +
            varint_len(b.get_varint_reverse().unwrap())

    }*/
}

/*impl Default for StreamFrameHeader {
    fn default() -> Self {
        Self {
            ..Default::default()
        }
    }
}*/

#[test]
fn test_encode_decode_stream_frame() {
    let mut buf = [0; 3];

    let stream_frame = Frame::Stream {
        length: 24,
        fin: 1,
    };

    let mut d = octets::OctetsMut::with_slice(&mut buf);

    stream_frame.encode(&mut d).unwrap();

    let mut c = octets::Octets::with_slice_reverse(&mut buf);

    let stream_frame_2 = Frame::parse(&mut c).unwrap();

    assert_eq!(stream_frame, stream_frame_2);
}

#[test]
fn test_encode_decode_ack_frame() {
    let mut buf = [0; 6];

    let ack_frame = Frame::ACK {
        highest_record_sn_received: 1753698,
        connection_id: 8,
    };

    let mut d = octets::OctetsMut::with_slice(&mut buf);

    ack_frame.encode(&mut d).unwrap();

    let mut c = octets::Octets::with_slice_reverse(&mut buf);

    let ack_frame_2 = Frame::parse(&mut c).unwrap();

    assert_eq!(ack_frame, ack_frame_2);
}

#[test]
fn test_encode_decode_new_token_frame() {
    let mut buf = [0; 37];

    let token_frame = Frame::NewToken {
        token: [0x0F; 32],
        sequence: 854785486,
    };

    let mut d = octets::OctetsMut::with_slice(&mut buf);

    token_frame.encode(&mut d).unwrap();

    let mut c = octets::Octets::with_slice_reverse(&mut buf);

    let token_frame_2 = Frame::parse(&mut c).unwrap();

    assert_eq!(token_frame, token_frame_2);
}

#[test]
fn test_parse_new_address_frame() {
    let mut v4 = [0; 12];

    let v4_frame = Frame::NewAddress {
        port: 9874,
        address: vec![0x0A, 0x00, 0x00, 0x0C],
        address_version: 0x04,
        address_id: 47854755,
    };

    #[test]
    fn test_reduce_offset_size() {



    }

    let mut d = octets::OctetsMut::with_slice(&mut v4);

    v4_frame.encode(&mut d).unwrap();

    let mut c = octets::Octets::with_slice_reverse(&mut v4);

    let v4_frame_2 = Frame::parse(&mut c).unwrap();

    assert_eq!(v4_frame, v4_frame_2);

    let mut v6 = [0; 30];

    let v6_frame = Frame::NewAddress {
        port: 987455,
        address: vec![
            0x0A, 0x00, 0x00, 0x0C, 0x0A, 0x00, 0x00, 0x0C, 0x0A, 0x00, 0x00, 0x0C, 0x0A, 0x00,
            0x00, 0x0C,
        ],
        address_version: 0x06,
        address_id: 4785475585858,
    };

    let mut d = octets::OctetsMut::with_slice(&mut v6);

    v6_frame.encode(&mut d).unwrap();

    let mut c = octets::Octets::with_slice_reverse(&mut v6);

    let v6_frame_2 = Frame::parse(&mut c).unwrap();

    assert_eq!(v6_frame, v6_frame_2);
}