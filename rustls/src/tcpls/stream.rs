// Copyright (C) 2018-2019, Cloudflare, Inc.
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     * Redistributions of source code must retain the above copyright notice,
//       this list of conditions and the following disclaimer.
//
//     * Redistributions in binary form must reproduce the above copyright
//       notice, this list of conditions and the following disclaimer in the
//       documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
// IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
// THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
// PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
// CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
// EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
// PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
// LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
// NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.



use std::collections::{hash_map, HashMap, HashSet};
use std::collections::hash_map::Iter;


use smallvec::SmallVec;
use crate::Error;


use crate::tcpls::frame::TcplsHeader;
use crate::vecbuf::ChunkVecBuffer;

pub const DEFAULT_BUFFER_LIMIT: usize = 64 * 1024;
pub const DEFAULT_STREAM_ID:u16 = 0;


pub struct Stream {

    pub id: u16,

    /// buffers encrypted TLS records that to be sent on the TCP socket
    pub(crate) send: ChunkVecBuffer,

    pub next_snd_pkt_num: u32,

    /// Dictates tcp connection to send on in case a record was partially sent in previous sending trial
    pub(crate) conn_to_use: Option<u64>
}

impl Stream {
    pub fn new(id: u16) -> Self {
        Self{
            id,
            send: ChunkVecBuffer::new(Some(DEFAULT_BUFFER_LIMIT)),
            next_snd_pkt_num: 0,
            conn_to_use: None,
        }
    }



    /// Returns true if the stream has enough capacity to be
    /// written to, and is not finished.
    #[inline]
    pub fn is_writable(&self) -> bool {
        !self.send.is_full()
    }

    /// Returns true if the stream has data to send.
    #[inline]
    pub fn is_flushable(&self) -> bool {
        !self.send.is_empty()
    }

    #[inline]
    pub fn reset_stream(&mut self) {
        self.send.reset();
    }
    #[inline]
    pub fn build_header(&mut self, len: u16) -> TcplsHeader {
        let header = TcplsHeader {
            chunk_num: self.next_snd_pkt_num,
            offset_step: len,
            stream_id: self.id,
        };

        self.next_snd_pkt_num += 1;
        self.send.advance_offset(len as u64);
        header
    }

    #[inline]
    pub fn set_conn(&mut self, conn_id: Option<u64>) {
        self.conn_to_use = conn_id;
    }

    pub fn get_conn(&self) -> Option<u64> {
        self.conn_to_use
    }


}

/// A simple no-op hasher for Stream IDs.

#[derive(Default)]
pub struct SimpleIdHasher {
    id: u64,
}

impl std::hash::Hasher for SimpleIdHasher {
    #[inline]
    fn finish(&self) -> u64 {
        self.id
    }

    #[inline]
    fn write_u64(&mut self, id: u64) {
        self.id = id;
    }

    #[inline]
    fn write(&mut self, _: &[u8]) {
        // We need a default write() for the trait but stream IDs will always
        // be a u64 so we just delegate to write_u64.
        unimplemented!()
    }
}

type BuildStreamIdHasher = std::hash::BuildHasherDefault<SimpleIdHasher>;

pub type SimpleIdHashMap<V> = HashMap<u64, V, BuildStreamIdHasher>;
pub type SimpleIdHashSet = HashSet<u64, BuildStreamIdHasher>;

/// Keeps track of TCPLS streams and enforces stream limits.
#[derive(Default)]
pub struct StreamMap {
    /// Map of streams indexed by stream ID.
    streams: SimpleIdHashMap<Stream>,
    /// Queue of stream IDs corresponding to streams that have buffered data
    /// ready to be sent to the peer. This also implies that the stream has
    /// enough flow control credits to send at least some of that data.
    flushable: SimpleIdHashSet,


    /// Set of stream IDs corresponding to streams that have enough flow control
    /// capacity to be written to, and is not finished. This is used to generate
    /// a `StreamIter` of streams without having to iterate over the full list
    /// of streams.
    pub writable: SimpleIdHashSet,

    /// Set of streams that were completed and garbage collected.
    ///
    /// Instead of keeping the full stream state forever, we collect completed
    /// streams to save memory, but we still need to keep track of previously
    /// created streams, to prevent peers from re-creating them.
    collected: SimpleIdHashSet,

}

impl StreamMap {
    pub fn new() -> Self {
        Self {
            streams: SimpleIdHashMap::default(),
            ..StreamMap::default()
        }
    }

    /// Returns the stream with the given ID if it exists.
    #[inline]
    pub fn get(&self, id: u16) -> Option<&Stream> {
        self.streams.get(&(id as u64))
    }

    /// Returns the mutable stream with the given ID if it exists.
    #[inline]
    pub fn get_mut(&mut self, id: u16) -> Option<&mut Stream> {
        self.streams.get_mut(&(id as u64))
    }

    /// Returns the mutable stream with the given ID if it exists, or creates
    /// a new one otherwise.
    ///
    /// The `local` parameter indicates whether the stream's creation was
    /// requested by the local application rather than the peer, and is
    /// used to validate the requested stream ID, and to select the initial
    /// flow control values from the local and remote transport parameters
    /// (also passed as arguments).
    ///
    /// This also takes care of enforcing both local and the peer's stream
    /// count limits. If one of these limits is violated, the `StreamLimit`
    /// error is returned.
    #[inline]
    pub fn get_or_create(
        &mut self, stream_id: u16,
    ) -> Result<&mut Stream, Error> {
        let (stream, is_new_and_writable) = match self.streams.entry(stream_id as u64) {
            hash_map::Entry::Vacant(v) => {
                // Stream has already been closed and garbage collected.
                if self.collected.contains(&(stream_id as u64)) {
                    return Err(Error::Done);
                }

                let s = Stream::new(stream_id);

                let is_writable = s.is_writable();

                (v.insert(s), is_writable)
            },

            hash_map::Entry::Occupied(v) => (v.into_mut(), false),
        };


        if is_new_and_writable {
            self.writable.insert(stream_id as u64);
        }

        Ok(stream)
    }



    /// Adds the stream ID to the writable streams set.
    ///
    /// This should also be called anytime a new stream is created, in addition
    /// to when an existing stream becomes writable.
    ///
    /// If the stream was already in the list, this does nothing.
    #[inline]
    pub fn insert_writable(&mut self, id: u64) {
        if !self.writable.contains(&id) {
            self.writable.insert(id);
        }
    }

    /// Removes the stream ID from the writable streams set.
    ///
    /// This should also be called anytime an existing stream stops being
    /// writable.
    #[inline]
    pub fn remove_writable(&mut self, stream_id: u64) {
        self.writable.remove(&stream_id);
    }

    /// Adds the stream ID to the flushable streams set.
    ///
    /// If the stream was already in the list, this does nothing.
    #[inline]
    pub fn insert_flushable(&mut self, id: u64) {
        if !self.flushable.contains(&id) {
            self.flushable.insert(id);
        }
    }

    /// Removes the stream ID from the flushable streams set.
    #[inline]
    pub fn remove_flushable(&mut self, stream_id: u64) { self.flushable.remove(&stream_id); }

    /// Adds the stream ID to the collected streams set.
    ///
    /// If the stream was already in the list, this does nothing.
    #[inline]
    pub fn insert_collected(&mut self, id: u64) {
        if !self.collected.contains(&id) {
            self.collected.insert(id);
        }
    }

    /// Removes the stream ID from the collected streams set.
    #[inline]
    pub fn remove_collected(&mut self, stream_id: u64) { self.collected.remove(&stream_id); }




    /// Creates an iterator over streams that can be written to.
    #[inline]
    pub fn writable(&self) -> StreamIter { StreamIter::from(&self.writable) }

    /// Creates an iterator over streams that have data to send.
    #[inline]
    pub fn flushable(&self) -> StreamIter { StreamIter::from(&self.flushable) }

    /// Creates an iterator over streams that have been collected.
    #[inline]
    pub fn collected(&self) -> StreamIter { StreamIter::from(&self.collected) }


    pub fn streams_to_flush(&self, flushables: &mut SimpleIdHashSet) -> StreamIter {
        StreamIter::from(&flushables)
    }

    /// Returns the set of ids of open streams
    pub fn open_streams(&self) -> SimpleIdHashSet {
        let mut id_set = SimpleIdHashSet::default();
        for item in self.streams.iter() {
            id_set.insert(item.1.id as u64);
        }
        id_set
    }

    pub fn iter(&self) -> Iter<'_, u64, Stream> {
        self.streams.iter()
    }

        /// Returns true if the stream has been collected.
    pub fn is_collected(&self, stream_id: u64) -> bool { self.collected.contains(&stream_id) }

    /// Returns true if there are any streams that have data to write.
    pub fn has_flushable(&self) -> bool {
        !self.flushable.is_empty()
    }
    #[inline]
    pub fn all_empty(&self) -> bool {
        let mut all_empty = true;
        let flushable = self.flushable();
        for id in flushable {
            all_empty &= self.streams.get(&id).unwrap().send.is_empty();
        }
        all_empty
    }



    /// Returns the number of active streams in the map.
    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.streams.len()
    }


    /// Rewind the Stream_id's receive buffer of num bytes
    pub fn rewind_recv_buf(&mut self, _stream_id: u64, _num: usize) -> Result<(), Error> {
        Ok(())
    }

    /// The current total number of bytes to be written to socket.
    pub fn total_to_write(&self) -> usize {
        let mut len = 0;
        for stream in &self.streams {
            len += stream.1.send.len();
        }
        len
    }

    pub fn reset_stream(&mut self, id: u32) {
        self.remove_flushable(id as u64);
        self.insert_writable(id as u64);
        self.get_mut(id as u16).unwrap().reset_stream()
    }
}



/// An iterator over TCPLS streams.
#[derive(Default)]
pub struct StreamIter {
    streams: SmallVec<[u64; 8]>,
    index: usize,
}

impl StreamIter {
    #[inline]
    pub fn from(streams: &SimpleIdHashSet) -> Self {
        StreamIter {
            streams: streams.iter().copied().collect(),
            index: 0,
        }
    }
}

impl Iterator for StreamIter {
    type Item = u64;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        let v = self.streams.get(self.index)?;
        self.index += 1;
        Some(*v)
    }
}

impl ExactSizeIterator for StreamIter {
    #[inline]
    fn len(&self) -> usize {
        self.streams.len() - self.index
    }
}

#[test]

fn test_create_stream(){
    let mut map = StreamMap::new();
    let stream = map.get_or_create(55).unwrap();
    assert_eq!(stream.send.is_empty(), true)
}
