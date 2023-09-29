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


use std::{cmp, time};
use std::collections::{BinaryHeap, BTreeMap, hash_map, HashMap, HashSet, VecDeque};
use std::sync::Arc;
use smallvec::SmallVec;
use crate::Error;
use crate::recvbuf::RecvBuffer;
use crate::vecbuf::ChunkVecBuffer;

pub const DEFAULT_BUFFER_LIMIT: usize = 64 * 1024;


pub struct Stream {

    pub id: u64,

    /**
     * the stream should be cleaned up the next time tcpls_send is called
     */
    pub marked_for_close: bool,

    /**
     * Whether we still have to initialize the aead context for this stream.
     * That may happen if this stream is created before the handshake took place.
     */
    pub aead_initialized: bool,

    /// buffers encrypted TLS records that to be sent on the TCP socket
    pub(crate) send: ChunkVecBuffer,

}

impl Stream {
    pub fn new(id: u64) -> Self {
        Self{
            id: id,
            marked_for_close: false,
            aead_initialized: false,
            send: ChunkVecBuffer::new(Some(DEFAULT_BUFFER_LIMIT)),
        }
    }



    /// Returns true if the stream has enough capacity to be
    /// written to, and is not finished.
    pub fn is_writable(&self) -> bool {
        !self.send.is_full()
    }

    /// Returns true if the stream has data to send.
    pub fn is_flushable(&self) -> bool {
        !self.send.is_empty()
    }

    /*/// Returns true if the stream is complete.
    ///
    /// For bidirectional streams this happens when both the receive and send
    /// sides are complete. That is when all incoming data has been read by the
    /// application, and when all outgoing data has been acked by the peer.
    ///

    pub fn is_complete(&self) -> bool {
        match (self.bidi, self.local) {
            // For bidirectional streams we need to check both receive and send
            // sides for completion.
            (true, _) => self.recv.is_fin() && self.send.is_complete(),

            // For unidirectional streams generated locally, we only need to
            // check the send side for completion.
            (false, true) => self.send.is_complete(),

            // For unidirectional streams generated by the peer, we only need
            // to check the receive side for completion.
            (false, false) => self.recv.is_fin(),
        }
    }*/

/// Returns true if the stream was created locally.
    pub fn is_local(stream_id: u64, is_server: bool) -> bool {
    (stream_id & 0x1) == (is_server as u64)
    }


}

/// A simple no-op hasher for Stream IDs.

#[derive(Default)]
pub struct StreamIdHasher {
    id: u64,
}

impl std::hash::Hasher for StreamIdHasher {
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

type BuildStreamIdHasher = std::hash::BuildHasherDefault<StreamIdHasher>;

pub type StreamIdHashMap<V> = HashMap<u64, V, BuildStreamIdHasher>;
pub type StreamIdHashSet = HashSet<u64, BuildStreamIdHasher>;

/// Keeps track of TCPLS streams and enforces stream limits.
#[derive(Default)]
pub struct StreamMap {
    /// Map of streams indexed by stream ID.
    streams: StreamIdHashMap<Stream>,
    /// Queue of stream IDs corresponding to streams that have buffered data
    /// ready to be sent to the peer. This also implies that the stream has
    /// enough flow control credits to send at least some of that data.
    flushable: StreamIdHashSet,

    /// Set of stream IDs corresponding to streams that have outstanding data
    /// to read. This is used to generate a `StreamIter` of streams without
    /// having to iterate over the full list of streams.
    pub readable: StreamIdHashSet,

    /// Set of stream IDs corresponding to streams that have enough flow control
    /// capacity to be written to, and is not finished. This is used to generate
    /// a `StreamIter` of streams without having to iterate over the full list
    /// of streams.
    pub writable: StreamIdHashSet,

    /// Set of streams that were completed and garbage collected.
    ///
    /// Instead of keeping the full stream state forever, we collect completed
    /// streams to save memory, but we still need to keep track of previously
    /// created streams, to prevent peers from re-creating them.
    collected: StreamIdHashSet,
}

impl StreamMap {
    pub fn new() -> Self {
        Self {
            streams: StreamIdHashMap::default(),
            ..StreamMap::default()
        }
    }

    /// Returns the stream with the given ID if it exists.
    pub fn get(&self, id: u64) -> Option<&Stream> {
        self.streams.get(&id)
    }

    /// Returns the mutable stream with the given ID if it exists.
    pub fn get_mut(&mut self, id: u64) -> Option<&mut Stream> {
        self.streams.get_mut(&id)
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
    pub fn get_or_create(
        &mut self, id: u64, is_server: bool,
    ) -> Result<&mut Stream, Error> {
        let (stream, is_new_and_writable) = match self.streams.entry(id) {
            hash_map::Entry::Vacant(v) => {
                // Stream has already been closed and garbage collected.
                if self.collected.contains(&id) {
                    return Err(Error::Done);
                }

                if is_server != (stream_id & 0x1) {
                    return Err(Error::BadStreamId);
                }

                let s = Stream::new(id);

                let is_writable = s.is_writable();

                (v.insert(s), is_writable)
            },

            hash_map::Entry::Occupied(v) => (v.into_mut(), false),
        };


        if is_new_and_writable {
            self.writable.insert(id);
        }

        Ok(stream)
    }

    /// Adds the stream ID to the readable streams set.
    ///
    /// If the stream was already in the list, this does nothing.
    pub fn insert_readable(&mut self, stream_id: u64) {
        self.readable.insert(stream_id);
    }

    /// Removes the stream ID from the readable streams set.
    pub fn remove_readable(&mut self, stream_id: u64) {
        self.readable.remove(&stream_id);
    }

    /// Adds the stream ID to the writable streams set.
    ///
    /// This should also be called anytime a new stream is created, in addition
    /// to when an existing stream becomes writable.
    ///
    /// If the stream was already in the list, this does nothing.
    pub fn insert_writable(&mut self, stream_id: u64) {
        self.writable.insert(stream_id);
    }

    /// Removes the stream ID from the writable streams set.
    ///
    /// This should also be called anytime an existing stream stops being
    /// writable.
    pub fn remove_writable(&mut self, stream_id: u64) {
        self.writable.remove(&stream_id);
    }

    /// Adds the stream ID to the flushable streams set.
    ///
    /// If the stream was already in the list, this does nothing.
    pub fn insert_flushable(&mut self, stream_id: u64) { self.flushable.insert(stream_id); }

    /// Removes the stream ID from the flushable streams set.
    pub fn remove_flushable(&mut self, stream_id: u64) { self.flushable.remove(&stream_id); }

    /// Adds the stream ID to the collected streams set.
    ///
    /// If the stream was already in the list, this does nothing.
    pub fn insert_collected(&mut self, stream_id: u64) { self.collected.insert(stream_id); }

    /// Removes the stream ID from the collected streams set.
    pub fn remove_collected(&mut self, stream_id: u64) { self.collected.remove(&stream_id); }


    /// Creates an iterator over streams that have outstanding data to read.
    pub fn readable(&self) -> StreamIter {
        StreamIter::from(&self.readable)
    }

    /// Creates an iterator over streams that can be written to.
    pub fn writable(&self) -> StreamIter { StreamIter::from(&self.writable) }

    /// Creates an iterator over streams that have been collected.
    pub fn collected(&self) -> StreamIter { StreamIter::from(&self.collected) }

        /// Returns true if the stream has been collected.
    pub fn is_collected(&self, stream_id: u64) -> bool { self.collected.contains(&stream_id) }

    /// Returns true if there are any streams that have data to write.
    pub fn has_flushable(&self) -> bool {
        !self.flushable.is_empty()
    }

    /// Returns true if there are any streams that have data to read.
    pub fn has_readable(&self) -> bool {
        !self.readable.is_empty()
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
}

#[derive(Default)]
pub struct RecvBufMap {
    buffers: StreamIdHashMap<RecvBuffer>,
}

impl RecvBufMap {

    pub fn new() -> RecvBufMap {
        RecvBufMap {
            ..Default::default()
        }
    }


    pub(crate) fn get_or_create_stream_buffer(&mut self, stream_id: u64) -> &mut RecvBuffer {
        match self.buffers.entry(stream_id) {
            hash_map::Entry::Vacant(v) => {
                v.insert(RecvBuffer::new(stream_id, None))
            },
            hash_map::Entry::Occupied(v) => v.into_mut(),
        }
    }


    pub fn get_mut(&mut self, stream_id: u64) -> Option<&mut [u8]> {
        Some(self.buffers.get_mut(&stream_id)?
            .get_mut_consumed())
    }

    pub(crate) fn read_mut(&mut self, stream_id: u64, stream: &mut Stream) -> Result<&mut [u8], Error> {
        let buf = match self.buffers.entry(stream_id) {
            hash_map::Entry::Vacant(_v) => {
                return Err(Error::RecvBufNotFound);
            }
            hash_map::Entry::Occupied(v) => v.into_mut().read_mut(&mut stream.recv)?,
        };
        Ok(buf)
    }

    pub(crate) fn has_consumed(&mut self, stream_id: u64, stream: Option<&Stream>, consumed: usize) -> Result<usize, Error>{
        match self.buffers.entry(stream_id) {
            hash_map::Entry::Occupied(v) => {
                // Registers how much the app has read on this stream buffer. If we don't
                // have a stream, it means it has been collected. We need to collect our stream
                // buffer as well assuming the application has read everything that was readable.
                let (to_collect, remaining_data) = v.into_mut().has_consumed(stream, consumed)?;
                if to_collect {
                    self.collect(stream_id);
                }
                Ok(remaining_data)
            },
            _ => Ok(0),
        }
    }*/

    /*pub(crate) fn is_consumed(&self, stream_id: u64) -> bool {
        match self.buffers.get(&stream_id) {
            Some(v) => {
                v.is_consumed()
            }
            _ => true,
        }
    }*/

   /* pub fn collect(&mut self, stream_id: u64) {
        if let Some(mut buf) = self.buffers.remove(&stream_id) {
            if self.recycled_buffers.len() < self.recycled_buffers.capacity() {
                buf.clear();
                self.recycled_buffers.push_back(buf);
            }
        }
    }*/

}

/// An iterator over TCPLS streams.
#[derive(Default)]
pub struct StreamIter {
    streams: SmallVec<[u64; 8]>,
    index: usize,
}

impl StreamIter {
    #[inline]
    fn from(streams: &StreamIdHashSet) -> Self {
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


