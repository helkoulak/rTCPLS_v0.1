
use alloc::collections::VecDeque;
use alloc::vec::Vec;
use core::cmp;
#[cfg(feature = "std")]
use std::io;
#[cfg(feature = "std")]
use std::io::Read;
use std::vec;

#[cfg(feature = "std")]
use crate::msgs::message::OutboundChunks;

/// This is a byte buffer that is built from a vector
/// of byte vectors.  This avoids extra copies when
/// appending a new byte vector, at the expense of
/// more complexity when reading out.
/// where the next chunk will be appended
#[derive(Default)]
pub(crate) struct ChunkVecBuffer {
    chunks: VecDeque<Vec<u8>>,
    limit: Option<usize>,
    /// where the next chunk will be appended
    current_offset: u64,
    /// The offset immediately behind "current_offset"
    previous_offset: u64,
    /// Amount of application bytes in plain that are buffered
    plain_buffered: usize,

}

impl ChunkVecBuffer {
    pub(crate) fn new(limit: Option<usize>) -> Self {
        Self {
            chunks: VecDeque::new(),
            limit,
            ..Default::default()
        }
    }
    #[inline]
    pub(crate)  fn get_current_offset(&self) -> u64 {
        self.current_offset
    }

    /// Output is of type u16 as maximum payload size for a TLS record is 16384 bytes
    #[inline]
    pub(crate)  fn get_offset_diff(&self) -> u16 {
        self.current_offset.saturating_sub(self.previous_offset) as u16
    }
    #[inline]
    pub(crate)  fn advance_offset(&mut self, added: u64) {
        self.previous_offset = self.current_offset;
        self.current_offset += added;
    }


    /// Sets the upper limit on how many bytes this
    /// object can store.
    ///
    /// Setting a lower limit than the currently stored
    /// data is not an error.
    ///
    /// A [`None`] limit is interpreted as no limit.

    pub(crate) fn set_limit(&mut self, new_limit: Option<usize>) {
        self.limit = new_limit;
    }

    /// If we're empty
    #[inline]
    pub(crate)  fn is_empty(&self) -> bool {
        self.chunks.is_empty()
    }
    #[inline]
    pub(crate)  fn shuffle_records(&mut self, n: usize) {
        self.chunks.rotate_left(n)
    }

    /// How many bytes we're storing
    pub(crate) fn len(&self) -> usize {
        let mut len = 0;
        for ch in &self.chunks {
            len += ch.len();
        }
        len
    }

    /// For a proposed append of `len` bytes, how many
    /// bytes should we actually append to adhere to the
    /// currently set `limit`?

    pub(crate) fn apply_limit(&self, len: usize) -> usize {
        if let Some(limit) = self.limit {
            let space = limit.saturating_sub(self.len());
            cmp::min(len, space)
        } else {
            len
        }
    }


    /// Take and append the given `bytes`.
    pub(crate) fn append(&mut self, bytes: Vec<u8>) -> usize {
        let len = bytes.len();

        if !bytes.is_empty() {
            self.chunks.push_back(bytes);
        }
        len
    }

    /// Take one of the chunks from this object.  This
    /// function panics if the object `is_empty`.
    pub(crate) fn pop(&mut self) -> Option<Vec<u8>> {
        self.chunks.pop_front()
    }

    pub(crate) fn reset(&mut self) {
        self.chunks.clear();
        self.limit = None;
        self.previous_offset = 0;
        self.current_offset = 0;
    }


    #[cfg(read_buf)]
    /// Read data out of this object, writing it into `cursor`.
    pub(crate) fn read_buf(&mut self, mut cursor: core::io::BorrowedCursor<'_>) -> io::Result<()> {
        while !self.is_empty() && cursor.capacity() > 0 {
            let chunk = self.chunks[0].as_slice();
            let used = core::cmp::min(chunk.len(), cursor.capacity());
            cursor.append(&chunk[..used]);
            self.consume(used);
        }

        Ok(())
    }
}

#[cfg(feature = "std")]
impl ChunkVecBuffer {
    pub(crate) fn is_full(&self) -> bool {
        self.limit
            .map(|limit| self.len() > limit)
            .unwrap_or_default()
    }

    /// Append a copy of `bytes`, perhaps a prefix if
    /// we're near the limit.
    pub(crate) fn append_limited_copy(&mut self, payload: OutboundChunks<'_>) -> usize {
        let take = self.apply_limit(payload.len());
        self.append(payload.split_at(take).0.to_vec());
        take
    }

    /// Read data out of this object, writing it into `buf`
    /// and returning how many bytes were written there.
    pub(crate) fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut offs = 0;

        while offs < buf.len() && !self.is_empty() {
            let used = self.chunks[0]
                .as_slice()
                .read(&mut buf[offs..])?;

            self.consume(used);
            offs += used;
        }

        Ok(offs)
    }


    fn consume(&mut self, mut used: usize) {
        while let Some(mut buf) = self.chunks.pop_front() {
            if used < buf.len() {
                buf.drain(..used);
                self.chunks.push_front(buf);
                break;
            } else {
                used -= buf.len();
            }
        }
    }


    pub(crate) fn consume_chunk(&mut self, mut used: usize, chunk: Vec<u8>) {
        let mut buf = chunk;
        if used < buf.len() {
            self.chunks.push_front(buf.split_off(used));
        }
    }

    /// Read data out of this object, passing it `wr`
    pub(crate) fn write_to(&mut self, wr: &mut dyn io::Write) -> io::Result<usize> {
        if self.is_empty() {
            return Ok(0);
        }

        let mut bufs = [io::IoSlice::new(&[]); 64];
        for (iov, chunk) in bufs.iter_mut().zip(self.chunks.iter()) {
            *iov = io::IoSlice::new(chunk);
        }
        let len = cmp::min(bufs.len(), self.chunks.len());
        let used = wr.write_vectored(&bufs[..len])?;
        self.consume(used);
        Ok(used)
    }

    #[inline]
    pub(crate) fn write_chunk_to(&mut self, wr: &mut dyn io::Write) -> io::Result<usize> {
        if self.is_empty() {
            return Ok(0);
        }

        let mut sent = 0;
        let chunk = self.chunks.pop_front().unwrap();
        let chunk_len = chunk.len();

        sent = wr
            .write(chunk.as_slice())
            .unwrap();
        self.consume_chunk(sent, chunk);

        Ok(sent)
    }

    pub(crate) fn get_chunk(&mut self) -> Option<Vec<u8>> {
        if self.is_empty() {
            return None ;
        } else {
            Some(self.chunks.pop_front().unwrap())
        }
    }

    #[inline]
    pub(crate) fn pop_front(&mut self) -> Option<Vec<u8>> {
       self.chunks.pop_front()
    }

    #[inline]
    pub(crate) fn push_front(&mut self, buf: Vec<u8>) {
        self.chunks.push_front(buf)
    }

}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::ChunkVecBuffer;

    #[test]
    fn short_append_copy_with_limit() {
        let mut cvb = ChunkVecBuffer::new(Some(12));

        assert_eq!(cvb.append_limited_copy(b"hello"[..].into()), 5);
        assert_eq!(cvb.append_limited_copy(b"world"[..].into()), 5);
        assert_eq!(cvb.append_limited_copy(b"hello"[..].into()), 2);
        assert_eq!(cvb.append_limited_copy(b"world"[..].into()), 0);
        let mut buf = [0u8; 12];
        assert_eq!(cvb.read(&mut buf).unwrap(), 12);
        assert_eq!(buf.to_vec(), b"helloworldhe".to_vec());
    }


    #[cfg(read_buf)]
    #[test]
    fn read_buf() {
        use core::io::BorrowedBuf;
        use core::mem::MaybeUninit;

        {
            let mut cvb = ChunkVecBuffer::new(None);
            cvb.append(b"test ".to_vec());
            cvb.append(b"fixture ".to_vec());
            cvb.append(b"data".to_vec());

            let mut buf = [MaybeUninit::<u8>::uninit(); 8];
            let mut buf: BorrowedBuf<'_> = buf.as_mut_slice().into();
            cvb.read_buf(buf.unfilled()).unwrap();
            assert_eq!(buf.filled(), b"test fix");
            buf.clear();
            cvb.read_buf(buf.unfilled()).unwrap();
            assert_eq!(buf.filled(), b"ture dat");
            buf.clear();
            cvb.read_buf(buf.unfilled()).unwrap();
            assert_eq!(buf.filled(), b"a");
        }

        {
            let mut cvb = ChunkVecBuffer::new(None);

            cvb.append(b"short message".to_vec());

            let mut buf = [MaybeUninit::<u8>::uninit(); 1024];
            let mut buf: BorrowedBuf<'_> = buf.as_mut_slice().into();
            cvb.read_buf(buf.unfilled()).unwrap();
            assert_eq!(buf.filled(), b"short message");
        }
    }
}
