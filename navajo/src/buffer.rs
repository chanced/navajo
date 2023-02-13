use alloc::{collections::VecDeque, vec::Vec};
use bytes::BytesMut;
use cfg_if::cfg_if;

pub trait Buffer<'a>: AsRef<[u8]> + AsMut<[u8]> + Extend<&'a u8> {
    fn truncate(&'a mut self, len: usize);
}

impl<'a> Buffer<'a> for Vec<u8> {
    fn truncate(&'a mut self, len: usize) {
        self.truncate(len)
    }
}

impl<'a> Buffer<'a> for BytesMut {
    fn truncate(&'a mut self, len: usize) {
        self.truncate(len)
    }
}
// cfg_if! {
//     if #[cfg(feature = "ring")] {
//         pub struct RingBuffer<'a, B>(pub(crate) &'a mut B);
//         impl<'a, B> Extend<&'a u8> for RingBuffer<'a, B>
//         where
//             B: Buffer,
//         {
//             fn extend<T: IntoIterator<Item = &'a u8>>(&mut self, iter: T) {
//                 self.0.extend(iter.into_iter().copied())
//             }
//         }
//         impl<B> AsRef<[u8]> for RingBuffer<'_, B>
//         where
//             B: Buffer,
//         {
//             fn as_ref(&self) -> &[u8] {
//                 self.0.as_ref()
//             }
//         }
//         impl<B> AsMut<[u8]> for RingBuffer<'_, B>
//         where
//             B: Buffer,
//         {
//             fn as_mut(&mut self) -> &mut [u8] {
//                 self.0.as_mut()
//             }
//         }
//     }
// }
