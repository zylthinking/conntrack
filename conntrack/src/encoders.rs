use neli::{Size, ToBytes, genl::Nlattr, types::Buffer};
use std::io::Cursor;

pub trait IntoBuffer {
    fn into_buffer(self) -> Buffer;
}

impl IntoBuffer for Buffer {
    fn into_buffer(self) -> Buffer {
        self
    }
}

impl<T: Size> IntoBuffer for Nlattr<T, Buffer>
where
    Nlattr<T, Buffer>: ToBytes,
{
    fn into_buffer(self) -> Buffer {
        let mut cursor = Cursor::new(vec![0; self.unpadded_size()]);
        _ = self.to_bytes(&mut cursor);
        Buffer::from(cursor.into_inner())
    }
}
