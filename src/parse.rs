pub trait CursorExt {
    fn peek(&mut self) -> io::Result<u8>;
}

impl CursorExt for io::Cursor<Vec<u8>> {
    fn peek(&mut self) -> io::Result<u8> {
        self.get_ref()
            .get(self.position() as usize)
            .cloned()
            .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "unable to peek cursor"))
    }
}
