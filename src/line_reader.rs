use bytes::Bytes;
use std::fs::File;
use std::io::{self, BufRead, BufReader};
use std::path::Path;

pub struct LineReader {
    reader: BufReader<File>,
}

impl LineReader {
    pub fn new(path: &Path) -> io::Result<Self> {
        let file = File::open(path)?;
        Ok(Self {
            reader: BufReader::new(file),
        })
    }

    pub fn next_line(&mut self) -> io::Result<Option<Bytes>> {
        let mut buf = String::new();
        let read = self.reader.read_line(&mut buf)?;
        if read == 0 {
            return Ok(None); // EOF
        }

        let trimmed = buf.trim_end();
        if trimmed.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Empty line in -Z file",
            ));
        }

        Ok(Some(Bytes::from(trimmed.to_owned())))
    }
}
