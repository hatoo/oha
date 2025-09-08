use bytes::Bytes;
use std::fs::File;
use std::io::{self, BufRead, BufReader, Lines};
use std::path::Path;

pub struct LineReader {
    lines: Lines<BufReader<File>>,
}

impl LineReader {
    pub fn new(path: &Path) -> io::Result<Self> {
        let file = File::open(path)?;
        Ok(Self {
            lines: BufReader::new(file).lines(),
        })
    }

    pub fn next_line(&mut self) -> io::Result<Option<Bytes>> {
        match self.lines.next() {
            Some(line) => line.map(|line| Some(Bytes::from(line))),
            None => Ok(None),
        }
    }
}
