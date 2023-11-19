use std::io;

#[non_exhaustive]
#[derive(Debug)]
/// A custom Goblin error
pub enum Error {
    /// The binary is malformed somehow
    Malformed(String),
    /// The binary's magic is unknown or bad
    BadMagic(u64),
    /// An error emanating from reading and interpreting bytes
    Scroll(scroll::Error),
    /// An IO based error
    IO(io::Error),
    /// Buffer is too short to hold N items
    BufferTooShort(usize, &'static str),
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match *self {
            Error::IO(ref io) => Some(io),
            Error::Scroll(ref scroll) => Some(scroll),
            _ => None,
        }
    }
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Error {
        Error::IO(err)
    }
}

impl From<scroll::Error> for Error {
    fn from(err: scroll::Error) -> Error {
        Error::Scroll(err)
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, fmt: &mut std::fmt::Formatter) -> std::fmt::Result {
        match *self {
            Error::IO(ref err) => write!(fmt, "{}", err),
            Error::Scroll(ref err) => write!(fmt, "{}", err),
            Error::BadMagic(magic) => write!(fmt, "Invalid magic number: 0x{:x}", magic),
            Error::Malformed(ref msg) => write!(fmt, "Malformed entity: {}", msg),
            Error::BufferTooShort(n, item) => write!(fmt, "Buffer is too short for {} {}", n, item),
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;
