use std::fmt;
use std::io;

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    Format(String),
    InvalidArgument(String),
    Unsupported(String),
    Cancelled(String),
}

impl Error {
    pub(crate) fn format(message: impl Into<String>) -> Self {
        Self::Format(message.into())
    }

    pub(crate) fn invalid(message: impl Into<String>) -> Self {
        Self::InvalidArgument(message.into())
    }

    pub(crate) fn unsupported(message: impl Into<String>) -> Self {
        Self::Unsupported(message.into())
    }

    pub(crate) fn cancelled(message: impl Into<String>) -> Self {
        Self::Cancelled(message.into())
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "I/O error: {e}"),
            Self::Format(s) => write!(f, "format error: {s}"),
            Self::InvalidArgument(s) => write!(f, "invalid argument: {s}"),
            Self::Unsupported(s) => write!(f, "unsupported: {s}"),
            Self::Cancelled(s) => write!(f, "cancelled: {s}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for Error {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

pub type Result<T> = std::result::Result<T, Error>;
