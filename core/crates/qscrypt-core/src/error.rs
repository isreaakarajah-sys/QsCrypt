use std::fmt;

/// Every failure the engine can report. `code()` gives a stable identifier
/// the apps map to localized messages.
#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    /// No header could be decrypted with the given password / PIM / keyfiles.
    WrongPassword,
    /// Valid data we do not handle yet (NTFS, Camellia, keyfiles...).
    Unsupported(String),
    /// Structurally invalid data.
    Corrupt(String),
    NotFound,
    AlreadyExists,
    NotADirectory,
    IsADirectory,
    InvalidName,
    NoSpace,
    ReadOnly,
    InvalidArgument(String),
    /// Authentication failed: the data was modified or truncated.
    Tampered,
    Cancelled,
    Crypto(String),
    /// A write to the outer volume would have overwritten the hidden one;
    /// all further writes are refused until the volume is closed.
    HiddenProtected,
}

impl Error {
    pub fn code(&self) -> &'static str {
        match self {
            Error::Io(_) => "io",
            Error::WrongPassword => "wrong_password",
            Error::Unsupported(_) => "unsupported",
            Error::Corrupt(_) => "corrupt",
            Error::NotFound => "not_found",
            Error::AlreadyExists => "exists",
            Error::NotADirectory => "not_a_directory",
            Error::IsADirectory => "is_a_directory",
            Error::InvalidName => "invalid_name",
            Error::NoSpace => "no_space",
            Error::ReadOnly => "read_only",
            Error::InvalidArgument(_) => "invalid_argument",
            Error::Tampered => "tampered",
            Error::Cancelled => "cancelled",
            Error::Crypto(_) => "crypto",
            Error::HiddenProtected => "hidden_protected",
        }
    }

    pub fn corrupt(msg: impl Into<String>) -> Error {
        Error::Corrupt(msg.into())
    }

    pub fn unsupported(msg: impl Into<String>) -> Error {
        Error::Unsupported(msg.into())
    }

    pub fn invalid(msg: impl Into<String>) -> Error {
        Error::InvalidArgument(msg.into())
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(e) => write!(f, "I/O error: {e}"),
            Error::WrongPassword => write!(f, "wrong password, PIM or format"),
            Error::Unsupported(m) => write!(f, "not supported yet: {m}"),
            Error::Corrupt(m) => write!(f, "corrupt data: {m}"),
            Error::NotFound => write!(f, "not found"),
            Error::AlreadyExists => write!(f, "already exists"),
            Error::NotADirectory => write!(f, "not a directory"),
            Error::IsADirectory => write!(f, "is a directory"),
            Error::InvalidName => write!(f, "invalid name"),
            Error::NoSpace => write!(f, "no space left"),
            Error::ReadOnly => write!(f, "read-only"),
            Error::InvalidArgument(m) => write!(f, "invalid argument: {m}"),
            Error::Tampered => write!(f, "authentication failed: data modified or truncated"),
            Error::Cancelled => write!(f, "cancelled"),
            Error::Crypto(m) => write!(f, "crypto error: {m}"),
            Error::HiddenProtected => write!(f, "write refused: it would damage the hidden volume"),
        }
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}

pub type Result<T> = std::result::Result<T, Error>;
