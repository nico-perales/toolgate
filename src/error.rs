//! The crate's error type.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("could not read the tarball: {0}")]
    Tarball(String),

    #[error("missing or invalid package.json: {0}")]
    Manifest(String),

    #[error("the server did not answer in time")]
    Timeout,

    #[error("invalid MCP response: {0}")]
    Protocol(String),

    #[error("the static pass vetoed the launch: {0}")]
    Vetoed(String),

    #[error("i/o error on {path}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
}
