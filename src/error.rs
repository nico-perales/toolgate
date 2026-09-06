//! Tipo de error del crate.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("no se pudo leer el tarball: {0}")]
    Tarball(String),

    #[error("package.json inválido o ausente: {0}")]
    Manifest(String),

    #[error("el servidor no respondió a tiempo")]
    Timeout,

    #[error("respuesta MCP inválida: {0}")]
    Protocol(String),

    #[error("el análisis estático vetó el arranque: {0}")]
    Vetoed(String),

    #[error("i/o error en {path}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
}
