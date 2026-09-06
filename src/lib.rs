//! `toolgate`: auditoría de seguridad para servidores MCP.
//!
//! Un servidor MCP es código de terceros con acceso a tus datos que inyecta
//! texto directamente en el contexto del modelo. `toolgate` audita qué puede
//! hacer ese código, qué texto va a recibir el modelo, y si algo ha cambiado
//! desde la última vez.

mod error;

pub use error::Error;
