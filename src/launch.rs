//! Arranque contenido de un servidor MCP.
//!
//! **Esto no es un sandbox.** Reduce la superficie —entorno mínimo, cwd
//! temporal, timeout, lecturas acotadas— pero no contiene a un atacante. En el
//! README va dicho igual de claro, no en la letra pequeña.

use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{Receiver, RecvTimeoutError, channel};
use std::time::Duration;

use crate::error::Error;

// Un servidor malicioso puede inundar stdout: se corta.
const MAX_LINES: usize = 10_000;

pub struct Contained {
    child: Child,
    stdin: ChildStdin,
    lines: Receiver<String>,
}

impl Contained {
    /// Arranca el servidor con el entorno reducido y la salida acotada.
    pub fn spawn(command: &str, args: &[String]) -> Result<Contained, Error> {
        let cwd = std::env::temp_dir().join(format!("toolgate-{}", std::process::id()));
        std::fs::create_dir_all(&cwd).map_err(|e| Error::Io {
            path: cwd.display().to_string(),
            source: e,
        })?;

        let mut child = Command::new(command)
            .args(args)
            // Entorno mínimo: no hereda tus variables ni tus credenciales.
            // Solo PATH, para que el proceso pueda encontrar sus binarios.
            .env_clear()
            .env("PATH", std::env::var("PATH").unwrap_or_default())
            .current_dir(&cwd)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| Error::Io {
                path: command.to_owned(),
                source: e,
            })?;

        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| Error::Protocol("the process exposes no stdin".to_owned()))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| Error::Protocol("the process exposes no stdout".to_owned()))?;

        // Un hilo lector empujando líneas por un canal: es la forma portable de
        // tener timeout de lectura sin async ni APIs específicas del SO.
        let (tx, lines) = channel();
        std::thread::spawn(move || {
            let reader = BufReader::new(stdout);
            for line in reader.lines().take(MAX_LINES) {
                let Ok(line) = line else { break };
                if tx.send(line).is_err() {
                    break;
                }
            }
        });

        Ok(Contained {
            child,
            stdin,
            lines,
        })
    }

    pub fn send_line(&mut self, text: &str) -> Result<(), Error> {
        writeln!(self.stdin, "{text}").map_err(|e| Error::Io {
            path: "stdin".to_owned(),
            source: e,
        })?;
        self.stdin.flush().map_err(|e| Error::Io {
            path: "stdin".to_owned(),
            source: e,
        })
    }

    pub fn recv_line(&mut self, timeout: Duration) -> Result<String, Error> {
        match self.lines.recv_timeout(timeout) {
            Ok(line) => Ok(line),
            Err(RecvTimeoutError::Timeout) => Err(Error::Timeout),
            Err(RecvTimeoutError::Disconnected) => {
                Err(Error::Protocol("the server closed its output".to_owned()))
            }
        }
    }
}

impl Drop for Contained {
    fn drop(&mut self) {
        // Nunca se deja corriendo un servidor no confiado.
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[cfg(test)]
mod tests {
    use super::Contained;
    use std::time::Duration;

    #[test]
    fn spawning_a_missing_command_fails() {
        assert!(Contained::spawn("comando_que_no_existe_xyz", &[]).is_err());
    }

    #[test]
    fn reading_with_nothing_to_read_times_out() {
        // `node -e ""` arranca y no escribe nada.
        let Ok(mut server) = Contained::spawn("node", &["-e".to_owned(), String::new()]) else {
            return; // sin Node instalado, el test se salta
        };
        assert!(server.recv_line(Duration::from_millis(400)).is_err());
    }

    #[test]
    fn round_trips_a_line() {
        let script = "process.stdin.on('data', d => process.stdout.write(d));";
        let Ok(mut server) = Contained::spawn("node", &["-e".to_owned(), script.to_owned()]) else {
            return;
        };
        server.send_line("hola").unwrap();
        let line = server.recv_line(Duration::from_secs(10)).unwrap();
        assert_eq!(line.trim(), "hola");
    }

    #[test]
    fn the_environment_is_minimal() {
        // El hijo no debe heredar el entorno del padre: solo PATH, para que
        // pueda encontrar sus binarios. `set_var` no vale aquí porque el crate
        // prohíbe `unsafe`, así que se mide el tamaño del entorno resultante.
        let script = "process.stdout.write(Object.keys(process.env).length + \":\" + String(!!process.env.PATH));";
        let Ok(mut server) = Contained::spawn("node", &["-e".to_owned(), script.to_owned()]) else {
            return;
        };
        let line = server.recv_line(Duration::from_secs(10)).unwrap();
        let (count, has_path) = line.trim().split_once(char::from(58)).unwrap();
        assert_eq!(has_path, "true", "el hijo necesita PATH");
        let count: usize = count.parse().unwrap();
        assert!(
            count < 5,
            "el entorno debería ser mínimo, tiene {count} variables"
        );
    }
}
