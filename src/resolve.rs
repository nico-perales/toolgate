//! Finding the executable to launch.
//!
//! On Windows, `Command::new("npx")` fails with "program not found": Rust adds
//! `.exe` but never tries `.cmd` or `.bat`, and `.cmd` is what npm installs. A bare
//! name is resolved here against `PATH` and `PATHEXT`, the way the Windows shell
//! does it. Rust escapes arguments for `.cmd` and `.bat` files safely since 1.77.2
//! (CVE-2024-24576) and refuses the ones it cannot escape, so this fails closed.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};

/// Resolves `name` for the current platform and environment.
pub fn resolve_command(name: &str) -> PathBuf {
    resolve_in(
        name,
        std::env::var_os("PATH").as_deref(),
        std::env::var_os("PATHEXT").as_deref(),
        cfg!(windows),
    )
}

const DEFAULT_PATHEXT: &str = ".COM;.EXE;.BAT;.CMD";

// The pure core of `resolve_command`, so the Windows rules can be tested on any
// platform without touching the process environment.
fn resolve_in(name: &str, path: Option<&OsStr>, pathext: Option<&OsStr>, windows: bool) -> PathBuf {
    let given = Path::new(name);
    // Outside Windows the OS already searches PATH.
    if !windows {
        return given.to_path_buf();
    }
    let extensions: Vec<&str> = pathext
        .and_then(OsStr::to_str)
        .unwrap_or(DEFAULT_PATHEXT)
        .split(';')
        .filter(|ext| !ext.is_empty())
        .collect();
    // A directory component, or an extension Windows would run, means the caller
    // was explicit. `python3.11` has a dot but no executable extension.
    let executable_ext = given
        .extension()
        .and_then(OsStr::to_str)
        .is_some_and(|ext| {
            extensions
                .iter()
                .any(|known| known.trim_start_matches('.').eq_ignore_ascii_case(ext))
        });
    if given.components().count() > 1 || executable_ext {
        return given.to_path_buf();
    }
    if let Some(path) = path {
        for dir in std::env::split_paths(path) {
            for ext in &extensions {
                let candidate = dir.join(format!("{name}{ext}"));
                if candidate.is_file() {
                    return candidate;
                }
            }
        }
    }
    given.to_path_buf()
}

#[cfg(test)]
mod tests {
    use super::resolve_in;
    use std::ffi::{OsStr, OsString};
    use std::path::PathBuf;

    const PATHEXT: &str = ".COM;.EXE;.BAT;.CMD";

    // A PATH holding one temporary directory with the given (empty) files. The
    // label keeps parallel tests out of each other's directories.
    fn dir_with(label: &str, files: &[&str]) -> (PathBuf, OsString) {
        let dir =
            std::env::temp_dir().join(format!("toolgate-resolve-{}-{label}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        for file in files {
            std::fs::write(dir.join(file), b"").unwrap();
        }
        let path = std::env::join_paths([&dir]).unwrap();
        (dir, path)
    }

    #[test]
    fn a_bare_name_finds_the_cmd_shim_on_windows() {
        let (dir, path) = dir_with("shim", &["fake.CMD"]);
        let found = resolve_in(
            "fake",
            Some(path.as_os_str()),
            Some(OsStr::new(PATHEXT)),
            true,
        );
        assert_eq!(found, dir.join("fake.CMD"));
    }

    #[test]
    fn pathext_order_decides_between_candidates() {
        let (dir, path) = dir_with("order", &["both.EXE", "both.CMD"]);
        let found = resolve_in(
            "both",
            Some(path.as_os_str()),
            Some(OsStr::new(PATHEXT)),
            true,
        );
        assert_eq!(found, dir.join("both.EXE"));
    }

    #[test]
    fn an_explicit_executable_extension_is_left_alone() {
        let (_dir, path) = dir_with("explicit", &["fake.CMD"]);
        let found = resolve_in(
            "fake.cmd",
            Some(path.as_os_str()),
            Some(OsStr::new(PATHEXT)),
            true,
        );
        assert_eq!(found, PathBuf::from("fake.cmd"));
    }

    #[test]
    fn a_dot_that_is_not_an_executable_extension_is_still_searched() {
        let (dir, path) = dir_with("dotted", &["python3.11.EXE"]);
        let found = resolve_in(
            "python3.11",
            Some(path.as_os_str()),
            Some(OsStr::new(PATHEXT)),
            true,
        );
        assert_eq!(found, dir.join("python3.11.EXE"));
    }

    #[test]
    fn outside_windows_nothing_is_resolved() {
        let (_dir, path) = dir_with("unix", &["fake.CMD"]);
        let found = resolve_in(
            "fake",
            Some(path.as_os_str()),
            Some(OsStr::new(PATHEXT)),
            false,
        );
        assert_eq!(found, PathBuf::from("fake"));
    }

    #[test]
    fn an_unknown_name_comes_back_unchanged() {
        let (_dir, path) = dir_with("unknown", &[]);
        let found = resolve_in(
            "nothing_here",
            Some(path.as_os_str()),
            Some(OsStr::new(PATHEXT)),
            true,
        );
        assert_eq!(found, PathBuf::from("nothing_here"));
    }
}
