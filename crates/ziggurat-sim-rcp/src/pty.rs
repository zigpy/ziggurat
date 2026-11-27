//! A pty whose slave side a host opens like the serial port of a real RCP.

use nix::fcntl::{FcntlArg, OFlag, fcntl};
use nix::pty::openpty;
use nix::sys::termios::{SetArg, cfmakeraw, tcgetattr, tcsetattr};
use std::fs::File;
use std::io::{ErrorKind, Read, Write};
use std::os::fd::OwnedFd;
use std::path::Path;
use tokio::io::unix::AsyncFd;
use tracing::warn;

pub struct Pty {
    master: AsyncFd<File>,
    /// Held open so the master never sees a hangup when a host closes the slave. A
    /// host can exit, and another can open the pty later.
    _slave: OwnedFd,
}

impl Pty {
    /// Opens a pty and points `link` at its slave side.
    pub fn open(link: &Path) -> Self {
        let pty = openpty(None, None).unwrap();

        let mut termios = tcgetattr(&pty.slave).unwrap();
        cfmakeraw(&mut termios);
        tcsetattr(&pty.slave, SetArg::TCSANOW, &termios).unwrap();

        let flags = OFlag::from_bits_truncate(fcntl(&pty.master, FcntlArg::F_GETFL).unwrap());
        fcntl(&pty.master, FcntlArg::F_SETFL(flags | OFlag::O_NONBLOCK)).unwrap();

        let slave_path = nix::unistd::ttyname(&pty.slave).unwrap();

        match std::fs::remove_file(link) {
            Ok(()) => {}
            Err(err) if err.kind() == ErrorKind::NotFound => {}
            Err(err) => panic!("cannot replace {}: {err}", link.display()),
        }
        std::os::unix::fs::symlink(&slave_path, link).unwrap();

        Self {
            master: AsyncFd::new(File::from(pty.master)).unwrap(),
            _slave: pty.slave,
        }
    }

    pub async fn read(&self, buffer: &mut [u8]) -> usize {
        loop {
            let mut guard = self.master.readable().await.unwrap();

            if let Ok(result) = guard.try_io(|master| {
                let mut file: &File = master.get_ref();
                file.read(buffer)
            }) {
                return result.unwrap();
            }
        }
    }

    /// Writes without waiting. Bytes the host has not made room for are dropped, like a
    /// UART overrun, so a pty with no host attached never stalls the radio.
    pub fn write(&self, bytes: &[u8]) {
        let mut file: &File = self.master.get_ref();

        match file.write(bytes) {
            Ok(written) if written == bytes.len() => {}
            Ok(written) => warn!(
                "Host is not reading, dropped {} bytes",
                bytes.len() - written
            ),
            Err(err) if err.kind() == ErrorKind::WouldBlock => {
                warn!("Host is not reading, dropped {} bytes", bytes.len());
            }
            Err(err) => panic!("pty write failed: {err}"),
        }
    }
}
