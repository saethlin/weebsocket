use crate::Error;
use mio::event::Event;
use mio::net::TcpStream;
use rustls::Session;
use std::io::{self, Read};

/// This encapsulates the TCP-level connection, some connection
/// state, and the underlying TLS-level session.
/// This struct is taken almost entirely from ctz/rustls/examples/tlsclient.rs
pub struct TlsClient {
    pub socket: TcpStream,
    closing: bool,
    clean_closure: bool,
    tls_session: rustls::ClientSession,
    buf: Vec<u8>,
    token: mio::Token,
}

/// We implement `io::Write` and pass through to the TLS session
impl io::Write for TlsClient {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.tls_session.write(bytes)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.tls_session.flush()
    }
}

impl TlsClient {
    pub fn new(sock: TcpStream, hostname: webpki::DNSNameRef, token: mio::Token) -> TlsClient {
        TlsClient {
            socket: sock,
            closing: false,
            clean_closure: false,
            tls_session: rustls::ClientSession::new(&TLS_CONFIG, hostname),
            buf: Vec::new(),
            token,
        }
    }

    pub fn ready(&mut self, poll: &mut mio::Poll, ev: &Event) -> Result<(), Error> {
        if ev.readiness().is_readable() {
            self.do_read()?;
        }

        if ev.readiness().is_writable() {
            self.do_write()?;
        }

        self.reregister(poll)?;

        Ok(())
    }

    /// We're ready to do a read.
    fn do_read(&mut self) -> Result<(), Error> {
        let bytes_read = self.tls_session.read_tls(&mut self.socket);
        match bytes_read {
            // Ready but no data
            Ok(0) => {
                self.closing = true;
                self.clean_closure = true;
                return Ok(());
            }
            // Underlying TCP connection is broken
            Err(e) => {
                self.closing = true;
                return Err(Error::Io(e));
            }
            _ => {}
        }

        // Reading some TLS data might have yielded new TLS
        // messages to process.  Errors from this indicate
        // TLS protocol problems and are fatal.
        let processed = self.tls_session.process_new_packets();
        if let Err(e) = processed {
            self.closing = true;
            return Err(Error::Tls(e));
        }

        // Having read some TLS data, and processed any new messages,
        // we might have new plaintext as a result.
        // Read it.
        let bytes_read = self.tls_session.read_to_end(&mut self.buf);

        // If that fails, the peer might have started a clean TLS-level
        // session closure.
        if let Err(e) = bytes_read {
            self.clean_closure = e.kind() == io::ErrorKind::ConnectionAborted;
            self.closing = true;
            if self.clean_closure {
                Ok(())
            } else {
                Err(Error::Io(e))
            }
        } else {
            Ok(())
        }
    }

    // Discards the usize that tells us how many bytes were written
    pub fn do_write(&mut self) -> io::Result<()> {
        while self.tls_session.wants_write() {
            self.tls_session.write_tls(&mut self.socket)?;
        }
        Ok(())
    }

    fn reregister(&self, poll: &mut mio::Poll) -> io::Result<()> {
        poll.reregister(
            &self.socket,
            self.token,
            self.ready_interest(),
            mio::PollOpt::level() | mio::PollOpt::oneshot(),
        )
    }

    // Use wants_read/wants_write to register for different mio-level
    // IO readiness events.
    pub fn ready_interest(&self) -> mio::Ready {
        let rd = self.tls_session.wants_read();
        let wr = self.tls_session.wants_write();

        if rd && wr {
            mio::Ready::readable() | mio::Ready::writable()
        } else if wr {
            mio::Ready::writable()
        } else {
            mio::Ready::readable()
        }
    }

    pub fn bytes(&mut self) -> &mut Vec<u8> {
        &mut self.buf
    }
}

impl Drop for TlsClient {
    fn drop(&mut self) {
        use std::io::Write;
        if !self.closing {
            self.tls_session.send_close_notify();
            let _ = self.flush();
        }
    }
}
