use crate::Message;
use rand_core::RngCore;
use std::io::{Read, Write};

const SEND_CHANNEL: mio::Token = mio::Token(0);
const STREAM: mio::Token = mio::Token(1);

pub struct Client {
    sender: std::sync::mpsc::SyncSender<Message>,
    receiver: std::sync::mpsc::Receiver<Message>,
    readiness: mio::SetReadiness,
}

pub enum Stream {
    Tcp(mio::net::TcpStream),
    #[cfg(feature = "tls")]
    Tls(rustls::StreamOwned<rustls::ClientSession, mio::net::TcpStream>),
}

impl Stream {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        match self {
            Stream::Tcp(s) => s.write(bytes),
            #[cfg(feature = "tls")]
            Stream::Tls(s) => s.write(bytes),
        }
    }

    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Stream::Tcp(s) => s.read(bytes),
            #[cfg(feature = "tls")]
            Stream::Tls(s) => s.read(bytes),
        }
    }
}

impl Client {
    fn new() -> (
        std::sync::mpsc::SyncSender<Message>,
        std::sync::mpsc::Receiver<Message>,
    ) {
        let (registration, readiness) = mio::Registration::new2();
        let (input_sender, input_receiver) = std::sync::mpsc::sync_channel(100);
        let (output_sender, output_receiver) = std::sync::mpsc::sync_channel(100);

        std::thread::spawn(move || {
            let mut poll = mio::Poll::new().unwrap();
            let mut events = mio::Events::with_capacity(4);
            poll.register(
                &registration,
                SEND_CHANNEL,
                mio::Ready::readable(),
                mio::PollOpt::edge(),
            )
            .unwrap();

            loop {
                poll.poll(&mut events, None).unwrap();

                for ev in events.iter() {
                    if ev.token() == SEND_CHANNEL {
                        // A new session has been attached to the poll loop
                        let message = input_receiver.recv().unwrap();
                    } else {
                        // Else, we need to handle reads on the stream
                        stream.ready(&mut poll, &ev).unwrap();

                        // TODO: Check if we're now done reading a message, and handle that
                    }
                }
            }
        });

        (input_sender, output_receiver)
    }

    #[cfg(feature = "tls")]
    pub fn connect_secure(uri: &str) -> std::io::Result<Self> {
        let uri: http::Uri = http::HttpTryFrom::try_from(uri).unwrap();
        let host = uri.host().unwrap();
        let port = uri.port_part().map(|p| p.as_u16()).unwrap_or(443);

        let mut config = rustls::ClientConfig::new();
        config
            .root_store
            .add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);
        let config = std::sync::Arc::new(config);

        let dns_name = webpki::DNSNameRef::try_from_ascii_str(host).unwrap();
        let session = rustls::ClientSession::new(&config, dns_name);
        let socket = std::net::TcpStream::connect((host, port))?;

        let mut stream = rustls::StreamOwned::new(session, socket);

        Self::init_connection(&mut stream, &uri)?;

        Ok(Client {
            rng: rand_os::OsRng::new().unwrap(),
            buf: Vec::new(),
            stream: Stream::Tls(stream),
        })
    }

    pub fn connect_insecure(uri: &str) -> std::io::Result<Self> {
        let uri: http::Uri = http::HttpTryFrom::try_from(uri).unwrap();
        let host = uri.host().unwrap();
        let port = uri.port_part().map(|p| p.as_u16()).unwrap_or(80);

        let mut stream = std::net::TcpStream::connect((host, port))?;

        Self::init_connection(&mut stream, &uri)?;

        Ok(Client {
            rng: rand_os::OsRng::new().unwrap(),
            buf: Vec::new(),
            stream: Stream::Tcp(stream),
        })
    }

    fn init_connection<S>(stream: &mut S, uri: &http::Uri) -> std::io::Result<()>
    where
        S: std::io::Write + std::io::Read,
    {
        let path = uri.path_and_query().map(|p| p.as_str()).unwrap_or("/");
        let host = uri.host().unwrap();
        write!(
            stream,
            "GET {} HTTP/1.1\r\n\
             Host: {}\r\n\
             Upgrade: websocket\r\n\
             Connection: Upgrade\r\n\
             Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
             Sec-WebSocket-Version: 13\r\n\r\n",
            path, host,
        )?;

        let mut buf = [0; 2048];
        let len = stream.read(&mut buf)?;

        let mut headers = [httparse::EMPTY_HEADER; 64];
        let mut response = httparse::Response::new(&mut headers);
        response.parse(&buf[..len]).unwrap();

        assert!(response.version.is_some());
        assert_eq!(response.code, Some(101));
        assert_eq!(response.reason, Some("Switching Protocols"));

        // Find the Sec-Websocket-Accept header and validate
        assert_eq!(
            headers[..]
                .iter()
                .find(|h| h.name.to_lowercase() == "sec-websocket-accept")
                .map(|h| h.value),
            Some(&b"s3pPLMBiTxaQ9kYGzzhZRbK+xOo="[..])
        );

        Ok(())
    }

    // only fin frames
    pub fn send_message(&mut self, message: &Message) -> std::io::Result<()> {
        let (opcode, len) = match message {
            Message::Text(b) => (1, b.len()),
            Message::Binary(b) => (2, b.len()),
            Message::Close(None) => (8, 0),
            Message::Close(Some((_, b))) => (8, b.len() + 2),
            Message::Ping(b) => (9, b.len()),
            Message::Pong(b) => (10, b.len()),
        };

        // write fin, rsv, and opcode.
        // fin always 1, rsv always 0
        self.write(&[128 + opcode])?;

        if len > u16::max_value() as usize {
            assert!(len <= i64::max_value() as usize);
            self.write(&[128 + 127])?;
            self.write(&(len as u64).to_be_bytes())?;
        } else if len > 125 {
            self.write(&[128 + 126])?;
            self.write(&(len as u16).to_be_bytes())?;
        } else {
            self.write(&[128 + len as u8])?;
        }

        // TODO: Generate and write a mask
        let mut mask = [0; 4];
        self.rng.fill_bytes(&mut mask);
        self.write(&mask)?;

        let mut data = match message {
            Message::Text(b) => b.as_bytes().to_vec(),
            Message::Binary(b) => b.to_vec(),
            Message::Close(None) => Vec::new(), // Number of bytes written
            Message::Close(Some((reason, b))) => {
                let mut v = Vec::with_capacity(2 + b.len());
                v.extend_from_slice(&reason.to_be_bytes());
                v.extend_from_slice(b.as_bytes());
                v
            }
            Message::Ping(b) => b.to_vec(),
            Message::Pong(b) => b.to_vec(),
        };

        // Apply the mask
        for i in 0..data.len() {
            data[i] ^= mask[i % 4];
        }

        self.write(&data)?;

        Ok(())
    }

    // This is really more like a read_frame
    pub fn recv_message(&mut self) -> std::io::Result<Message> {
        let mut bytes = [0; 2];
        self.read(&mut bytes)?;

        let fin = (bytes[0] & 0b10000000) > 0;
        assert!(
            fin,
            "Got a multi-frame message, but those aren't supported yet"
        );
        //let rsv = bytes[0] & 0b01110000;
        let opcode = bytes[0] & 0b00001111;
        let mask = bytes[1] & 0b10000000 > 0;
        let mut payload_length = (bytes[1] & 0b01111111) as u64;

        if payload_length == 126 {
            let mut len_bytes = [0; 2];
            self.read(&mut len_bytes)?;
            payload_length = u16::from_be_bytes(len_bytes) as u64;
        } else if payload_length == 127 {
            let mut len_bytes = [0; 8];
            self.read(&mut len_bytes)?;
            payload_length = u64::from_be_bytes(len_bytes);
        }

        let masking_key = if mask {
            let mut key = [0; 4];
            self.read(&mut key)?;
            Some(key)
        } else {
            None
        };

        let mut data = vec![0; payload_length as usize];
        if payload_length > 0 {
            let bytes_read = self.read(&mut data)?;
            assert_eq!(bytes_read, data.len());
        }

        if let Some(key) = masking_key {
            for i in 0..data.len() {
                data[i] ^= key[i % 4];
            }
        }

        Ok(match opcode {
            1 => Message::Text(String::from_utf8(data).unwrap()),
            2 => Message::Binary(data),
            8 => {
                if data.is_empty() {
                    Message::Close(None)
                } else {
                    let code = u16::from_be_bytes([data[0], data[1]]);
                    Message::Close(Some((code, String::from_utf8(data[2..].to_vec()).unwrap())))
                }
            }
            9 => Message::Ping(data),
            10 => Message::Pong(data),
            _ => panic!("Unrecognized opcode"),
        })
    }
}
