use std::io::{Read, Write};

#[derive(Debug)]
pub enum Message {
    Ping(Vec<u8>),
    Pong(Vec<u8>),
    Text(String),
    Binary(Vec<u8>),
    Close,
}

pub enum Client {
    Tcp(std::net::TcpStream),
    #[cfg(feature = "tls")]
    Tls(rustls::StreamOwned<rustls::ClientSession, std::net::TcpStream>),
}

impl Client {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        match self {
            Client::Tcp(s) => s.write(bytes),
            #[cfg(feature = "tls")]
            Client::Tls(s) => s.write(bytes),
        }
    }

    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Client::Tcp(s) => s.read(bytes),
            #[cfg(feature = "tls")]
            Client::Tls(s) => s.read(bytes),
        }
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

        Ok(Client::Tls(stream))
    }

    pub fn connect_insecure(uri: &str) -> std::io::Result<Self> {
        let uri: http::Uri = http::HttpTryFrom::try_from(uri).unwrap();
        let host = uri.host().unwrap();
        let port = uri.port_part().map(|p| p.as_u16()).unwrap_or(80);

        let mut stream = std::net::TcpStream::connect((host, port))?;

        Self::init_connection(&mut stream, &uri)?;

        Ok(Client::Tcp(stream))
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
        let (opcode, data) = match message {
            Message::Text(s) => (1, s.as_bytes()),
            Message::Binary(b) => (2, b.as_slice()),
            Message::Close => (8, &[][..]),
            Message::Ping(b) => (9, b.as_slice()),
            Message::Pong(b) => (10, b.as_slice()),
        };

        // write fin, rsv, and opcode.
        // fin always 1, rsv always 0
        self.write(&[128 + opcode])?;

        if data.len() > u16::max_value() as usize {
            assert!(data.len() <= i64::max_value() as usize);
            self.write(&[128 + 127])?;
            self.write(&(data.len() as u64).to_be_bytes())?;
        } else if data.len() > 125 {
            self.write(&[128 + 126])?;
            self.write(&(data.len() as u16).to_be_bytes())?;
        } else {
            self.write(&[128 + data.len() as u8])?;
        }

        self.write(&[0, 0, 0, 0])?;

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
            8 => Message::Close,
            9 => Message::Ping(data),
            10 => Message::Pong(data),
            _ => panic!("Unrecognized opcode"),
        })
    }
}
