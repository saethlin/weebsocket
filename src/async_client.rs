use crate::Message;
use std::io::Write;

const SEND_CHANNEL: mio::Token = mio::Token(0);
const STREAM: mio::Token = mio::Token(1);

/// A handle to an asynchronous client that can send messages to the server
#[derive(Clone)]
pub struct Sender {
    inner: std::sync::mpsc::SyncSender<Message>,
    readiness: mio::SetReadiness,
}

impl Sender {
    /// Send a message on the corresponding connection. Never blocks.
    pub fn send(&mut self, m: Message) {
        self.inner.send(m).unwrap();
        self.readiness
            .set_readiness(mio::Ready::readable())
            .unwrap();
    }
}

/// A handle to an asynchronous client that can recieve messages sent by the server
pub struct Receiver {
    inner: std::sync::mpsc::Receiver<Message>,
}

impl Receiver {
    /// Recieve a message on the corresponding connection. Blocks if needed.
    /// Though this blocks the current thread, it does not interfere with the sending of other
    /// messages.
    pub fn recv(&mut self) -> Message {
        self.inner.recv().unwrap()
    }
}

/// Create a websocket connection that runs on a background thread
pub fn connect(uri: &str) -> std::io::Result<(Sender, Receiver)> {
    use std::net::ToSocketAddrs;
    let uri: http::Uri = http::HttpTryFrom::try_from(uri).unwrap();
    let host = uri.host().unwrap();
    let port = uri.port_part().map(|p| p.as_u16()).unwrap_or(443);

    let dns_name = webpki::DNSNameRef::try_from_ascii_str(host).unwrap();
    let socket_addr = (host, port).to_socket_addrs().unwrap().next().unwrap();
    let socket = mio::net::TcpStream::connect(&socket_addr)?;

    let mut tls = crate::tls::TlsClient::new(socket, dns_name, STREAM);

    let path = uri.path_and_query().map(|p| p.as_str()).unwrap_or("/");
    let host = uri.host().unwrap();
    write!(
        tls,
        "GET {} HTTP/1.1\r\n\
         Host: {}\r\n\
         Upgrade: websocket\r\n\
         Connection: Upgrade\r\n\
         Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
         Sec-WebSocket-Version: 13\r\n\r\n",
        path, host,
    )?;
    tls.flush().unwrap();

    let mut is_initialized = false;

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
        poll.register(
            &tls.socket,
            STREAM,
            tls.ready_interest(),
            mio::PollOpt::level() | mio::PollOpt::oneshot(),
        )
        .unwrap();

        let mut rng = crate::XorshiroRng::new();

        loop {
            poll.poll(&mut events, None).unwrap();

            for ev in events.iter() {
                if ev.token() == SEND_CHANNEL {
                    // A message was sent on the incoming channel
                    // Dequeue it and write to the tls session
                    while let Ok(message) = input_receiver.try_recv() {
                        crate::write_message(&mut tls, &mut rng, &message).unwrap();
                        tls.do_write().unwrap();
                    }
                } else if ev.token() == STREAM {
                    // Else, we need to handle reads on the stream
                    tls.ready(&mut poll, &ev).unwrap();

                    if !is_initialized {
                        if let Ok(()) = dequeue_ws_init(tls.bytes()) {
                            is_initialized = true;
                        }
                    }
                    while let Ok(message) = crate::parse::dequeue_message_from(tls.bytes()) {
                        output_sender.send(message).unwrap();
                    }
                }
            }
        }
    });

    Ok((
        Sender {
            readiness,
            inner: input_sender,
        },
        Receiver {
            inner: output_receiver,
        },
    ))
}

fn dequeue_ws_init(buf: &mut Vec<u8>) -> Result<(), crate::Error> {
    let mut headers = [httparse::EMPTY_HEADER; 64];
    let mut response = httparse::Response::new(&mut headers);
    if let httparse::Status::Complete(parsed_bytes) = response.parse(buf.as_slice())? {
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

        // Remove the http response
        let unused_bytes = buf[parsed_bytes..].to_vec();
        buf.clear();
        buf.extend_from_slice(&unused_bytes);
        Ok(())
    } else {
        Err(crate::Error::Custom(
            "Didn't get the full initialization response yet".to_string(),
        ))
    }
}
