use weebsocket::{Client, Message};

fn main() -> std::io::Result<()> {
    let mut client = Client::connect_insecure("127.0.0.1:2794").unwrap();

    // Read the hello websocket message
    println!("{:?}", client.recv_message());

    // Ping/Pong
    client.send_message(&Message::Ping(vec![1, 2, 3])).unwrap();
    println!("{:?}", client.recv_message());

    // Text echo
    client.send_message(&Message::Text(String::from("test")))?;
    println!("{:?}", client.recv_message()?);

    // Shutdown
    client.send_message(&Message::Close(None))?;
    println!("{:?}", client.recv_message()?);

    Ok(())
}
