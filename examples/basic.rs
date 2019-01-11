use weebsocket::{Client, Message};

fn main() -> std::io::Result<()> {
    let mut client = Client::connect("127.0.0.1:2794").unwrap();

    // Read the hello websocket message
    println!("{:?}", client.read_message());

    // Ping/Pong
    client.send_message(&Message::Ping(vec![1, 2, 3])).unwrap();
    println!("{:?}", client.read_message());

    // Text echo
    client.send_message(&Message::Text(String::from("test")))?;
    println!("{:?}", client.read_message()?);

    // Shutdown
    client.send_message(&Message::Close)?;
    println!("{:?}", client.read_message()?);

    Ok(())
}
