use weebsocket::{Client, Message};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let response = weeqwest::get(&format!(
        "https://slack.com/api/rtm.connect?token={}",
        std::env::var("SLACK_TOKEN").unwrap(),
    ))?;

    let url = std::str::from_utf8(response.bytes())
        .unwrap()
        .split("\"")
        .nth(5)
        .unwrap();
    let url = url.replace("\\/", "/");

    eprintln!("{:?}", url);

    let mut client = Client::connect(&url)?;

    loop {
        let msg = client.recv_message()?;
        println!("{:?}", msg);
        if let Message::Ping(data) = msg {
            client.send_message(&Message::Pong(data))?;
        }
    }
}
