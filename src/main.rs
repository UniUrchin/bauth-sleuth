use std::env;

use anyhow::Result as AResult;
use base64::decode;
use chrono::{DateTime, Local};
use combine::parser::char::string;
use combine::parser::range::{take, take_until_range};
use combine::Parser;
use etherparse::{InternetSlice, SlicedPacket, TransportSlice};
use pnet::datalink::Channel::Ethernet;
use pnet::datalink::{self, NetworkInterface};

static TITLE: &str = " - BasicAuth Information - ";

fn main() {
  let network_interface = env::args().nth(1).expect("Error: Cannot find argument!!");
  let interface = datalink::interfaces()
    .into_iter()
    .filter(|interface: &NetworkInterface| interface.name == network_interface)
    .next()
    .expect("Error: Cannot find interface!!");

  let (_tx, mut rx) =
    if let Ok(Ethernet(tx, rx)) = datalink::channel(&interface, Default::default()) {
      (tx, rx)
    } else {
      panic!("Error: canot create channel!!")
    };

  loop {
    match rx.next() {
      Ok(packet) => match SlicedPacket::from_ethernet(packet) {
        Ok(sliced_packet_data) => match sliced_packet_data.ip {
          Some(ip_packet_data) => match ip_packet_data {
            InternetSlice::Ipv4(_, _) => match sliced_packet_data.transport {
              Some(tcp_packet_data) => match tcp_packet_data {
                TransportSlice::Tcp(port_data) => match port_data.destination_port() {
                  80 => match http_parser(Local::now(), sliced_packet_data.payload) {
                    _ => continue,
                  },
                  _ => continue,
                },
                _ => continue,
              },
              _ => continue,
            },
            _ => continue,
          },
          _ => continue,
        },
        _ => continue,
      },
      Err(_) => {
        panic!("Error: Problem occurred while reading packet!!")
      }
    }
  }
}

fn http_parser(timestamp: DateTime<Local>, payload: &[u8]) -> AResult<()> {
  let cleartext = payload.iter().map(|&s| s as char).collect::<String>();
  let ((request_line, _), cleartext) = take_until_range("\r\n").and(take(2)).parse(&*cleartext)?;
  let ((_, uri), _) = string("GET")
    .and(take(1))
    .and(take_until_range(" "))
    .parse(request_line)?;
  let (cleartext, _) = take_until_range("\r\n\r\n").parse(cleartext)?;
  let request_header = cleartext.split("\r\n").collect::<Vec<&str>>();

  let mut request_url = String::new();
  let mut encrypted_bauth = String::new();

  for content in request_header {
    let ((header_name, _), value) = take_until_range(":").and(take(2)).parse(content)?;

    match header_name {
      "Host" => {
        request_url = format!("http://{}{}", value, uri);
      }
      "Authorization" => {
        let (_, value) = string("Basic").and(take(1)).parse(value)?;
        encrypted_bauth = value.to_string();
      }
      _ => continue,
    }
  }

  let decrypted_bauth = decode(&encrypted_bauth)?
    .iter()
    .map(|&s| s as char)
    .collect::<String>();
  let ((username, _), password) = take_until_range(":")
    .and(take(1))
    .parse(&*decrypted_bauth)?;

  println!(
    "{}\n{}\n{}",
    "=".repeat(TITLE.len()),
    TITLE,
    "=".repeat(TITLE.len())
  );
  println!("Timestamp: {}", timestamp.format("%Y/%m/%d %H:%M:%S"));
  println!("Request_URL: {}", request_url);
  println!("Username: {}", username);
  println!("password: {}\n", password);

  return Ok(());
}
