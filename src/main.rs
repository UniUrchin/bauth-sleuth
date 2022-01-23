use std::env;

use anyhow::Result as AResult;
use chrono::{DateTime, Local};
use combine::Parser;
use combine::parser::char::string;
use combine::parser::range::{take, take_until_range};
use etherparse::{InternetSlice, TransportSlice, SlicedPacket};
use pnet::datalink::{self, NetworkInterface};
use pnet::datalink::Channel::Ethernet;

fn main() {
    let network_interface = env::args().nth(1).expect("Error: Cannot find argument!!");
    let interface = datalink::interfaces().into_iter().filter(|interface: &NetworkInterface| interface.name == network_interface).next().expect("Error: Cannot find interface!!");
  
    let (_tx, mut rx) = if let Ok(Ethernet(tx, rx)) = datalink::channel(&interface, Default::default()) { (tx, rx) } else { panic!("Error: canot create channel!!") };
  
    loop {
        match rx.next() {
            Ok(packet) => {
                match SlicedPacket::from_ethernet(packet) {
                    Ok(sliced_packet_data) => {
                        match sliced_packet_data.ip {
                            Some(ip_packet_data) => {
                                match ip_packet_data {
                                    InternetSlice::Ipv4(_, _) => {
                                        match sliced_packet_data.transport {
                                            Some(tcp_packet_data) => {
                                                match tcp_packet_data {
                                                    TransportSlice::Tcp(port_data) => {
                                                        match port_data.destination_port() {
                                                            80 => match http_parser(Local::now(), sliced_packet_data.payload) {
                                                                _ => (),
                                                            },
                                                            _ => (),
                                                        }
                                                    },
                                                    _ => (),
                                                }
                                            },
                                            _ => (),
                                        }
                                    },
                                    _ => ()
                                }
                            },
                            _ => (),
                        }
                    },
                    _ => (),
                }
            },
            Err(_) => { panic!("Error: Problem occurred while reading packet!!") }
        }
    }
}

fn http_parser(timestamp: DateTime<Local>, payload: &[u8]) -> AResult<()> {
    let cleartext = payload.iter().map(|&s| s as char).collect::<String>();
    let ((request_line, _), cleartext) = take_until_range("\r\n").and(take(2)).parse(&*cleartext)?;
    let ((_, uri), _) = string("GET").and(take(1)).and(take_until_range(" ")).parse(request_line)?;

    println!("{:?}", uri);
    return Ok(())
}