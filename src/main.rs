use std::env;

use pnet::datalink::{self, NetworkInterface};
use pnet::datalink::Channel::Ethernet;
use pnet::packet::ethernet::EthernetPacket;
use pnet::packet::Packet;

use etherparse::{InternetSlice, TransportSlice, SlicedPacket};
use chrono::{DateTime, Local};

fn main() {
    let network_interface = env::args().nth(1).expect("Error: Cannot find argument!!");
    let interface = datalink::interfaces().into_iter().filter(|interface: &NetworkInterface| interface.name == network_interface).next().expect("Error: Cannot find interface!!");
  
    let (_, mut rx) = if let Ok(Ethernet(tx, rx)) = datalink::channel(&interface, Default::default()) { (tx, rx) } else { panic!("Error: canot create channel!!") };
  
    loop {
      match rx.next() {
          Ok(packet) => {
              let packet = EthernetPacket::new(packet).expect("Error: Detect unreadable packet!!");
              packet_parser(packet.payload());
            },
            Err(_) => { panic!("Error: Problem occurred while reading packet!!") }
        }
    }
}

fn packet_parser(payload: &[u8]) {
    match SlicedPacket::from_ethernet(payload) {
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
                                                80 | 8080 => http_parser(Local::now(), sliced_packet_data.payload),
                                                _ => (),
                                            }
                                        },
                                        _ => (),
                                    }
                                },
                                _ => (),
                            }
                        },
                        InternetSlice::Ipv6(_, _) => {
                            match sliced_packet_data.transport {
                                Some(tcp_packet_data) => {
                                    match tcp_packet_data {
                                        TransportSlice::Tcp(port_data) => {
                                            match port_data.destination_port() {
                                                80 | 8080 => http_parser(Local::now(), sliced_packet_data.payload),
                                                _ => (),
                                            }
                                        },
                                        _ => (),
                                    }
                                },
                                _ => (),
                            }
                        },
                    }
                },
                _ => (),
            }
        },
        _ => (),
    }
}

fn http_parser(timestamp: DateTime<Local>, payload: &[u8]) {
    println!("{}: HTTP REQUEST DETECTION!!", timestamp);
    println!("{:02x?}", payload);
}