use pnet::packet::ip::IpNextHeaderProtocols::Udp;
use pnet::packet::udp::{MutableUdpPacket, UdpPacket};
use pnet::packet::{MutablePacket, Packet};
use pnet::transport::TransportProtocol::Ipv4;
use pnet::transport::{transport_channel, udp_packet_iter, TransportProtocol};
use log;
fn main() {
    let protocol = pnet::transport::TransportChannelType::Layer4(Ipv4(Udp));
    let (mut tx, mut rx) = transport_channel(4096, protocol).unwrap();
    log::info!("Initialized UDP transport channel");

    let mut iter = udp_packet_iter(&mut rx);
    loop {
        match iter.next() {
            Ok((packet, addr)) => {
                // Allocate enough space for a new packet
                let mut vec: Vec<u8> = vec![0; packet.packet().len()];
                let mut new_packet = MutableUdpPacket::new(&mut vec[..]).unwrap();

                // Create a clone of the original packet
                new_packet.clone_from(&packet);

                // Send the OG packet
                match tx.send_to(new_packet, addr) {
                    Ok(n) => assert_eq!(n, packet.packet().len()),
                    Err(e) => log::error!("Couldn't forward packet due to {}",e),
                }
            }
            Err(e) => {
                log::error!("Failed to read packet due to {}",e)
            }
        }
    }
}
