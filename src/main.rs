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
                // -----------Forward Packet--------------

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

                // ----------Tomfoolery----------

                let content = packet.payload().to_owned();
                //version, padding, and extension, all of which don't matter to us
                let vpe = &content[0..3];
                // CRSC Counter, should be 0
                let cc = &content[4..7];
                //marker and payload type
                let mp = &content[8..15];
                //sequence number
                let seq = &content[16..31];
                //timestamp
                let timest = &content[32..63];
                // sync source identifiers
                let ssrc = &content[64..95];
                //data
                let data = &content[96+32*cc..];


            }
            Err(e) => {
                log::error!("Failed to read packet due to {}",e)
            }
        }
    }
}
