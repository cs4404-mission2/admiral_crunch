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
                


            }
            Err(e) => {
                log::error!("Failed to read packet due to {}",e)
            }
        }
    }
}

struct RTP {
    vpec: u8,
    mp: u8,
    seq: u16,
    timestamp:u32,
    ssrc: u32,
    csrcList: Vec<u8>,
    data: Vec<u8>
}
impl RTP{
    fn new(raw: Vec<u8>) -> RTP{
        //version, padding, extension, CRSC count all of which don't matter to us
        let vpec = &raw[0];
        //marker and payload type
        let mp = &raw[1];
        //sequence number
        let seq = &raw[2..4];
        //timestamp
        let timest = &raw[4..8];
        // sync source identifiers
        let ssrc = &raw[8..12];
        //data
        let data = &raw[12+4*cc..];
        RTP { vpec: vpec.to_owned(), mp: mp.to_owned(), seq: RTP::byteToInt(seq), 
            timestamp: (), ssrc: (), csrcList: (), data: () }
    }
    fn byteToInt(input: &[u8])->u32{
        let mut out: u32=0;
        for i in input.iter(){
            out = out << 8 + i;
        }
        return out;
    }
}