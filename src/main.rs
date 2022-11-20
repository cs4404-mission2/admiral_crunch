use pnet::packet::ip::IpNextHeaderProtocols::Udp;
use pnet::packet::udp::{MutableUdpPacket, UdpPacket};
use pnet::packet::{MutablePacket, Packet};
use pnet::transport::TransportProtocol::Ipv4;
use pnet::transport::{transport_channel, udp_packet_iter, TransportProtocol};
use log;
fn main() {
    // TODO: forward all non-udp traffic without inspection
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
    header: Vec<u8>,
    data: Vec<u8>
}
impl RTP{
    fn new(raw: Vec<u8>) -> RTP{
        //We don't have to care about header content, just preserve it
        let header = &raw[0..12];
        let data = &raw[12..];
        RTP { header: header.to_owned(), data: data.to_owned()}
    }
    fn byteToInt(input: &[u8])->u32{
        let mut out: u32=0;
        for i in input.iter(){
            out = out << 8 + i;
        }
        return out;
    }
}
fn ulaw2lin(frame:u8)->i16{
    let lst:Vec<i16> = vec!(
        -32124,  -31100,  -30076,  -29052,  -28028,  -27004,  -25980,
        -24956,  -23932,  -22908,  -21884,  -20860,  -19836,  -18812,
        -17788,  -16764,  -15996,  -15484,  -14972,  -14460,  -13948,
        -13436,  -12924,  -12412,  -11900,  -11388,  -10876,  -10364,
         -9852,   -9340,   -8828,   -8316,   -7932,   -7676,   -7420,
         -7164,   -6908,   -6652,   -6396,   -6140,   -5884,   -5628,
         -5372,   -5116,   -4860,   -4604,   -4348,   -4092,   -3900,
         -3772,   -3644,   -3516,   -3388,   -3260,   -3132,   -3004,
         -2876,   -2748,   -2620,   -2492,   -2364,   -2236,   -2108,
         -1980,   -1884,   -1820,   -1756,   -1692,   -1628,   -1564,
         -1500,   -1436,   -1372,   -1308,   -1244,   -1180,   -1116,
         -1052,    -988,    -924,    -876,    -844,    -812,    -780,
          -748,    -716,    -684,    -652,    -620,    -588,    -556,
          -524,    -492,    -460,    -428,    -396,    -372,    -356,
          -340,    -324,    -308,    -292,    -276,    -260,    -244,
          -228,    -212,    -196,    -180,    -164,    -148,    -132,
          -120,    -112,    -104,     -96,     -88,     -80,     -72,
           -64,     -56,     -48,     -40,     -32,     -24,     -16,
        -8,       0,   32124,   31100,   30076,   29052,   28028,
         27004,   25980,   24956,   23932,   22908,   21884,   20860,
         19836,   18812,   17788,   16764,   15996,   15484,   14972,
         14460,   13948,   13436,   12924,   12412,   11900,   11388,
         10876,   10364,    9852,    9340,    8828,    8316,    7932,
          7676,    7420,    7164,    6908,    6652,    6396,    6140,
          5884,    5628,    5372,    5116,    4860,    4604,    4348,
          4092,    3900,    3772,    3644,    3516,    3388,    3260,
          3132,    3004,    2876,    2748,    2620,    2492,    2364,
          2236,    2108,    1980,    1884,    1820,    1756,    1692,
          1628,    1564,    1500,    1436,    1372,    1308,    1244,
          1180,    1116,    1052,     988,     924,     876,     844,
           812,     780,     748,     716,     684,     652,     620,
           588,     556,     524,     492,     460,     428,     396,
           372,     356,     340,     324,     308,     292,     276,
           260,     244,     228,     212,     196,     180,     164,
           148,     132,     120,     112,     104,      96,      88,
        80,      72,      64,      56,      48,      40,      32,
        24,      16,       8,       0
    );
    lst.get(usize::from(frame)).unwrap().to_owned()
    
}