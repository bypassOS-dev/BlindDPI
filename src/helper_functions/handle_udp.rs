use nfq::Verdict;
use pnet::packet::{Packet, udp::UdpPacket};

pub async fn handle_udp (
    udp_packet: UdpPacket<'_>
) -> Result<Verdict, Box<dyn std::error::Error + Send + Sync>>{
    let payload = udp_packet.payload();

    if udp_packet.get_destination() != 443 || payload.len() < 1200 {
        return Ok(Verdict::Accept);
    }

    let first = payload[0];

    let is_long_header = (first & 0xC0) == 0xC0;

    let is_initial = (first & 0x30) == 0x00; 

    let is_v1 = payload[1..5] == [0, 0, 0, 1];

    if is_initial && is_long_header && is_v1 {
        let dcid_len = payload[5] as usize;

        let dcid_end = 6 + dcid_len;

        let Some(dcid) = payload.get(6..dcid_end) else {
            return Ok(Verdict::Accept);
        };

        let Some(&scid_len) = payload.get(dcid_end) else {
            return Ok(Verdict::Accept);
        };

        let scid_end = dcid_end + 1 + scid_len as usize;

        eprintln!("Initial: DCID={:02x?}, SCID's lenght {}, SCID ended: {}",
          dcid, scid_len, scid_end);
        // TODO
    }

    Ok(Verdict::Accept)
}