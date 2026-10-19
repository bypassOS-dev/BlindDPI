use nfq::Verdict;
use pnet::packet::{Packet, udp::UdpPacket};
use hkdf::Hkdf;
use sha2::Sha256;

const INITIAL_SALT: [u8; 20] = [
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
    0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a,
];

pub async fn handle_udp (
    udp_packet: UdpPacket<'_>
) -> Result<Verdict, Box<dyn std::error::Error + Send + Sync>>{
    // Get payload for future work
    let payload = udp_packet.payload();

    // If that's isn't https 
    // or if payload of packet less than 1200 
    // (and payload QUIC Initial MUST BE more than 1200)
    // That just skip this packet.
    if udp_packet.get_destination() != 443 || payload.len() < 1200 {
        return Ok(Verdict::Accept);
    }

    let first = payload[0];

    // The most interesting part of check.
    // 0xC0 = 1100 0000
    // And first bit (well 7 for computer) 
    // in QUIC Initial must be equal 1
    // 1 means what it is long header
    // Second bit (and 6 for computer)
    // just should be 1 otherwise packet 
    // will be considered invalid
    let is_long_header = (first & 0xC0) == 0xC0;

    // 0x30 = 0011 0000
    // That is 3 and 4 bit 
    // (for computer 4 and 5)
    // must be equal 0 and 0 so we compare
    // our bit with 00 (0x00 = 0000 0000)
    let is_initial = (first & 0x30) == 0x00; 

    // Just get version 
    let is_v1 = payload[1..5] == [0, 0, 0, 1];

    // If everythink is true ===> That is QUIC Initial packet
    if is_initial && is_long_header && is_v1 {
        // DCID - Destination Connection ID
        let dcid_len = payload[5] as usize;

        let dcid_end = 6 + dcid_len;

        let Some(dcid) = payload.get(6..dcid_end) else {
            return Ok(Verdict::Accept);
        };

        let Some(&scid_len) = payload.get(dcid_end) else {
            return Ok(Verdict::Accept);
        };

        let scid_end = dcid_end + 1 + scid_len as usize;

        let Some(&token_len) = payload.get(scid_end) else {
            return Ok(Verdict::Accept);
        };
        if token_len != 0 {
            return Ok(Verdict::Accept);
        }
        let token_end = scid_end + 1;


        let Some(&a) = payload.get(token_end) else {
            return Ok(Verdict::Accept);
        };
        let Some(&b) = payload.get(token_end + 1) else {
            return Ok(Verdict::Accept);
        };

        if a < 64 || a >= 128 {
            return Ok(Verdict::Accept);
        }

        let length = (a as usize - 64) * 256 + b as usize;

        let encrypted_start = token_end + 2;

        let hk = Hkdf::<Sha256>::new(Some(&INITIAL_SALT), dcid);

        let label = b"tls13 client in";

        let mut info = Vec::new();
        info.extend_from_slice(&[0x00, 0x20]);
        info.push(label.len() as u8);
        info.extend_from_slice(label);
        info.push(0x00);

        let mut client_secret = [0u8; 32];

        hk.expand(&info, &mut client_secret).map_err(|_| "hkdf expand failed")?;
        // TODO: find SNI and think up what to do with it
    }

    Ok(Verdict::Accept)
}
