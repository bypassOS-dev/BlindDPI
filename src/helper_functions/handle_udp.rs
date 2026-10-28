    use nfq::Verdict;
    use pnet::packet::{Packet, udp::UdpPacket};
    use hkdf::Hkdf;
    use sha2::{Sha256};
    use aes::Aes128;
    use aes::cipher::{BlockEncrypt, KeyInit};
    use aes::cipher::generic_array::GenericArray;

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

            // Check token: 
            // Token - this is data for check (this check need for server)
            // That is if connect to server is first then token will equal 0
            // If that's not first check then this packet is QUIC Initial (we skip it)
            let Some(&token_len) = payload.get(scid_end) else {
                return Ok(Verdict::Accept);
            };
            if token_len != 0 {
                return Ok(Verdict::Accept);
            }

            let token_end = scid_end + 1;

            // It's first and second byte of encrypted length
            let Some(&a) = payload.get(token_end) else {
                return Ok(Verdict::Accept);
            };

            // Here we check: Is the length written in 2 bytes?
            // If the lenght written in 1, 4 or 8 bytes then we skip this packet (it's bad. I'll fix it)
            // TODO: Add another check
            let mut length: usize;
            let (number_of_bytes, num) = if a < 64 {
                (1, 0)
            }else if a > 63 && a < 128 {
                (2, 64)
            }else if a > 127 && a < 192 {
                (4, 128)
            } else if a > 191 {
                (8,192)
            } else {
                return Ok(Verdict::Accept);    
            };
            if payload.len() < token_end + number_of_bytes {
                return Ok(Verdict::Accept);
            }

            length = a as usize - num;  
            for i in 1..number_of_bytes {
                length = length * 256 + payload[token_end + i] as usize;
            };

            let pn_offset = token_end + number_of_bytes;

            // It's 32 bytes of data. This data we get from DCID and salt. 
            // From this data we will get 3 another keys:
            //
            // 1) Encrypted key (16 bytes). It's real key. Via this key  we 
            // could decipher encrypted data after header
            //
            // 2) IV (Initialization Vector - 12 bytes). It's a number that mixed in
            // to encrypted key. Why? Because it's help to defend from one dangerous 
            // type of attack - attack by repetition
            // 
            // 3) Header security key (16 bytes). Just key for decode some 
            // parts of code.
            let client_secret = client_secret(dcid)?;

            let hk = Hkdf::<Sha256>::from_prk(&client_secret).map_err(|_| "from prk falled")?;

            let mut client_key = [0u8; 16];
            get_from_hk(&hk, "quic key", &mut client_key)?;

            let mut iv = [0u8; 12];
            get_from_hk(&hk, "quic iv", &mut iv)?;

            let mut hs = [0u8; 16];
            get_from_hk(&hk, "quic hp", &mut hs)?;

            if payload.len() < pn_offset + 20{
                return Ok(Verdict::Accept);
            }

            let sample_start = pn_offset + 4;
            let sample_end = sample_start + 16;
            let sample = &payload[sample_start..sample_end];

            let cipher = Aes128::new(GenericArray::from_slice(&hs));
            let mut block = GenericArray::clone_from_slice(&sample);
            cipher.encrypt_block(&mut block);

            let mask: [u8; 5] = block[0..5].try_into()?;
            // TODO: find SNI and think up what to do with it
        }

    Ok(Verdict::Accept)
}

pub fn client_secret(dcid: &[u8]) -> Result<[u8; 32], Box<dyn std::error::Error + Send + Sync>>{
    let hk = Hkdf::<Sha256>::new(Some(&INITIAL_SALT), dcid);

    let mut out = [0u8; 32];

    get_from_hk(&hk, "client in", &mut out)?;

    Ok(out)
}

fn get_from_hk(
    hk: &Hkdf<Sha256>,   
    string: &str, 
    out: &mut [u8]
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let label = format!("tls13 {}", string);

    let mut info = Vec::new();
    info.extend_from_slice(&(out.len() as u16).to_be_bytes());
    info.push(label.len() as u8);
    info.extend_from_slice(label.as_bytes());
    info.push(0x00);

    hk.expand(&info, out).map_err(|_| "hkdf expand failed")?;

    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn rfc9001_client_initial_secret() {
        let dcid = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];
        let secret = client_secret(&dcid).unwrap();
        assert_eq!(
            hex::encode(secret), 
            "c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea"
        );
    }
}
