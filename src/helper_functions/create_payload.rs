use rand::Rng;

pub fn _make_payload() -> Vec<u8>{
    let mut payload: Vec<u8> = Vec::new();

    // This is average first byte in QUIC Initial packet: 11000000
    let first_byte: u8 = 0xC0;
    payload.push(first_byte);

    // Create 4 bytes of version
    let version: u32 = 0x00000001;
    payload.extend_from_slice(&version.to_be_bytes());

    // Next DCID Length - 1 byte
    let dcid_len = 0x8;
    payload.push(dcid_len);

    // DCID(random data):
    let mut dcid = [0u8; 8];
    rand::thread_rng().fill(&mut dcid);
    payload.extend_from_slice(&dcid);

    // SCID Length
    let scid_len = 0x0;
    payload.push(scid_len);
    // We skip SCID

    // Token length
    let token_len = 0x0;
    payload.push(token_len);
    // We skip token



    payload

}