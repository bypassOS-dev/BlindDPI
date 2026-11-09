use rand::Rng;

pub fn _make_payload(content:&[String]) -> Vec<u8>{
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


    let sni = random_sni(content);

    let client_hello = build_clien_hello(sni);

    payload

}


fn random_sni(content: &[String]) -> &str{
    let count_of_lines = content.len();
    if count_of_lines > 1 {
        let random_domain: usize = rand::thread_rng().gen_range(0..count_of_lines);
        let random_domain = &content[random_domain];
        return random_domain;
    }
    return "vk.ru";
}



fn build_clien_hello(sni: &str) -> Vec<u8>{
    let mut  client_hello = Vec::new();

    // Handshake header:
    {
        let type_of_payload: u8 = 0x01;
        client_hello.push(type_of_payload);

        // let length_of_body: u8 = 
    }

    // Client hello body 
    {
        let legacy_ver: [u8; 2] = [0x03, 0x03];
        client_hello.extend_from_slice(&legacy_ver);


        let mut random_b = [0u8; 32];
        rand::thread_rng().fill(&mut random_b);
        client_hello.extend_from_slice(&random_b);

        let session_id_len: u8 = 0x00;
        client_hello.push(session_id_len);

        let cipher_suites_len: [u8; 2] = [0x00, 0x06];
        client_hello.extend_from_slice(&cipher_suites_len);

        let cipher_suites: [u8; 6] = [0x13, 0x01, 0x13, 0x02, 0x13, 0x03];
        client_hello.extend_from_slice(&cipher_suites);

        let compression_len = 0x01;
        client_hello.push(compression_len);

        let compression = 0x01;
        client_hello.push(compression);
    }

    client_hello
}