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
    let mut client_hello: Vec<u8> = Vec::new();
    let mut client_hello_body: Vec<u8> = Vec::new();
    let mut client_hello_extensions: Vec<u8> = Vec::new();



    // client hello extensions
    {
        // server name
        let type1: [u8; 2] = [0x00, 0x00]; // SNI
        client_hello_extensions.extend_from_slice(&type1);

        let sni_len = sni.len();

        let length: [u8; 2] = (2 + 1 + 2 + sni_len as u16).to_be_bytes();    // 2 - list_len, 1 - name_type, 2 - name_len, name
        client_hello_extensions.extend_from_slice(&length);

        let list_len: [u8; 2] = (1 + 2 + sni_len  as u16).to_be_bytes();
        client_hello_extensions.extend_from_slice(&list_len);

        let name_type = 0x00;
        client_hello_extensions.push(name_type);

        client_hello_extensions.extend_from_slice(&(sni_len as u16).to_be_bytes());

        client_hello_extensions.extend_from_slice(&sni.as_bytes());



        // supported_groups
        let type1: [u8; 2] = [0x00, 0x0a];
        client_hello_extensions.extend_from_slice(&type1);

        let length: [u8; 2] = [0x00, 0x04];
        client_hello_extensions.extend_from_slice(&length);

        let list_len: [u8; 2] = [0x00, 0x02];
        client_hello_extensions.extend_from_slice(&list_len);

        let group: [u8; 2] = [0x00, 0x1d];    // Most popular group (Curve25519. IANA = 29)
        client_hello_extensions.extend_from_slice(&group);



        // signature_algorithms - list of signature algorithms that understand client
        let type1: [u8; 2] = [0x00, 0x0d];
        client_hello_extensions.extend_from_slice(&type1);

        let length: [u8; 2] = [0x00, 0x06];
        client_hello_extensions.extend_from_slice(&length);

        let list_len: [u8; 2] = [0x00, 0x04];
        client_hello_extensions.extend_from_slice(&list_len);

        let rsa_pss_rsae_sha256: [u8; 2] = [0x08, 0x04];  // idk what is this but this is standart for RSA certificates
        client_hello_extensions.extend_from_slice(&rsa_pss_rsae_sha256);

        let ecdsa_secp256r1_sha256: [u8; 2] = [0x04, 0x03];   // For ECDSA certificates
        client_hello_extensions.extend_from_slice(&ecdsa_secp256r1_sha256);



        // Application-Layer Protocol Negotiation
        let type1: [u8; 2] = [0x00, 0x10];
        client_hello_extensions.extend_from_slice(&type1);

        let length: [u8; 2] = [0x00, 0x05];
        client_hello_extensions.extend_from_slice(&length);

        let list_len: [u8; 2] = [0x00, 0x03];
        client_hello_extensions.extend_from_slice(&list_len);

        let entry_len: u8 = 0x02;
        client_hello_extensions.push(entry_len);

        let protocol: [u8; 2] = [0x68, 0x33];
        client_hello_extensions.extend_from_slice(&protocol);
        


        // supported_versions
        let type1: [u8; 2] = [0x00, 0x2b];
        client_hello_extensions.extend_from_slice(&type1);

        let length: [u8; 2] = [0x00, 0x03];  // 1 (list_len) + 2 (version) = 3
        client_hello_extensions.extend_from_slice(&length);

        let list_len: u8 = 0x02;
        client_hello_extensions.push(list_len);

        let tls_1_3: [u8; 2] = [0x03, 0x04];  // TLS 1.3
        client_hello_extensions.extend_from_slice(&tls_1_3);



        // key_share
        let type1: [u8; 2] = [0x00, 0x33];
        client_hello_extensions.extend_from_slice(&type1);

        let length: [u8; 2] = [0x00, 0x26];  // 2 (shares_len) + 2 (group) + 2 (key_len) + 32 (key) = 38
        client_hello_extensions.extend_from_slice(&length);

        let client_shares_len: [u8; 2] = [0x00, 0x24];  // 2 (group) + 2 (key_len) + 32 (key) = 36
        client_hello_extensions.extend_from_slice(&client_shares_len);

        let group: [u8; 2] = [0x00, 0x1d];  // x25519
        client_hello_extensions.extend_from_slice(&group);

        let key_len: [u8; 2] = [0x00, 0x20];  // 32 байта
        client_hello_extensions.extend_from_slice(&key_len);

        let mut key: [u8; 32] = [0u8; 32];
        rand::thread_rng().fill(&mut key);
        client_hello_extensions.extend_from_slice(&key);
    } 

    // client hello body
    {
        let legacy_ver: [u8; 2] = [0x03, 0x03];
        client_hello_body.extend_from_slice(&legacy_ver);

        let mut random_b = [0u8; 32];
        rand::thread_rng().fill(&mut random_b);
        client_hello_body.extend_from_slice(&random_b);

        let session_id_len: u8 = 0x00;
        client_hello_body.push(session_id_len);

        let cipher_suites_len: [u8; 2] = [0x00, 0x06];
        client_hello_body.extend_from_slice(&cipher_suites_len);

        let cipher_suites: [u8; 6] = [0x13, 0x01, 0x13, 0x02, 0x13, 0x03];
        client_hello_body.extend_from_slice(&cipher_suites);

        let compression_len = 0x01;
        client_hello_body.push(compression_len);

        let compression = 0x00;
        client_hello_body.push(compression);

        // Leength of extensions
        client_hello_body.extend_from_slice(&(client_hello_extensions.len() as u16).to_be_bytes());

        client_hello_body.extend_from_slice(&client_hello_extensions);
    }

    // Handshake header:
    {
        let type_of_payload: u8 = 0x01;
        client_hello.push(type_of_payload);
    }

    client_hello
}