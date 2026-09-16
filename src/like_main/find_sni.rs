pub fn find_sni(buf: &[u8]) -> Option<(usize, String)>{
    let mut pos = 0usize;  // Create variable pos -> start index of byte whit a value 0 
    pos += 5;                    // 5 bytes --> TLS Record Header (Type, Version, Lenght)
    pos += 4;                   // 4 bytes --> Handshake header (handshake type, Handshake's lenght)
    pos += 2;                  // 2 bytes --> Client Version
    pos += 32;                //32 bytes --> random number
                             // In total: 43 bytes
    let session_id_len = *buf.get(pos)? as usize;  // Look at the 43rd bytes of the packet
    pos += 1 + session_id_len;                                 // Move the pointer to the 1 and "session_id_len" bytes

    let cipher_suites_len = u16::from_be_bytes([*buf.get(pos)?, *buf.get(pos + 1)?]) as usize;   // Later in packet 2 bytes of cipher!
    pos += 2 + cipher_suites_len;                                                                                   // Move pointer to the 2 bytes and "cipher_suites_len"
                                                                                                                   
    let compression_len = *buf.get(pos)? as usize;     //Here is lenght compression methods                                         
    pos += 1 + compression_len;                                    // Move pointer to the 1 bytes and "compression_len"                                                                    

    let _extensions_total_len = u16::from_be_bytes([*buf.get(pos)?, *buf.get(pos + 1)?]) as usize;   // Inside these 2 bytes total lenght extension
    pos += 2;                                                                                                           // Move pointer to the 1 bytes and from this posicion
                                                                                                                       // We begin loop!
    loop {
        let ext_type = u16::from_be_bytes([*buf.get(pos)?, *buf.get(pos + 1)?]) as usize;     // Get ID this extension...
        let ext_len = u16::from_be_bytes([*buf.get(pos + 2)?, *buf.get(pos + 3)?]) as usize; // Read lenght this extension
        let ext_data_start = pos + 4;                                                                    // Calculate index of useful data

        if ext_type == 0x0000 {                              // 0x0000 - SNI. So if ext_type == 0x0000...
            let name_len_pos = ext_data_start + 3;   // Skip 3 of useless bytes
            let name_len = u16::from_be_bytes([      
                *buf.get(name_len_pos)?,
                *buf.get(name_len_pos + 1)?
            ]) as usize;                                //Get lenght of server-name
            
            let name_start = name_len_pos + 2;        // Get first char of domain
            let name_bytes = buf.get(name_start..name_start + name_len)?;
            let domain = String::from_utf8(name_bytes.to_vec()).ok()?;
            let split_pos = name_start + name_len / 2;
            return Some((split_pos, domain)); // Split domain
        }

        if ext_len == 0 && ext_type == 0 {     //if it useless packet then just leave loop
            break;
        }

        pos = ext_data_start + ext_len;   // Go to next packet
    }
    None
}