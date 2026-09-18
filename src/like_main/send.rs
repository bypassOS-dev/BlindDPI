async fn send_fake_packet(
    pos: usize, 
    domain: &str, 
    start_seq: u32, 
    data: &[u8], 
    my_ip: SocketAddrV4,
    server_ip: SocketAddrV4,
    ack: u32,    
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    println!("Pos: {pos}, domain: {domain}");

    let trash = rand::thread_rng().gen_range(10..=33);
    let real_seq = start_seq;

    let junk: Vec<u8> = vec![0x41; trash];
    let mut packet1_payload = junk.clone();
    packet1_payload.extend_from_slice(&data[..pos]);

    let packet1_seq = real_seq.wrapping_sub(trash as u32);
    let packet2_payload = &data[pos..];
    let packet2_seq = real_seq + pos as u32;

    send_packet(my_ip, server_ip, packet1_seq, ack, 64, &packet1_payload).await?;
    send_packet(my_ip, server_ip, packet2_seq, ack, 64, packet2_payload).await?;

    Ok(())
}