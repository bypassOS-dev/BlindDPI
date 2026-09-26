use rand::seq::SliceRandom;
use std::net::SocketAddrV4;
use rand::Rng;

use crate::send_packet::send_packet;

pub async fn send_fake_packets(
    pos: usize,     
    _domain: &str, 
    start_seq: u32, 
    data: &[u8], 
    my_ip: SocketAddrV4,
    server_ip: SocketAddrV4,
    ack: u32,    
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut another_packets: Vec<(Vec<u8>, u32)> = vec![];
    
    let trash = rand::thread_rng().gen_range(10..=33);
    let real_seq = start_seq.wrapping_sub(trash as u32);

    let mut junk: Vec<u8> = vec![0u8; trash];
    rand::thread_rng().fill(&mut junk[..]);
    
    let mut packet1_payload = junk.clone();
    packet1_payload.extend_from_slice(&data[..pos]);

    if packet1_payload.len() >= 100 {
        let half = packet1_payload.len() / 2;
        let packet_1_payload = packet1_payload[..half].to_vec();
        let packet_1_seq = real_seq;

        let packet_2_payload = packet1_payload[half..].to_vec();
        let packet_2_seq = real_seq.wrapping_add(half as u32);

        another_packets.push((packet_1_payload, packet_1_seq));
        another_packets.push((packet_2_payload, packet_2_seq));

        let packet2_payload = &data[pos..];
        let packet_2_seq = start_seq.wrapping_add(pos as u32);

        split_payload(packet2_payload, packet_2_seq, &mut another_packets);
    } else {
        let packet2_payload = &data[pos..];
        let packet_2_seq = real_seq.wrapping_add(packet1_payload.len() as u32);

        let packet1_seq = real_seq;
        another_packets.push((packet1_payload, packet1_seq));
        
        split_payload(packet2_payload, packet_2_seq, &mut another_packets);
    }

    another_packets.shuffle(&mut rand::thread_rng());

    for (payload, seq) in another_packets {
        send_packet(my_ip, server_ip, seq, ack, 64, &payload).await?;
    }

    Ok(())
}


fn split_payload(payload: &[u8], base_seq: u32, out: &mut Vec<(Vec<u8>, u32)>) {
    let len = payload.len();
    if len == 0 {
        return;
    }

    if len < 100 {
        out.push((payload.to_vec(), base_seq));
        return;
    }

    let (min_s, max_s) = if len <= 400 {
        let will_split = rand::thread_rng().gen_range(2..=4);
        let avg = len / will_split;
        (avg.saturating_sub(10).max(1), avg + 10)
    } else {
        let will_split = rand::thread_rng().gen_range(5..=9);
        let avg = len / will_split;
        (avg.saturating_sub(20).max(1), avg + 20)
    };

    let mut sum = 0;
    while sum < len {
        let split = rand::thread_rng().gen_range(min_s..=max_s);
        let end = (sum + split).min(len);
        out.push((payload[sum..end].to_vec(), base_seq + sum as u32));
        sum = end; 
    }
}