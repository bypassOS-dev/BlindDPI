use rand::seq::SliceRandom;
use std::{net::SocketAddrV4, u8};
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
    let packet_1_payload: Vec<u8>;
    let packet_2_payload: Vec<u8>;
    let mut another_packets: Vec<(Vec<u8>, u32)> = vec![];
    //=================
    let trash = rand::thread_rng().gen_range(10..=33);
    let real_seq = start_seq.wrapping_sub(trash as u32);

    let mut junk: Vec<u8> = vec![0u8; trash];
    rand::thread_rng().fill(&mut junk[..]);
    
    let mut packet1_payload = junk.clone();
    packet1_payload.extend_from_slice(&data[..pos]);

    if packet1_payload.len() >= 100 {
        let half = packet1_payload.len() / 2;
        packet_1_payload = packet1_payload[..half].to_vec();
        let packet_1_seq = real_seq;

        packet_2_payload = packet1_payload[half..].to_vec();
        let packet_2_seq = real_seq.wrapping_add(half as u32);

        another_packets.push((packet_1_payload, packet_1_seq));
        another_packets.push((packet_2_payload, packet_2_seq));

        let packet2_payload = &data[pos..];
        let packet_2_seq = start_seq.wrapping_add(pos as u32);

        if packet2_payload.len() < 100 {
            another_packets.push((packet2_payload.to_vec(), packet_2_seq));
        } else if packet2_payload.len() <= 400 {
            let will_split = rand::thread_rng().gen_range(2..5);
            let average = packet2_payload.len() / will_split;
            let mut sum = 0;
            for i in 1..=will_split {
                if i == will_split {
                    another_packets.push((packet2_payload[sum..].to_vec(), packet_2_seq + sum as u32));
                    break;
                }
                let split = rand::thread_rng().gen_range(average - 10..average +  10  );
                another_packets.push((packet2_payload[sum..sum + split].to_vec(), packet_2_seq + sum as u32));
                sum += split;
            }
        } else {
            let will_split = rand::thread_rng().gen_range(5..10);
            let average = packet2_payload.len() / will_split;
            let mut sum = 0;

            for i in 1..=will_split {
                if i == will_split {
                    another_packets.push((packet2_payload[sum..].to_vec(), packet_2_seq + sum as u32));
                    break;
                }
                let split = rand::thread_rng().gen_range(average - 20..average +  20  );
                let end = (sum + split).min(packet2_payload.len());
                another_packets.push((packet2_payload[sum..end].to_vec(), packet_2_seq + sum as u32));
                sum += split;
            }
        }
    } else {
        let packet2_payload = &data[pos..];
        let packet_2_seq = real_seq.wrapping_add(packet1_payload.len() as u32);

        let packet1_seq = real_seq;
        another_packets.push((packet1_payload, packet1_seq));
        if packet2_payload.len() < 100{
            another_packets.push((packet2_payload.to_vec(), packet_2_seq));
        }else if packet2_payload.len() <= 400 {
            let will_split = rand::thread_rng().gen_range(2..5);
            let average = packet2_payload.len() / will_split;
            let mut sum = 0;
            for i in 1..=will_split {
                if i == will_split {
                    another_packets.push((packet2_payload[sum..].to_vec(), packet_2_seq + sum as u32));
                    break;
                }
                let split = rand::thread_rng().gen_range(average - 10..average +  10  );
                another_packets.push((packet2_payload[sum..sum + split].to_vec(), packet_2_seq + sum as u32));
                sum += split;
            }
        } else {
            
            let will_split = rand::thread_rng().gen_range(5..10);
            let average = packet2_payload.len() / will_split;
            let mut sum = 0;

            for i in 1..=will_split {
                if i == will_split {
                    another_packets.push((packet2_payload[sum..].to_vec(), packet_2_seq + sum as u32));
                    break;
                }
                let split = rand::thread_rng().gen_range(average - 20..average +  20  );
                another_packets.push((packet2_payload[sum..sum + split].to_vec(), packet_2_seq + sum as u32));
                sum += split;
            }
        }
    }
    another_packets.shuffle(&mut rand::thread_rng());

    for (payload, seq) in another_packets {
        send_packet(my_ip, server_ip, seq, ack, 64, &payload).await?;
    }

    Ok(())
}