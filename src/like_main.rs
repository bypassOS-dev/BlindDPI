use std::{collections::HashMap, net::SocketAddrV4};

use nfq::{Queue, Verdict};
use pnet::packet::{Packet, ipv4::Ipv4Packet, tcp::{TcpPacket}};

mod find_sni;
mod iptables;
mod send_packet;

use send_packet::send_packet;
use iptables::run_iptables;
use find_sni::find_sni;
use rand::Rng;

pub async fn like_main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    println!("Start iptables");
    run_iptables().await;
    println!("Iptables working..?");
    let mut queue = Queue::open()?;
    queue.bind(0)?;
    println!("binding");

    let mut pending: HashMap<u32, Vec<u8>> = HashMap::new();

    loop {
        let mut msg = queue.recv()?;
        let payload = msg.get_payload();
        
        if let Some(ipv4_packet) = Ipv4Packet::new(payload) {
            if let Some(tcp_packet) = TcpPacket::new(ipv4_packet.payload()) {
                println!("We get a packet");
                let sequence = tcp_packet.get_sequence();
                let tcp_payload = tcp_packet.payload();

                let mut matched_start_seq: Option<u32> = None;

                for (&strat_seq, data) in pending.iter() {
                    let expected_seq = strat_seq.wrapping_add(data.len() as u32);
                    if expected_seq == sequence {
                        matched_start_seq = Some(expected_seq);
                        break;
                    }
                }

                if let Some(start_seq) = matched_start_seq {
                    let data = pending.get_mut(&start_seq).unwrap();
                    data.extend_from_slice(tcp_payload);

                    if let Some((pos, domain)) = find_sni(data) {
                        println!("Pos: {pos}, domain: {domain}");

                        let trash = rand::thread_rng().gen_range(10..=33);

                        let real_seq = start_seq;

                        let junk: Vec<u8> = vec![0x41; trash];
                        let mut packet1_payload = junk.clone();
                        packet1_payload.extend_from_slice(&data[..pos]);

                        let packet1_seq = real_seq.wrapping_sub(trash as u32);
                        let packet2_payload = &data[pos..];
                        let packet2_seq = real_seq + pos as u32;

                        let my_ip = SocketAddrV4::new(ipv4_packet.get_source(), tcp_packet.get_source());
                        let server_ip = SocketAddrV4::new(ipv4_packet.get_destination(), tcp_packet.get_destination());
                        let ack = tcp_packet.get_acknowledgement();

                        send_packet(my_ip, server_ip, packet1_seq, ack, 64, &packet1_payload).await?;
                        send_packet(my_ip, server_ip, packet2_seq, ack, 64, packet2_payload).await?;

                        pending.remove(&start_seq);
                    }
                    msg.set_verdict(Verdict::Drop);
                    queue.verdict(msg)?;
                    continue;
                }

                if tcp_payload.len() > 5 && tcp_payload[0] == 0x16 {
                    println!("This looking like TSP handshake!!!");


                    msg.set_verdict(Verdict::Drop);
                    queue.verdict(msg)?;
                    continue;
                }
                msg.set_verdict(Verdict::Accept);
                queue.verdict(msg)?;
            }
        }
    }
}
