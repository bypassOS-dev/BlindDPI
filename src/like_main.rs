use std::net::SocketAddrV4;

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
    let mut pending: Option<(u32, Vec<u8>)> = None;
    loop {
        let mut msg = queue.recv()?;
        let payload = msg.get_payload();
        
        if let Some(ipv4_packet) = Ipv4Packet::new(payload) {
            if let Some(tcp_packet) = TcpPacket::new(ipv4_packet.payload()) {
                println!("We get a packet");
                let sequence = tcp_packet.get_sequence();
                let tcp_payload = tcp_packet.payload();

                if let Some((pending_seq, pending_data)) = &mut pending {
                    let expected_seq = pending_seq.wrapping_add(pending_data.len() as u32);
                    if expected_seq == sequence {
                        pending_data.extend_from_slice(tcp_payload);
                        if let Some((split_pos, domain)) = find_sni(pending_data) {
                            println!("{domain}");
                            let trash = rand::thread_rng().gen_range(10..=30);

                            let real_seq = *pending_seq;

                            let junk: Vec<u8> = vec![0x41; trash];
                            let mut packet1_payload = junk.clone();

                            packet1_payload.extend_from_slice(&pending_data[..split_pos]);

                            let packet1_sequence = real_seq.wrapping_sub(trash as u32);

                            let packet2_payload = &pending_data[split_pos..];
                            let packet2_sequence = real_seq + split_pos as u32;

                            let my_ip = SocketAddrV4::new(
                                ipv4_packet.get_source(),
                                tcp_packet.get_source()
                            );
                            let dst_ip = SocketAddrV4::new(
                                ipv4_packet.get_destination(), 
                                tcp_packet.get_destination()
                            );

                            let ack = tcp_packet.get_acknowledgement();

                            send_packet(my_ip, dst_ip, packet1_sequence, ack, 64, &packet1_payload).await?;
                            send_packet(my_ip, dst_ip, packet2_sequence, ack, 64, &packet2_payload).await?;

                            pending = None;
                        }
                    }
                }

                if tcp_payload.len() > 5 && tcp_payload[0] == 0x16 {
                    pending = Some((sequence, tcp_payload.to_vec()));

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