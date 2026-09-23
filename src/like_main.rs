use std::{collections::HashMap, fs, net::SocketAddrV4, u8};
use nfq::{Queue, Verdict};
use tokio::io as tokio_io; 
use tokio::io::AsyncWriteExt;
use std::time::{Instant, Duration};
use pnet::packet::{Packet, ipv4::Ipv4Packet, tcp::{TcpPacket}};
//==============================================================
mod find_sni;
mod iptables;
mod send_packet;
mod get_domain;
//===========================================================
use send_packet::send_packet;
use iptables::run_iptables;
use find_sni::find_sni;
use rand::Rng;
use get_domain::is_domain_in_white_list;
use get_domain::is_domain_rus;
//===================================================

pub async fn like_main(split_tunneling_bool: bool) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    run_iptables().await;

    let mut queue = Queue::open()?;
    queue.bind(0)?;

    let mut pending: HashMap<u32, (Instant, Vec<u8>)> = HashMap::new();
    let mut last_clean = Instant::now();

    tokio::spawn(async {
        let time = Instant::now();
        let mut stdout = tokio_io::stdout(); 
        loop {
            let msg = format!("\r\x1b[2KBlindDPI is working ({:?})", time.elapsed().as_secs());

            if stdout.write_all(msg.as_bytes()).await.is_ok() {
                let _ = stdout.flush().await;
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    });

    let white_list: Vec<String> = fs::read_to_string("white_list.txt")
        .expect("[Error]File white list doesn't exist!")
        .lines()
        .map(|s| s.trim().to_lowercase())
        .filter(|s| !s.is_empty() && !s.starts_with('#'))
        .collect();

    loop {
        if last_clean.elapsed() >= Duration::from_secs(10) {
            pending.retain(| _, (created_at, _)| created_at.elapsed() < Duration::from_secs(10));
            last_clean = Instant::now();
        }

        let mut msg = queue.recv()?;
        let payload = msg.get_payload();
        
        if let Some(ipv4_packet) = Ipv4Packet::new(payload) {
            if let Some(tcp_packet) = TcpPacket::new(ipv4_packet.payload()) {
                let sequence = tcp_packet.get_sequence();
                let tcp_payload = tcp_packet.payload();

                let mut matched_start_seq: Option<u32> = None;

                for (&strat_seq, (_, data)) in pending.iter() {
                    let expected_seq = strat_seq.wrapping_add(data.len() as u32);
                    if expected_seq == sequence {
                        matched_start_seq = Some(strat_seq);
                        break;
                    }
                }

                if let Some(start_seq) = matched_start_seq {
                    if let Some((_, mut data)) = pending.remove(&start_seq){
                        data.extend_from_slice(tcp_payload);
                        if let Some((pos, domain)) = find_sni(&data) {
                            let domain_in_white_list = is_domain_in_white_list(&domain, &white_list);
                            if domain_in_white_list && split_tunneling_bool || !split_tunneling_bool{
                                let my_ip = SocketAddrV4::new(ipv4_packet.get_source(), tcp_packet.get_source());
                                let server_ip = SocketAddrV4::new(ipv4_packet.get_destination(), tcp_packet.get_destination());
                                let ack = tcp_packet.get_acknowledgement();

                                send_fake_packets(pos, &domain, start_seq, &data, my_ip, server_ip, ack).await?;
                            } else {
                                let my_ip = SocketAddrV4::new(ipv4_packet.get_source(), tcp_packet.get_source());
                                let server_ip = SocketAddrV4::new(ipv4_packet.get_destination(), tcp_packet.get_destination());
                                let ack = tcp_packet.get_acknowledgement();

                                let p1_len  = data.len() - tcp_payload.len();
                                let p1_payload = &data[..p1_len];
                                let p2_payload = &data[p1_len..];
                                send_packet(my_ip, server_ip, start_seq, ack, 64, p1_payload).await?;
                                send_packet(my_ip, server_ip, sequence, ack, 64, p2_payload).await?;
                            } 
                        }
                        msg.set_verdict(Verdict::Drop);
                        queue.verdict(msg)?;
                        continue;
                    }
                }

                if tcp_payload.len() >= 5 
                    && tcp_payload[0] == 0x16 
                    && tcp_payload[1] == 0x03
                    && (tcp_payload[2] >= 0x01 && tcp_payload[2] <= 0x04)
                {  
                    
                    if let Some((pos, domain)) = find_sni(tcp_payload) {
                        let split_tunneling = is_domain_in_white_list(&domain, &white_list);
                        if split_tunneling && split_tunneling_bool{
                            let my_ip = SocketAddrV4::new(ipv4_packet.get_source(), tcp_packet.get_source());
                            let server_ip = SocketAddrV4::new(ipv4_packet.get_destination(), tcp_packet.get_destination());
                            let ack = tcp_packet.get_acknowledgement();

                            send_fake_packets(pos, &domain, sequence, tcp_payload, my_ip, server_ip, ack).await?;
                        }else if split_tunneling_bool && is_domain_rus(&domain){
                            msg.set_verdict(Verdict::Accept);
                            queue.verdict(msg)?;
                            continue;
                        }else if split_tunneling_bool ==  false {
                            let my_ip = SocketAddrV4::new(ipv4_packet.get_source(), tcp_packet.get_source());
                            let server_ip = SocketAddrV4::new(ipv4_packet.get_destination(), tcp_packet.get_destination());
                            let ack = tcp_packet.get_acknowledgement();

                            send_fake_packets(pos, &domain, sequence, tcp_payload, my_ip, server_ip, ack).await?;
                        } else {
                            msg.set_verdict(Verdict::Accept);
                            queue.verdict(msg)?;
                            continue;
                        }
                        
                    }else {
                        pending.insert(sequence, (Instant::now(), tcp_payload.to_vec()));
                    }

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
//====================================================
//==========================
//====================================================
async fn send_fake_packets(
    pos: usize,     
    _domain: &str, 
    start_seq: u32, 
    data: &[u8], 
    my_ip: SocketAddrV4,
    server_ip: SocketAddrV4,
    ack: u32,    
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let trash = rand::thread_rng().gen_range(10..=33);
    let real_seq = start_seq;

    let mut junk: Vec<u8> = vec![0u8; trash];
    rand::thread_rng().fill(&mut junk[..]);
    
    let mut packet1_payload = junk.clone();
    packet1_payload.extend_from_slice(&data[..pos]);

    let packet1_seq = real_seq.wrapping_sub(trash as u32);
    let packet2_payload = &data[pos..];
    let packet2_seq = real_seq + pos as u32;

    send_packet(my_ip, server_ip, packet2_seq, ack, 64, packet2_payload).await?;
    send_packet(my_ip, server_ip, packet1_seq, ack, 64, &packet1_payload).await?;
    Ok(())
}