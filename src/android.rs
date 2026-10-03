use crate::helper_functions::find_sni::{find_sni};
use tokio::{io::AsyncReadExt, time::Instant};
use pnet::packet::{Packet, ipv4::Ipv4Packet, ipv6::Ipv6Packet, tcp::TcpPacket};
use std::collections::HashMap;
use std::os::fd::FromRawFd;

pub async fn like_main(split_tunneling_bool: bool, vpn_fd: i32) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let file = unsafe { std::fs::File::from_raw_fd(vpn_fd) };
    let mut tun = tokio::fs::File::from_std(file);

    let mut buffer = vec![0u8; 65535];

    let mut pending: HashMap<u32, (Instant, Vec<u8>)> = HashMap::new();
    let last_clean = Instant::now();
    loop {
        
        let n = tun.read(&mut buffer).await?;
        if n == 0 {
            break;
        }
        let packet = &buffer[..n];

        let ip_version = packet[0] >> 4;
        
        if ip_version == 4 {
            if let Some(ipv4_packet) = Ipv4Packet::new(packet) {
                if let Some(tcp_packet) = TcpPacket::new(ipv4_packet.payload()) {
                    let sequence = tcp_packet.get_sequence();
                    let tcp_payload = tcp_packet.payload();
                    let mut matched_start_seq: Option<u32> = None;

                    for (&seq, (_, data)) in pending.iter() {
                        let expected_seq = seq.wrapping_add(data.len() as u32);
                        if expected_seq == sequence {
                            matched_start_seq == Some(seq);
                            break;
                        }
                    }

                    if let Some(start_sequence) = matched_start_seq {
                        if let Some((_, mut data)) = pending.remove(&start_sequence) {
                            data.extend_from_slice(tcp_payload);

                            if let Some((pos, domain)) = find_sni(&data) {

                            } else {
                                pending.insert(start_sequence, (Instant::now(), data));
                            }
                        }
                    }
                }
            }
        } else {
            if let Some(ipv6_packet) = Ipv6Packet::new(packet) {
                if let Some(tcp_packet) = TcpPacket::new(ipv6_packet.payload()) {

                }
            }
        }
    }

    Ok(())
}