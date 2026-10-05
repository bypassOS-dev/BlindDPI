use crate::helper_functions::find_sni::{find_sni};
use crate::send_packet::send_packet;
use crate::helper_functions::get_domain::is_domain_in_white_list;
use crate::helper_functions::send_fake_packets::send_fake_packets;
use tokio::{io::AsyncReadExt, time::Instant};
use pnet::packet::{Packet, ipv4::Ipv4Packet, ipv6::Ipv6Packet, tcp::TcpPacket};
use std::collections::HashMap;
//use std::fs;
use std::net::SocketAddr;
use std::os::fd::FromRawFd;
use std::time::Duration;

use jni::JNIEnv;
use jni::objects::JClass;
use jni::sys::jint;

pub async fn like_main(split_tunneling_bool: bool, vpn_fd: i32) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let file = unsafe { std::fs::File::from_raw_fd(vpn_fd) };
    let mut tun = tokio::fs::File::from_std(file);

    let mut buffer = vec![0u8; 65535];

    let mut pending: HashMap<u32, (Instant, Vec<u8>)> = HashMap::new();
    let mut last_clean = Instant::now();


    let white_list: Vec<String> = 
        vec![
            "youtube.com".to_string(),       
            "youtu.be".to_string(),
            "googlevideo.com".to_string(),
            "ytimg.com".to_string(),
            "ggpht.com".to_string(),
            "youtubei.googleapis.com".to_string(),
        ];
    loop {
        if last_clean.elapsed() >= Duration::from_secs(10) {
            pending.retain(|_, (created_in, _)| created_in.elapsed() < Duration::from_secs(10));
            last_clean = Instant::now();
        }
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
                            matched_start_seq = Some(seq);
                            break;
                        }
                    }

                    if let Some(start_sequence) = matched_start_seq {
                        if let Some((_, mut data)) = pending.remove(&start_sequence) {
                            data.extend_from_slice(tcp_payload);

                            if let Some((pos, domain)) = find_sni(&data) {
                                let domain_in_white_list = is_domain_in_white_list(&domain, &white_list);

                                if domain_in_white_list && split_tunneling_bool ||  !split_tunneling_bool {
                                    let my_ip = SocketAddr::new(ipv4_packet.get_source().into(), tcp_packet.get_source());
                                    let server_ip = SocketAddr::new(ipv4_packet.get_destination().into(), tcp_packet.get_destination());
                                    let ack = tcp_packet.get_acknowledgement();

                                    send_fake_packets(pos, &domain, start_sequence, &data, my_ip, server_ip, ack).await?;
                                } else {
                                    let my_ip = SocketAddr::new(ipv4_packet.get_source().into(), tcp_packet.get_source());
                                    let server_ip = SocketAddr::new(ipv4_packet.get_destination().into(), tcp_packet.get_destination());
                                    let ack = tcp_packet.get_acknowledgement();

                                    let p1_len = data.len() - tcp_payload.len();
                                    let p1_payload = &data[..p1_len];
                                    let p2_payload = &data[p1_len..];

                                    send_packet(my_ip, server_ip, start_sequence, ack, 64, p1_payload).await?;
                                    send_packet(my_ip, server_ip, sequence, ack, 64, p2_payload).await?;
                                }
                            } else {
                                pending.insert(start_sequence, (Instant::now(), data));
                            }
                            if tcp_payload.len() >= 5 
                                && tcp_payload[0] == 0x16 
                                && tcp_payload[1] == 0x03
                                && (tcp_payload[2] >= 0x01 && tcp_payload[2] <= 0x04)
                            {
                                if let Some((pos, domain)) = find_sni(tcp_payload) {
                                    let split_tunneling = is_domain_in_white_list(&domain, &white_list);
                                    if split_tunneling && split_tunneling_bool || !split_tunneling_bool{
                                        let my_ip = SocketAddr::new(ipv4_packet.get_source().into(), tcp_packet.get_source());
                                        let server_ip = SocketAddr::new(ipv4_packet.get_destination().into(), tcp_packet.get_destination());
                                        let ack = tcp_packet.get_acknowledgement();

                                        send_fake_packets(pos, &domain, sequence, tcp_payload, my_ip, server_ip, ack).await?;
                                    } else {
                                        continue;
                                    }
                                } else {
                                    continue;
                                }
                                continue;

                            }
                        }
                    }
                    continue;
                }
        } 
        else {
            if let Some(ipv6_packet) = Ipv6Packet::new(packet) {
                if let Some(tcp_packet) = TcpPacket::new(ipv6_packet.payload()) {
                    let sequence = tcp_packet.get_sequence();
                    let tcp_payload = tcp_packet.payload();
                    let mut matched_start_seq: Option<u32> = None;

                    for (&seq, (_, data)) in pending.iter() {
                        let expected_seq = seq.wrapping_add(data.len() as u32);
                        if expected_seq == sequence {
                            matched_start_seq = Some(seq);
                            break;
                        }
                    }

                    if let Some(start_sequence) = matched_start_seq {
                        if let Some((_, mut data)) = pending.remove(&start_sequence) {
                            data.extend_from_slice(tcp_payload);

                            if let Some((pos, domain)) = find_sni(&data) {
                                let domain_in_white_list = is_domain_in_white_list(&domain, &white_list);

                                if domain_in_white_list && split_tunneling_bool ||  !split_tunneling_bool {
                                    let my_ip = SocketAddr::new(ipv6_packet.get_source().into(), tcp_packet.get_source());
                                    let server_ip = SocketAddr::new(ipv6_packet.get_destination().into(), tcp_packet.get_destination());
                                    let ack = tcp_packet.get_acknowledgement();

                                    send_fake_packets(pos, &domain, start_sequence, &data, my_ip, server_ip, ack).await?;
                                } else {
                                    let my_ip = SocketAddr::new(ipv6_packet.get_source().into(), tcp_packet.get_source());
                                    let server_ip = SocketAddr::new(ipv6_packet.get_destination().into(), tcp_packet.get_destination());
                                    let ack = tcp_packet.get_acknowledgement();

                                    let p1_len = data.len() - tcp_payload.len();
                                    let p1_payload = &data[..p1_len];
                                    let p2_payload = &data[p1_len..];

                                    send_packet(my_ip, server_ip, start_sequence, ack, 64, p1_payload).await?;
                                    send_packet(my_ip, server_ip, sequence, ack, 64, p2_payload).await?;
                                }
                            } else {
                                pending.insert(start_sequence, (Instant::now(), data));
                            }
                            if tcp_payload.len() >= 5 
                                && tcp_payload[0] == 0x16 
                                && tcp_payload[1] == 0x03
                                && (tcp_payload[2] >= 0x01 && tcp_payload[2] <= 0x04)
                            {
                                if let Some((pos, domain)) = find_sni(tcp_payload) {
                                    let split_tunneling = is_domain_in_white_list(&domain, &white_list);
                                    if split_tunneling && split_tunneling_bool ||  !split_tunneling_bool {
                                        let my_ip = SocketAddr::new(ipv6_packet.get_source().into(), tcp_packet.get_source());
                                        let server_ip = SocketAddr::new(ipv6_packet.get_destination().into(), tcp_packet.get_destination());
                                        let ack = tcp_packet.get_acknowledgement();
                                        send_fake_packets(pos, &domain, sequence, tcp_payload, my_ip, server_ip, ack).await?;
                                    }else {
                                        continue;
                                    }
                                } else {
                                    continue;
                                }
                                continue;

                                }
                            }
                        }
                        continue;
                    }
                }
            }
        }
    }
    Ok(())
}


#[unsafe(no_mangle)]
pub extern "C" fn Java_com_example_blinddpi_NativeBridge_startEngine(
    _env: JNIEnv,
    _class: JClass,
    vpn_fd: jint,
    split_tunneling: jni::sys::jboolean
) {
    std::thread::spawn(move || {
        let split_bool = split_tunneling != 0;
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            if let Err(e) = like_main(split_bool, vpn_fd).await {
                eprintln!("[Rust Error] Engine crashed: {:?}", e);
            }
        });
    });
}