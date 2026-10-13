use std::{net::SocketAddr, collections::HashMap};
use std::time::Instant;
use nfq::Verdict;
use pnet::packet::{Packet, ipv4::Ipv4Packet, tcp::TcpPacket};
//==============================================================
use crate::helper_functions::{find_sni, get_domain, send_fake_packets};
//===========================================================
use send_fake_packets::send_fake_packets;
use crate::send_packet::send_packet;
use find_sni::find_sni;
use get_domain::is_domain_in_white_list;
//===================================================


pub async fn general (
    payload: Vec<u8>, 
    pending: &mut HashMap<u32, (std::time::Instant, std::vec::Vec<u8>)>,
    white_list: Vec<String>,
    split_tunneling_bool: bool,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if let Some(ipv4_packet) = Ipv4Packet::new(&payload) {
        // ========= If this packet is Ipv4 then get Tcp-packet inside Ipv4 packet ==========
        if let Some(tcp_packet) = TcpPacket::new(ipv4_packet.payload()) {
            let sequence = tcp_packet.get_sequence();
            let tcp_payload = tcp_packet.payload();
            let mut matched_start_seq: Option<u32> = None;
            //============= Check: It's new packet or old and partial packet? ===============
            for (&strat_seq, (_, data)) in pending.iter() {
                let expected_seq = strat_seq.wrapping_add(data.len() as u32);
                if expected_seq == sequence {
                    matched_start_seq = Some(strat_seq);
                    break;
                }
            }

            // If this packet old and partial then...
            if let Some(start_seq) = matched_start_seq {
                // We to get hold of data:
                if let Some((_, mut data)) = pending.remove(&start_seq){
                    // And just to glue 2 piece to one!
                    data.extend_from_slice(tcp_payload);

                    // Find sni:
                    if let Some((pos, domain)) = find_sni(&data) {
                        // Checking domain. If it's domain must
                        // will bypass then variable == true
                        let domain_in_white_list = is_domain_in_white_list(&domain, &white_list);

                        // If it's domain in white list and user asked for split tunneling,
                        // Or if he doesn't ask for split tonneling... 
                        if domain_in_white_list && split_tunneling_bool || !split_tunneling_bool{
                            // Get user's IP, server's IP and acknowledgement for send packets
                            let my_ip = SocketAddr::new(ipv4_packet.get_source().into(), tcp_packet.get_source());
                            let server_ip = SocketAddr::new(ipv4_packet.get_destination().into(), tcp_packet.get_destination());
                            let ack = tcp_packet.get_acknowledgement();

                            send_fake_packets(pos, &domain, start_seq, &data, my_ip, server_ip, ack).await?;
                        } else {
                            // If domain don't in white list 
                            // (it's can be some site that don't block in user's region)
                            // we just forward packet! 
                            let my_ip = SocketAddr::new(ipv4_packet.get_source().into(), tcp_packet.get_source());
                            let server_ip = SocketAddr::new(ipv4_packet.get_destination().into(), tcp_packet.get_destination());
                            let ack = tcp_packet.get_acknowledgement();

                            let p1_len  = data.len() - tcp_payload.len();
                            let p1_payload = &data[..p1_len];
                            let p2_payload = &data[p1_len..];
                            send_packet(my_ip, server_ip, start_seq, ack, 64, p1_payload).await?;
                            send_packet(my_ip, server_ip, sequence, ack, 64, p2_payload).await?;
                        } 
                    // If sni don't found then add to our storage
                    // (because it's mean that packet was modified)
                    }else {
                        pending.insert(start_seq, (Instant::now(), data));
                    }

                    // Drop real packet
                    // (Because we already send our packet)
                    }
                }

                // But if this packet isn't partial ==> check: Is it TSL-handshake?
                if tcp_payload.len() >= 5          // This packet must be more that 5 bytes to rust isn't panic
                    && tcp_payload[0] == 0x16     // "0x16" -> First byte ALL tls-handshake
                    && tcp_payload[1] == 0x03    // Like you already understand second byte --> 0x03 
                    && (tcp_payload[2] >= 0x01 && tcp_payload[2] <= 0x04)   // Check tsl-version
                {  
                    // Get domain...
                    if let Some((pos, domain)) = find_sni(tcp_payload) {
                        // Check domain: Is domain in white list?
                        let split_tunneling = is_domain_in_white_list(&domain, &white_list);

                        // If it's domain in white list and user asked for split tunneling,
                        // Or if he doesn't ask for split tonneling... 
                        if split_tunneling && split_tunneling_bool || !split_tunneling_bool{
                            // Get user's IP, server's IP and acknowledgement for send packets
                            let my_ip = SocketAddr::new(ipv4_packet.get_source().into(), tcp_packet.get_source());
                            let server_ip = SocketAddr::new(ipv4_packet.get_destination().into(), tcp_packet.get_destination());
                            let ack = tcp_packet.get_acknowledgement();

                            send_fake_packets(pos, &domain, sequence, tcp_payload, my_ip, server_ip, ack).await?;
                        } else {
                            // If domain don't in white list 
                            // (it's can be some site that don't block in user's region)
                            // we just forward packet! 
                            let my_ip = SocketAddr::new(ipv4_packet.get_source().into(), tcp_packet.get_source());
                            let server_ip = SocketAddr::new(ipv4_packet.get_destination().into(), tcp_packet.get_destination());
                            let ack = tcp_packet.get_acknowledgement();

                            send_packet(my_ip, server_ip, sequence, ack, 64, tcp_payload).await?;
                        }
                    // If inside packet we don't find domain then put it in pending 
                    }else {
                        pending.insert(sequence, (Instant::now(), tcp_payload.to_vec()));
                    }
                }
                // If it's not piece of packet or tls-handshake ==> We don't care!
        }
    }
    
    Ok(())
}