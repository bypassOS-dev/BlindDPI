use std::collections::HashMap;
use nfq::Verdict;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::udp::UdpPacket;
use pnet::packet::{Packet, ipv4::Ipv4Packet, tcp::TcpPacket};
//==============================================================
use crate::helper_functions::handle_tcp::handle_tcp;
use crate::helper_functions::handle_udp::handle_udp;
//===========================================================

pub async fn general (
    payload: &[u8], 
    pending: &mut HashMap<u32, (std::time::Instant, std::vec::Vec<u8>)>,
    white_list: &[String],
    split_tunneling_bool: bool,
) -> Result<Verdict, Box<dyn std::error::Error + Send + Sync>> {
    if let Some(ipv4_packet) = Ipv4Packet::new(payload) {
        // ========= If this packet is Ipv4 then get Tcp-packet inside Ipv4 packet ==========
        if let Some(tcp_packet) = TcpPacket::new(ipv4_packet.payload()) {
            return handle_tcp(
                pending, 
                tcp_packet, 
                ipv4_packet.get_source().into(), 
                ipv4_packet.get_destination().into(), 
                split_tunneling_bool, 
                white_list
            ).await;
        }
        if let Some(udp_packet) = UdpPacket::new(ipv4_packet.payload()) {
            return handle_udp(
                udp_packet,
            ).await;
        }
    } 
    if let Some(ipv6_packet) = Ipv6Packet::new(payload) {
        if let Some(tcp_packet) = TcpPacket::new(ipv6_packet.payload()) {
            return handle_tcp(
                pending, 
                tcp_packet, 
                ipv6_packet.get_source().into(), 
                ipv6_packet.get_destination().into(), 
                split_tunneling_bool, 
                white_list
            ).await;
        }
    }
    Ok(Verdict::Accept)
}