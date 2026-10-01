//================for linux========================
#[cfg(target_os = "linux")]
use pnet::packet::{
    Packet, ip::{IpNextHeaderProtocols}, ipv4::{self, MutableIpv4Packet}, ipv6::MutableIpv6Packet, tcp::{self, MutableTcpPacket, TcpFlags},
};
#[cfg(target_os = "linux")]
use pnet_transport::{TransportChannelType::Layer3, transport_channel};
//=================for windows=====================
#[cfg(target_os = "windows")]
use windivert::{address::WinDivertAddress, layer, packet::WinDivertPacket};
#[cfg(target_os = "windows")]
use windivert::WinDivert;
#[cfg(target_os = "windows")]
use pnet::packet::{
    Packet, icmp::IcmpTypes::AddressMaskReply, ip::IpNextHeaderProtocols, ipv4::{self, MutableIpv4Packet}, tcp::{self, MutableTcpPacket, TcpFlags},
};
//==================general========================
use std::net::{SocketAddr,Ipv4Addr, Ipv6Addr, IpAddr};

pub async fn send_packet(
    my_ip: SocketAddr,
    server_ip: SocketAddr,
    seq: u32,
    ack: u32,
    ttl: u8,
    random_text: &[u8],
    #[cfg(target_os = "windows")]
    driver: &WinDivert<layer::NetworkLayer>,
    #[cfg(target_os = "windows")]
    address: &WinDivertAddress<layer::NetworkLayer>
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    match (my_ip.ip(), server_ip.ip()) {
        (IpAddr::V4(src_v4), IpAddr::V4(dst_v4)) => assemble_packet_v4(
            my_ip, 
            server_ip, 
            src_v4, 
            dst_v4, 
            seq, 
            ack, 
            ttl, 
            random_text,
            #[cfg(target_os = "windows")]
            driver,
            #[cfg(target_os = "windows")]
            address
        )?,
        (IpAddr::V6(_src_v4), IpAddr::V6(_dst_v6)) => return Ok(()),
        _ => return Ok(()),
    }
    
    Ok(())
}
//==================================================================
//
// Ipv4
//
//===================================================================
fn assemble_packet_v4(
    my_ip: SocketAddr,
    server_ip: SocketAddr,
    src_v4: Ipv4Addr,
    dst_v4: Ipv4Addr,
    seq: u32,
    ack: u32,
    ttl: u8,
    random_text: &[u8],
    #[cfg(target_os = "windows")]
    driver: &WinDivert<layer::NetworkLayer>,
    #[cfg(target_os = "windows")]
    address: &WinDivertAddress<layer::NetworkLayer>) -> Result<(), Box<dyn std::error::Error + Send + Sync>>{
    #[cfg(target_os = "linux")]
    let (mut tx, _) = transport_channel(2048, Layer3(IpNextHeaderProtocols::Tcp))?; // Open a special communication channel  

        //Calculate total lenght of TCP-segments in bytes:
       // 20 bytes: 
      // 4 bytes: sender's port (2 bytes) + recipient's port (2 bytes)
     // 10 bytes: Sequence Numbet (4 bytes) + Acknowledgement number (4 bytes) + flags and header lenght (2 bytes)
    // 6 bytes: Window Size (2 bytes) + Checksum (2 bytes) + Urgent Pointer (2 bytes) 
    let tcp_len = 20 + random_text.len(); //calculate how many bytes the entire TCP-segment will be occupy
    let mut tcp_buf = vec![0u8; tcp_len];
    let mut tcp_packet = MutableTcpPacket::new(&mut tcp_buf) // Create a "wrapper-helper"
        .ok_or("Failed to create TCP packet buffer")?;  // If buffer is too small then program end work

    // Start to fill our "wrapper" 
    tcp_packet.set_source(my_ip.port());                  // Write to TCP-header sender's port
    tcp_packet.set_destination(server_ip.port());         // Write to TCP-header recipient's port
    tcp_packet.set_sequence(seq);                         // Write to TCP-header sequence number
    tcp_packet.set_acknowledgement(ack);                  // Write to TCP-header acknowledgement numbet 
    tcp_packet.set_flags(TcpFlags::ACK | TcpFlags::PSH);  // A combination of flags that usualy found in normal packet
    tcp_packet.set_window(64240);                         // Write to TCP-header standart window size
    tcp_packet.set_data_offset(5);                        // Say to recipient where start payload (5 piece of 4 bytes)
    tcp_packet.set_payload(random_text);                 // Write payload after TCP-header (20 bytes)

    let tcp_checksum = tcp::ipv4_checksum(&tcp_packet.to_immutable(), &src_v4, &dst_v4);
    tcp_packet.set_checksum(tcp_checksum);

    let ip_len = 20 + tcp_len;   
    let mut ip_buf = vec![0u8; ip_len];
    let mut ip_packet = MutableIpv4Packet::new(&mut ip_buf)
        .ok_or("Failed to create IP packet buffer")?;

    ip_packet.set_version(4);
    ip_packet.set_header_length(5);
    ip_packet.set_next_level_protocol(IpNextHeaderProtocols::Tcp); // Inside this packet found TCP
    ip_packet.set_total_length(ip_len as u16);
    ip_packet.set_identification(0x1234);
    ip_packet.set_flags(0);
    ip_packet.set_fragment_offset(0);
    ip_packet.set_ttl(ttl);
    ip_packet.set_payload(tcp_packet.packet());
    ip_packet.set_source(src_v4);
    ip_packet.set_destination(dst_v4);

    let ip_checksum = ipv4::checksum(&ip_packet.to_immutable());
    ip_packet.set_checksum(ip_checksum);

    #[cfg(target_os = "linux")]
    tx.send_to(ip_packet.to_immutable(), std::net::IpAddr::V4(dst_v4))?;

    #[cfg(target_os = "windows")]
    let packet = WinDivertPacket {
        data: ip_buf.into(),
        address: address.clone(),
    };
    #[cfg(target_os = "windows")]
    driver.send(&packet)?;

    Ok(())
}


//=====================================================================
//
// Ipv6
//
//=====================================================================
fn _assemble_packet_v6(
    my_ip: SocketAddr,
    server_ip: SocketAddr,
    src_v6: Ipv6Addr,
    dst_v6: Ipv6Addr,
    seq: u32,
    ack: u32,
    ttl: u8,
    random_text: &[u8],
    #[cfg(target_os = "windows")]
    driver: &WinDivert<layer::NetworkLayer>,
    #[cfg(target_os = "windows")]
    address: &WinDivertAddress<layer::NetworkLayer>) -> Result<(), Box<dyn std::error::Error + Send + Sync>>{
    #[cfg(target_os = "linux")]
    let (mut tx, _) = transport_channel(2048, Layer3(IpNextHeaderProtocols::Tcp))?; // Open a special communication channel  
    
    let tcp_len = 20 + random_text.len();
    let mut tcp_buff = vec![0u8; tcp_len];
    let mut tcp_packet = MutableTcpPacket::new(&mut tcp_buff).ok_or("Failed to create TCP packet buffer")?;

    tcp_packet.set_source(my_ip.port());
    tcp_packet.set_destination(server_ip.port());
    tcp_packet.set_sequence(seq);
    tcp_packet.set_acknowledgement(ack);
    tcp_packet.set_flags(TcpFlags::ACK | TcpFlags::PSH);
    tcp_packet.set_window(64240);
    tcp_packet.set_data_offset(5);
    tcp_packet.set_payload(random_text);

    let tcp_checksum = tcp::ipv6_checksum(&tcp_packet.to_immutable(), &src_v6, &dst_v6);
    tcp_packet.set_checksum(tcp_checksum);


    let ipv6_len = 40 + tcp_len;
    let mut ipv6_buf = vec![0u8;ipv6_len];
    let mut ipv6_packet = MutableIpv6Packet::new(&mut ipv6_buf)
        .ok_or("Failed to create IPv6 packet buffer")?;

    ipv6_packet.set_version(6);
    ipv6_packet.set_traffic_class(0);
    ipv6_packet.set_flow_label(0);
    ipv6_packet.set_payload_length(tcp_len as u16);
    ipv6_packet.set_next_header(IpNextHeaderProtocols::Tcp);
    ipv6_packet.set_hop_limit(ttl);
    ipv6_packet.set_source(src_v6);
    ipv6_packet.set_destination(dst_v6);
    ipv6_packet.set_payload(tcp_packet.packet());

    #[cfg(target_os = "linux")]
    tx.send_to(ipv6_packet, std::net::IpAddr::V6(dst_v6))?;

    #[cfg(target_os = "windows")]
    let packet = WinDivertPacket {
        data: ip_buf.into(),
        address: address.clone(),
    };

    Ok(())
}