use std::net::SocketAddrV4;
use pnet::packet::{
    Packet, ip::{IpNextHeaderProtocols}, ipv4::{self, MutableIpv4Packet}, tcp::{self, MutableTcpPacket, TcpFlags},
};
use pnet_transport::{TransportChannelType::Layer3, transport_channel};

pub async fn send_packet(
    my_ip: SocketAddrV4,
    server_ip: SocketAddrV4,
    seq: u32,
    ack: u32,
    ttl: u8,
    random_text: &[u8]
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
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

    let checksum = tcp::ipv4_checksum(&tcp_packet.to_immutable(), my_ip.ip(), server_ip.ip()); // Calculate checksum
    tcp_packet.set_checksum(checksum);         // write checksum to TCP-packet

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
    ip_packet.set_source(*my_ip.ip());
    ip_packet.set_destination(*server_ip.ip());
    ip_packet.set_payload(tcp_packet.packet());
    let ip_checksum = ipv4::checksum(&ip_packet.to_immutable());
    ip_packet.set_checksum(ip_checksum);

    tx.send_to(ip_packet.to_immutable(), std::net::IpAddr::V4(*server_ip.ip()))?;
    Ok(())
}