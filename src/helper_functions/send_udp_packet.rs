use pnet::packet::{ip::IpNextHeaderProtocol, ipv4::MutableIpv4Packet, udp::{self, MutableUdpPacket}};
use pnet_transport::{TransportChannelType::Layer3, transport_channel};
use std::net::{SocketAddr,Ipv4Addr, Ipv6Addr, IpAddr};
use pnet::packet::{
    Packet, ip::{IpNextHeaderProtocols}, ipv4::{self}, ipv6::MutableIpv6Packet, tcp::{self, MutableTcpPacket, TcpFlags},
};
use pnet_transport::TransportSender;
pub async fn _send_fake_udp(
    payload: &[u8],
    src: Ipv4Addr,
    src_port: u16,
    dst: Ipv4Addr,
    dst_port: u16
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>{
    let udp_len = 8 + payload.len();
    let mut udp_buffer = vec![0u8; udp_len];

    if let Some(mut udp_packet) = MutableUdpPacket::new(&mut udp_buffer) {
        udp_packet.set_source(src_port);
        udp_packet.set_destination(dst_port);
        udp_packet.set_length(udp_len as u16);

        let udp_checksum = udp::ipv4_checksum(&udp_packet.to_immutable(), &src, &dst);
        udp_packet.set_checksum(udp_checksum);

        let ip_len = 20 + udp_len;
        let mut ip_buffer = vec![0u8; ip_len];
    }

    Ok(())
}