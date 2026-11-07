use pnet::packet::{ipv4::MutableIpv4Packet, udp::{self, MutableUdpPacket}};
use std::net::Ipv4Addr;
use pnet::packet::{
    ip::{IpNextHeaderProtocols}, ipv4::{self}
};
use pnet_transport::TransportSender;



// DOESN'T WORK!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
pub fn _send_fake_udp(
    payload: &[u8],
    src: Ipv4Addr,
    src_port: u16,
    dst: Ipv4Addr,
    dst_port: u16,
    #[cfg(target_os = "linux")]
    tx:  &mut TransportSender,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>{
    let udp_len = 8 + payload.len();
    let mut udp_buffer = vec![0u8; udp_len];

    if let Some(mut udp_packet) = MutableUdpPacket::new(&mut udp_buffer) {
        udp_packet.set_source(src_port);
        udp_packet.set_destination(dst_port);
        udp_packet.set_length(udp_len as u16);
        udp_packet.set_payload(payload);

        let udp_checksum = udp::ipv4_checksum(&udp_packet.to_immutable(), &src, &dst);
        udp_packet.set_checksum(udp_checksum);

        //======================================================
        let ip_len = 20 + udp_len;
        let mut ip_buffer = vec![0u8; ip_len];

        if let Some(mut ip_packet) = MutableIpv4Packet::new(&mut ip_buffer) {
            ip_packet.set_version(4);
            ip_packet.set_destination(dst);
            ip_packet.set_source(src);
            ip_packet.set_header_length(5);
            ip_packet.set_ttl(7);
            ip_packet.set_next_level_protocol(IpNextHeaderProtocols::Udp);
            ip_packet.set_payload(&udp_buffer);
            ip_packet.set_total_length(ip_len as u16);
            ip_packet.set_checksum(ipv4::checksum(&ip_packet.to_immutable()));

            #[cfg(target_os = "linux")]
            tx.send_to(ip_packet, dst.into())?;
        }
    }

    Ok(())
}