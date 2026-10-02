use tokio::{io::AsyncReadExt, time::Instant};
use pnet::packet::{Packet, ipv4::Ipv4Packet, ipv6::Ipv6Packet, tcp::TcpPacket};

pub async fn _like_main(split_tunneling_bool: bool, vpn_fd: i32) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
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