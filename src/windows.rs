use windivert::WinDivert;
use pnet::packet::{Packet, ipv4::Ipv4Packet, tcp::TcpPacket};

pub async fn like_main(_split_tunneling_bool: bool) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let filter = "outbound and ip and tcp.DstPort == 443";
    let driver = WinDivert::network(filter, 0, Default::default())?;

    let mut buffer = vec![0u8; 65535];

    loop {
        let packet = driver.recv(Some(&mut buffer))?;
        if let Some(ipv4_packet) = Ipv4Packet::new(&packet.data) {
            if let Some(tcp_packet) = TcpPacket::new(ipv4_packet.payload()) {
                
            }
        }
    }   
}