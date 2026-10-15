use nfq::Verdict;
use pnet::packet::udp::UdpPacket;

pub async fn handle_udp (
    _udp_packet: UdpPacket<'_>
) -> Result<Verdict, Box<dyn std::error::Error + Send + Sync>>{
    Ok(Verdict::Accept)
}