use pnet::packet::ipv4::MutableIpv4Packet;

pub async fn _send_fake_udp(
    payload: &[u8]
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>{
    let total = 20 + 8 + payload.len();
    let mut buffer = vec![0u8; total];

    if let Some(mut _ip) = MutableIpv4Packet::new(&mut buffer) {

    }

    Ok(())
}