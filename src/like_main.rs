use nfq::{Queue, Verdict};
use pnet::packet::{Packet, ipv4::Ipv4Packet, tcp::{self, TcpPacket}};

pub async fn like_main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut queue = Queue::open()?;
    queue.bind(0)?;

    let mut pending: Option<(u32, Vec<u8>)> = None;
    loop {
        let mut msg = queue.recv()?;
        let payload = msg.get_payload();

        if let Some(ipv4_packet) = Ipv4Packet::new(payload) {
            if let Some(tcp_packet) = TcpPacket::new(ipv4_packet.payload()) {
                let sequence = tcp_packet.get_sequence();
                let tcp_payload = tcp_packet.payload();

                if let Some((pending_seq, pending_data)) = &mut pending{
                    let expected_seq = pending_seq.wrapping_add(pending_data.len() as u32);
                    if expected_seq == sequence {
                        
                    }
                }

                if tcp_payload.len() > 5 && tcp_payload[0] == 0x16 {
                    pending = Some((sequence, tcp_payload.to_vec()));

                    msg.set_verdict(Verdict::Drop);
                    queue.verdict(msg)?;
                    continue;
                }
                
            }
        }
    }
}
