use tokio::process::Command;

pub async fn run_iptables() {
    let status = Command::new("iptables")
        .arg("-A")
        .arg("OUTPUT")
        .arg("-p")
        .arg("tcp")
        .arg("--dport")
        .arg("443")
        .arg("-j")
        .arg("NFQUEUE")
        .arg("--queue-num")
        .arg("0")
        .status()
        .await
        .expect("Executing error");
    println!("{status}");
}