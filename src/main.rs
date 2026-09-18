mod like_main;
use like_main::like_main;
use tokio::process::Command;

#[tokio::main]
async fn main() {
    tokio::select! {
        result = like_main() => {
            eprintln!("like_main exited: {:?}", result);
        }
        _ = tokio::signal::ctrl_c() => {
            remove_iptables().await;
            std::process::exit(0);
        }
    }
}

pub async fn remove_iptables() {
    let _status = Command::new("iptables")
        .arg("-D")
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
}