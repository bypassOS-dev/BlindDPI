mod like_main;
use like_main::like_main;
use tokio::process::Command;

#[tokio::main]
async fn main() {
    println!("Waiting run, please...");

    std::thread::spawn(|| {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(like_main()).ok();
    });

    tokio::signal::ctrl_c().await.unwrap();

    println!("\nOk... make clean the iptables...");
    remove_iptables().await;
    std::process::exit(0);
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