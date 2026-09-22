mod like_main;
use like_main::like_main;
use tokio::process::Command;

#[tokio::main]
async fn main() {
    let split_tunneling_bool:bool;
    println!("Please wait for a launch...");
    //===============Split tunneling=======================
    println!("Enable split tunneling? (yes/no)  ");
    let mut split_tunneling = String::new();
    std::io::stdin()
        .read_line(&mut split_tunneling)
        .expect("[Error line ~14]Sorry, read error");
    let split_tunneling = split_tunneling.trim();

    if split_tunneling == "yes" || split_tunneling == "y"   {
        split_tunneling_bool = true;
    }else {
        split_tunneling_bool = false;
    }
    //=====================================================
    std::thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(like_main(split_tunneling_bool)).ok();
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