use tokio::process::Command;

pub async fn run_iptables() {
    let _add_table_inet = Command::new("nft")
        .args(["add", "table", "inet", "blind_dpi"])
        .status()
        .await
        .expect("[ERROR] CRASHED WHEN ADDIND THE RULE!");

    let _chain = Command::new("nft")
        .args(["add", "chain", "inet", "blind_dpi", "output", "{ type filter hook output priority 0; }"])
        .status()
        .await
        .expect("[ERROR] CRASHED WHEN CREATED A CHAIN!");

    let _rule = Command::new("nft")
        .args([
            "add",
            "rule",
            "inet",
            "blind_dpi",
            "output",
            "tcp",
            "dport",
            "443",
            "counter",
            "queue",
            "num",
            "0",
        ])
        .status()
        .await
        .expect("[ERROR] CRASHED WHEN CREATED A NFT RULE!");
}
pub async fn remove_iptables() {
    let _ = Command::new("nft")
        .args(["delete", "table", "inet", "blind_dpi"])
        .status();
}