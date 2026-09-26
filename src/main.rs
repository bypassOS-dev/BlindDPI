mod like_main;
mod send_packet;

use like_main::like_main;

#[tokio::main]
async fn main() {
    let split_tunneling_bool:bool;
    
    println!("Please wait for a launch...");
    //===============Split tunneling=======================
    println!("Enable split tunneling? (yes/no)  ");
    let mut split_tunneling = String::new();
    std::io::stdin()
        .read_line(&mut split_tunneling)
        .expect("[Error! line ~14]Sorry, read error");
    let split_tunneling = split_tunneling.trim();

    if split_tunneling == "yes" || split_tunneling == "y"   {
        split_tunneling_bool = true;
    }else {
        split_tunneling_bool = false;
    }

    std::thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(like_main(split_tunneling_bool)).ok();
    });

    tokio::signal::ctrl_c().await.unwrap();

    println!("\nOk... make clean the iptables...");
    like_main::iptables::remove_iptables().await;
    std::process::exit(0);

}

    
    