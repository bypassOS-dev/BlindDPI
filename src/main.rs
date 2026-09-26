//=========LINUX=================
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
use linux::like_main as backend;
#[cfg(target_os = "linux")]
mod send_packet;
//===============================
//========
//==========WINDOWS==============
#[cfg(target_os = "windows")]
mod windows;
#[cfg(target_os = "windows")]
use windows::like_main as backend;
//===============================
//========
//==========GENERAL==============
use std::io;
//===============================
#[tokio::main]
async fn main() {
    let split_tunneling_bool:bool;
    
    println!("Please wait for a launch...");
    //===============Split tunneling=======================
    println!("Enable split tunneling? (yes/no)  ");
    let mut split_tunneling = String::new();
    io::stdin()
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
        rt.block_on(backend(split_tunneling_bool)).ok();
    });

    tokio::signal::ctrl_c().await.unwrap();
    #[cfg(target_os = "linux")]
    {
    println!("\nOk... make clean the iptables...");
    linux::iptables::remove_iptables().await;
    std::process::exit(0);
    }
}

    
    