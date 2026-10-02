//=========LINUX=================
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
use linux::like_main as backend;
#[cfg(target_os = "linux")]
use linux::iptables::run_iptables;
//===============================
//==========WINDOWS==============
#[cfg(target_os = "windows")]
mod windows;
#[cfg(target_os = "windows")]
use windows::like_main as backend;
//===============================
//===========ANDROID=============
#[cfg(target_os = "android")]
mod android;
#[cfg(target_os = "android")]
use android::like_main as backend;
//===============================
//==========GENERAL==============
use std::{io, process::Command};
mod helper_functions;
pub mod send_packet;
//===============================



#[tokio::main]
async fn main() {
    #[cfg(target_os = "android")]
    println!("Your OS isn't support yet. Sorry.");

    #[cfg(target_os = "linux")]
    let script = include_str!("check_iptables.sh");
    #[cfg(target_os = "linux")]
    let status = Command::new("bash")
        .arg("-c")
        .arg(script)
        .status()
        .expect("[FATAL ERROR] bash script crashed!");

    #[cfg(target_os = "linux")]
    if !status.success() {
        eprintln!("Script was ended with error(Code: {:?}). Stop. ", status.code());
        std::process::exit(1);
    }

    run_iptables().await;
    //===============Split tunneling=======================
    let split_tunneling_bool:bool;

    println!("Enable split tunneling? (yes/no)  ");
    let mut split_tunneling = String::new();
    io::stdin()
        .read_line(&mut split_tunneling)
        .expect("[Error]Read error");
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