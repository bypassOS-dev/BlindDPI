//=========LINUX=================
#[cfg(target_os = "linux")]
use crate::linux::like_main as backend;
#[cfg(target_os = "linux")]
use crate::linux::iptables::run_iptables;
//===============================
//==========GENERAL==============
use std::process::Command;
//===============================

pub async fn run_blinddpi(token: tokio_util::sync::CancellationToken) {
    // Run bash script which checking for necessary utils
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

    // If check was succassfully then run
    // somee stuff for sniffing packets:
    #[cfg(target_os = "linux")]
    run_iptables().await;

    //===============Split tunneling=======================
    let split_tunneling_bool:bool = false;

    
    //====================================================
    //Run main function in another OS-stream
    std::thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(backend(split_tunneling_bool)).ok();
    });
    //=====================================================
    // If user press ctrl+c/stop then clean all nft-rule (if OS isn't linux then just close programm)
    tokio::select! {
        _ = token.cancelled() => {},
        _ = tokio::signal::ctrl_c() => {},
    }

    #[cfg(target_os = "linux")]
    {
        println!("Ok... make clean the iptables...");
        crate::linux::iptables::remove_iptables().await;

        if !token.is_cancelled() {
            std::process::exit(0);
        }
    }
    
}