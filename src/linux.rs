use std::{collections::HashMap, fs};
use nfq::Queue;
use tokio::io as tokio_io; 
use tokio::io::AsyncWriteExt;
use std::time::{Duration, Instant};
//==============================================================
use crate::helper_functions::general::general;
//===========================================================
pub mod iptables;
//===================================================

pub async fn like_main(split_tunneling_bool: bool) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut queue = Queue::open()?;
    queue.bind(0)?;

    // Pending is need for packets 
    // that was splite on your PC 
    let mut pending: HashMap<u32, (Instant, Vec<u8>)> = HashMap::new();
    let mut last_clean = Instant::now();
    //=====================Time counter=========================
    //================Just beautifull output====================
    tokio::spawn(async {
        let time = Instant::now();
        let mut stdout = tokio_io::stdout(); 
        //
        loop {
            let total_secs = time.elapsed().as_secs();

            let hours = total_secs / 3600;
            let minutes = (total_secs % 3600) / 60;
            let seconds = total_secs % 60;

            let msg = format!(
                 "\r\x1b[2KBlindDPI is working ({:02}:{:02}:{:02}sec)",
                 hours, minutes, seconds
              );


            if stdout.write_all(msg.as_bytes()).await.is_ok() {
                let _ = stdout.flush().await;
            }

            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    });
    //==============Checking for exist file=====================
    let whitelist_path = "white_list.txt";

    if !std::path::Path::new(whitelist_path).exists() {
        let default_domains = "\
youtube.com
youtu.be
googlevideo.com
ytimg.com
ggpht.com
youtubei.googleapis.com
soundcloud.com
sndcdn.com
discord.com
discord.co
discordstatus.com
discordapp.com
discordapp.net
discord.media
discord.gg
instagram.com
cdninstagram.com
facebook.com
fb.com
fbcdn.net
twitter.com
x.com
twimg.com
t.co
";
        tokio::fs::write(whitelist_path, default_domains).await?;
    }
    //==============Checking for witelist=======================
    let white_list: Vec<String> = fs::read_to_string(whitelist_path)
        .expect("[Error]File white list doesn't exist!")
        .lines()
        .map(|s| s.trim().to_lowercase())
        .filter(|s| !s.is_empty() && !s.starts_with('#'))
        .collect();
    //===============main===============
    loop {
        // Every 10 secs will crean our "pending"
        if last_clean.elapsed() >= Duration::from_secs(10) {
            pending.retain(| _, (created_at, _)| created_at.elapsed() < Duration::from_secs(10));
            last_clean = Instant::now();
        }

        let mut msg: nfq::Message = queue.recv()?;
        let payload = msg.get_payload().to_vec();
        
        let verdict = general(
            &payload, 
            &mut pending, 
            &white_list, 
            split_tunneling_bool
        ).await?;

        msg.set_verdict(verdict);
        queue.verdict(msg)?;
    }
}