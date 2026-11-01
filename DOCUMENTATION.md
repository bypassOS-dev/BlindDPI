# Documentation for BlindDPI (Developers version)

## What does each file in the project do?

### `src/`

- [`main.rs`](#mainrs)
- [`run_blinddpi.rs`](#run_blinddpirs)






















# main.rs
Main.rs - isn't so important. Most important task is **run the graphics** and upon clicking the start-button run function **run_blinddpi.rs** or **reclaim the token** if user clicked stop. 

"What does mean *token*?" u might ask me. I'll tell u:

We have function that run when user click button, yea? So how can we turn off my piece of program that make some with your traffic? Of course, we can just kill process "BlindDPI":

```rust
use sysinfo::{Pid, System};

let mut sys = System::new_all();
sys.refresh_all();

// PID of the process what need to kill (of course not "1234". In real code I would found it PID)
let pid_to_kill = Pid::from(1234);

// Find the process
if let Some(process) = sys.process(pid_to_kill) {
    // Just kill the process
    process.kill()
}
```

Great, yea..? **NO!** Because it would kill and **THE ENTIRE PROGRAM!** Just imagine this: User wanna turn off the program for 5 minutes but because our great(no) solution they would have to restart the app again and again.... **IT'S SOME HORROR!**

So return to **token**! We move it inside **run_blinddpi**. When user click "stop" we send signal to token. Function **run_blinddpi** waiting for this signal (or if user press **ctrl + c** ib terminal) and run another function (**remove_iptables**) that clean all nft rules.



# run_blinddpi.rs

Inside this function happen 5  tings:

- run "**check_iptables.sh**"
- run "**run_iptables**"
- run "**backend**"(well "like_main") in another OS stream
- catch press "**ctrl + c**" or "**stop**" and run "**remove_iptables**" if user's OS is linux

Let's examine each of them:

## check_iptables.sh 

This is bash script that do 1 thing:

Check for the presence of **nfttables** (and download it if user's PC haven't nfttables)!

piece of code from **check_iptables.sh**:
```bash
if command -v nft &> /dev/null; then
    echo "nft is already installed!"
else
    SUCCESSFULLY=false

    echo "nft not found! Installing..."
    # and download it...
```


## run_iptables.sh

FIRST! How work nftables? If u wanna create a rule in nfttables then u must build "russian doll":

--table
      |
      chain
          |
          rule


This is bash script that:

- create a table for nfttables:

```rust
let _add_table_inet = Command::new("/usr/sbin/nft")
    .args(["add", "table", "inet", "blind_dpi"])
    .status()
    .await
    .expect("[ERROR] CRASHED WHEN ADDIND THE RULE!");
```

What is table at nfttables?  It's container where all else will stored. "inet" (in this code) mean what what everything else will work with IPv4 and IPv6.


- create a chain for nfttables:

```rust
let _chain = Command:: new("/usr/sbin/nft")
    .args(["add", "chain", "inet", "blind_dpi", "output", "{ type filter hook output priority 0; }"])
    .status()
    .await
    .expect ("[ERROR] CRASHED WHEN CREATED A CHAIN!");
```

In this code we force linux route ALL PACKETS (which computer wanna send to network) to us. 


- create a rule for nfttables:

```rust 
// Here we will create a rule that "say" OS route all packets 
// which come from 433 port (https) to queue number 0:
let _rule = Command::new("/usr/sbin/nft")
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
```


## Backend (linux::like_main())

> Windows version isn't supporting yet, so I will tell u about linux version 🐧



