# Documentation for BlindDPI (Developers version)

## What does each file in the project do?

### `src/`

- [`main.rs`](#mainrs)
- [`run_blinddpi.rs`](#runblinddpirs)






















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
- catch press "**ctrl + c**" or "**stop**" and run "**remove_iptables**" is user's OS is linux
