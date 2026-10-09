use sysinfo::{ProcessRefreshKind, RefreshKind, System};

pub fn send_ctrl_c() {
    let mut sys = System::new_with_specifics(
        RefreshKind::nothing().with_processes(ProcessRefreshKind::everything())
    );

    sys.refresh_processes(sysinfo::ProcessesToUpdate::All, true);

    for process in sys.processes().values() {
        let name = process.name().to_string_lossy().to_lowercase();

        if name.contains("blinddpi") {
            let raw_pid = process.pid().as_u32();

            let pid = nix::unistd::Pid::from_raw(raw_pid as i32);

            if let Err(e) = nix::sys::signal::kill(pid, nix::sys::signal::Signal::SIGINT) {
                eprint!("Error: {e}");
            }
        }
    }
}