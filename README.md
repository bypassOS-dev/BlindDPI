# BlindDPI

**BlindDPI** is a high-performance Rust utility designed to bypass Deep Packet Inspection (DPI) systems using TLS `ClientHello` fragmentation and SNI spoofing / TTL packet manipulation at the network layer via `NFQUEUE`.

The tool analyzes incoming/outgoing traffic, extracts Server Name Indication (SNI) hostnames from TLS handshakes, and performs selective split-tunneling based on a customizable whitelist.

## 📋 Prerequisites

* **OS:** Linux (Kernel $\ge 5.0$)
* **Dependencies:**
* `iptables`
* `libnetfilter_queue` (Debian/Ubuntu: `sudo apt install libnetfilter-queue-dev build-essential`)


* **Privileges:** `root` access (required for raw sockets and `iptables` manipulation).

---

## 🛠️ Build & Installation

1. Clone the repository:
```bash
git clone https://github.com/bypassOS-dev/BlindDPI.git
cd BlindDPI
```


2. Compile the binary using `cargo`:
```bash
cargo build --release
```


The output binary will be located at `./target/release/BlindDPI`.

---

## ⚙️ Configuration (`white_list.txt`)

Also you can change domain list and add some `domain that is need you`! (supports comments using `#` and empty lines):

```text
# New domain:
example.com
my_site.com
some_site.com
```

---

## Usage

Run the compiled binary with elevated privileges:

```bash
sudo ./target/release/BlindDPI

```

To stop the program, press **`Ctrl+C`**. BlindDPI will automatically flush the applied `iptables` rules and perform a clean exit.

> [!IMPORTANT]
> But if something went wrong use this command:
> ```bash
> sudo iptables -D OUTPUT -p tcp --dport 443 -j NFQUEUE --queue-num 0
> ```
---

> ### 💬 A Note from the Author
> 
> Thank you for downloading and using **BlindDPI**! This project was built with a lot of passion for low-level networking, performance, and digital freedom.
> 
> *Blazingly fast & built with love in Rust.* 🦀✨
> 
> Found a bug, or have an idea to improve it? Feel free to open an **Issue** or submit a **Pull Request**! Any feedback and contributions are greatly appreciated.
> 
> If you find this tool helpful, don't forget to give it a ⭐ on GitHub!
