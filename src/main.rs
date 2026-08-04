use std::{io, net::TcpListener};

#[tokio::main]
async fn main() -> std::io::Result<()>{
    let connect = TcpListener::bind("127.0.0.1:8080").await?;
    let welcome = "welcome! Write something:\n".as_bytes();

    loop {
        let (socet, addr) = connect.
        //=============================================
        let mut answ = String::new();
        io::stdin()
            .read_line(&mut answ)
            .unwrap();
        //=============================================

    }
}