use std::io;
use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncWriteExt, AsyncReadExt};
#[tokio::main]
async fn main() -> std::io::Result<()>{
    let connect = TcpListener::bind("127.0.0.1:8080").await?;
    let welcome = "welcome! Write something:\n".as_bytes();

    loop {
        //let (socet, addr) = connect.
        //=============================================
        let mut answ = String::new();
        io::stdin()
            .read_line(&mut answ)
            .unwrap();
        //=============================================

    }
}
async fn send_message(mut socet: TcpStream, text: &str) -> std::io::Result<()> {
    let data = text.as_bytes();
    let len = data.len() as u32;
    let len_bytes = len.to_be_bytes();

    socet.write_all(&len_bytes).await?;
    socet.write_all(&data).await?;
    Ok(())
}
