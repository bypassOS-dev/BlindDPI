use std::io;
use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncWriteExt, AsyncReadExt};
#[tokio::main]
async fn main() -> std::io::Result<()>{
    let connect = TcpListener::bind("127.0.0.1:8080").await?;
    let welcome = "welcome! Write something:\n".as_bytes();

    loop {
        let (mut socet, addr) = connect.accept().await?;
        //=============================================
        tokio::spawn(async move {
            //========================================================
            let mut answ = String::new();
            io::stdin()
                .read_line(&mut answ)
                .unwrap();
            //========================================================
            send_message(socet, &answ).await.unwrap();
        });
    }
    let text = recive_fn(socet).await?;
    println!("{text}");
}
async fn send_message(mut socet: TcpStream, text: &str) -> std::io::Result<()> {
    let data = text.as_bytes();
    let len = data.len() as u32;
    let len_bytes = len.to_be_bytes();

    socet.write_all(&len_bytes).await?;
    socet.write_all(&data).await?;
    Ok(())
}
async fn recive_fn(mut socet: &mut TcpStream) -> std::io::Result<String>{
    let mut len_bytes = [0u8; 4];
    socet.read_exact(&mut len_bytes).await?;
    let len = u32::from_be_bytes(len_bytes) as usize;

    let mut bufer = vec![0u8;len];
    socet.read_exact(&mut bufer).await?;

    let text = String::from_utf8_lossy(&bufer).to_string();

    Ok(text)
}
