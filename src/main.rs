mod like_main;
use like_main::like_main;

#[tokio::main]
async fn main() {
    tokio::select! {
        _ = like_main() => {

        }
        _ = tokio::signal::ctrl_c() => {

        }
    }
}
