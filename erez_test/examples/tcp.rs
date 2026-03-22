use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

use erez_test::{
    ns::Ns,
    topology::{VethPair, VethPlacement},
};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let client_ns = Ns::net("client").await?;
    let server_ns = Ns::net("server").await?;
    VethPair::new(
        VethPlacement::Addr(client_ns.clone(), "192.168.0.1/24".parse().unwrap()),
        VethPlacement::Addr(server_ns.clone(), "192.168.0.2/24".parse().unwrap()),
    )
    .await?;

    let socket_addr = server_ns
        .spawn(async {
            let listener = TcpListener::bind("192.168.0.2:0").await?;
            let addr = listener.local_addr()?;
            tokio::spawn(async move {
                while let Ok((mut stream, _)) = listener.accept().await {
                    eprintln!("Sent: I like cats!");
                    let _ = stream.write_all(b"I like cats!").await;
                }
            });
            Ok::<_, anyhow::Error>(addr)
        })
        .await??;

    client_ns
        .spawn(async move {
            let mut stream = TcpStream::connect(socket_addr).await?;
            let mut msg = String::new();
            stream.read_to_string(&mut msg).await?;
            eprintln!("Received: {msg}");
            Ok::<_, anyhow::Error>(())
        })
        .await??;

    Ok(())
}
