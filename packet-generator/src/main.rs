use std::{io, net::SocketAddr};
use structopt::StructOpt;
use tokio::{net::{TcpListener, TcpStream}, io::{AsyncReadExt, AsyncWriteExt}, stream::StreamExt};

#[derive(StructOpt)]
struct Opts {
    #[structopt(long, help = "Address at the tap interface")]
    address: SocketAddr,
}

async fn read_at_tap(s: TcpStream) -> Result<(), io::Error> {
    let mut buf = [0; 0x10000];
    let mut s = s;
    loop {
        match s.read(buf.as_mut()).await {
            Ok(r) => println!("read {} bytes", r),
            Err(e) => if let io::ErrorKind::ConnectionReset = e.kind() {
                break Ok(());
            } else {
                return Err(e);
            }
        }
    }
}

async fn listen_at_tap(address: SocketAddr) -> Result<(), io::Error> {
    let mut l = TcpListener::bind(address).await?;

    while let Some(s) = l.next().await {
        let s = s?;
        tokio::spawn(async move { read_at_tap(s).await.unwrap() });
    }

    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), io::Error> {
    let Opts { address } = Opts::from_args();

    tokio::spawn(async move { listen_at_tap(address.clone()).await.unwrap() });

    let mut s = TcpStream::connect(address).await?;
    let mut b = [0; 0x100];
    let mut i = 0u64;
    while i < u64::MAX - 1 {
        b[0..8].clone_from_slice(i.to_be_bytes().as_ref());
        s.write_all(b.as_ref()).await?;
        i += 1;
    }

    Ok(())
}
