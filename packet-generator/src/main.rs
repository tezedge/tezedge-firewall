use std::{io, net::SocketAddr};
use structopt::StructOpt;
use tokio::{net::TcpStream, io::AsyncWriteExt};

#[derive(StructOpt)]
struct Opts {
    #[structopt(long, help = "Address at the tap interface")]
    address: SocketAddr,
}

#[tokio::main]
async fn main() -> Result<(), io::Error> {
    let Opts { address } = Opts::from_args();

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
