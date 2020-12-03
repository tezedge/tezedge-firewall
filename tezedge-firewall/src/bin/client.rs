#![forbid(unsafe_code)]

use std::net::IpAddr;
use structopt::StructOpt;
use tokio::{io::AsyncWriteExt, net::UnixStream};
use tezedge_firewall_command::Command;

#[derive(StructOpt)]
struct Opts {
    #[structopt(short, long, default_value = "/tmp/tezedge_firewall.sock")]
    socket: String,
    #[structopt(subcommand)]
    cmd: Cmd,
}

#[derive(StructOpt)]
enum Cmd {
    Block {
        addr: IpAddr,
    },
    Unblock {
        addr: IpAddr,
    },
    Node {
        port: u16,
    },
}

#[tokio::main]
async fn main() {
    let Opts { socket, cmd } = Opts::from_args();

    let mut control = UnixStream::connect(socket).await.unwrap();
    let command = match cmd {
        Cmd::Block { addr } => Command::Block(addr),
        Cmd::Unblock { addr } => Command::Unblock(addr),
        Cmd::Node { port } => Command::FilterLocalPort(port),
    };
    control.write_all(command.as_bytes().unwrap().as_ref()).await.unwrap();
}
