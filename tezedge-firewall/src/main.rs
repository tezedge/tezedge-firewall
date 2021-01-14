use tezedge_firewall::{firewall, logger};
use structopt::StructOpt;

#[tokio::main]
async fn main() {
    let log = logger();
    firewall(StructOpt::from_args(), log).await
}
