use tezedge_firewall::{firewall, logger};
use structopt::StructOpt;
use procfs::sys::kernel::Version;

#[tokio::main]
async fn main() {
    // safe to unwrap it never returns error
    sudo::escalate_if_needed().unwrap();
    let log = logger();
    match Version::current() {
        Ok(kernel_version) => {
            if kernel_version.major < 5 {
                slog::error!(
                    log,
                    "Kernel version is: {:?}, the minimal required version is {:?}",
                    kernel_version,
                    Version::new(5, 0, 0),
                )
            } else {
                slog::info!(log, "Kernel version is: {:?}", kernel_version);
                firewall(StructOpt::from_args(), log).await            
            }
        },
        Err(err) => {
            slog::error!(log, "Failed to determine kernel version (is it linux?): {:?}", err)
        },
    }
}
