//#![forbid(unsafe_code)]

use structopt::StructOpt;
use xdp_module::PowEvent;

use futures::stream::StreamExt;
use redbpf::{
    load::{Loaded, Loader},
    xdp::Flags,
};
use std::env;
use std::ptr;
use tokio::signal;

#[derive(StructOpt)]
struct Opts {
    #[structopt(
        long,
        default_value = "enp4s0",
        help = "Interface name to attach the firewall"
    )]
    device: String,
}

fn start_event_handler(mut loaded: Loaded) {
    tokio::spawn(async move {
        while let Some((name, events)) = loaded.events.next().await {
            for event in events {
                match name.as_str() {
                    "pow_events" => {
                        let event = unsafe { ptr::read(event.as_ptr() as *const PowEvent) };
                        println!("{:?}", event);
                    },
                    unknown => eprintln!("warning: ignored unknown event: {}", unknown),
                }
            }
        }
    });
}

#[tokio::main]
async fn main() {
    let opts = Opts::from_args();

    let code = include_bytes!(concat!(
        env!("OUT_DIR"),
        "/target/bpf/programs/xdp_module/xdp_module.elf"
    ));
    let mut loaded = Loader::load(code).expect("error loading BPF program");
    for kp in loaded.xdps_mut() {
        kp.attach_xdp(opts.device.as_str(), Flags::Unset)
            .expect(&format!("error attaching xdp program {}", kp.name()));
    }

    start_event_handler(loaded);

    signal::ctrl_c().await.unwrap();
}
