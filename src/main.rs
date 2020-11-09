//#![forbid(unsafe_code)]

use structopt::StructOpt;
use xdp_module::{Event, Status};

use futures::{stream::{StreamExt, Stream}, channel::mpsc};
use redbpf::{
    load::{Loader, map_io::PerfMessageStream},
    xdp::Flags,
    HashMap,
};
use std::{env, ptr, convert::TryInto};
use tokio::signal;

#[derive(StructOpt)]
struct Opts {
    #[structopt(
        long,
        default_value = "enp4s0",
        help = "Interface name to attach the firewall"
    )]
    device: String,
    #[structopt(short)]
    block: Vec<String>,
}

fn start_event_handler(events: mpsc::UnboundedReceiver<(String, <PerfMessageStream as Stream>::Item)>) {
    tokio::spawn(async move {
        let mut events = events;
        while let Some((name, events)) = events.next().await {
            for event in events {
                match name.as_str() {
                    "events" => {
                        let event = unsafe { ptr::read(event.as_ptr() as *const Event) };
                        println!("{:x?}", event);
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

    start_event_handler(loaded.events);

    let module = loaded.module;
    if let Some(base) = module.maps.iter().find(|m| m.name == "list") {
        let map = HashMap::<[u8; 4], Status>::new(base).unwrap();
        for block in opts.block {
            let block: String = block;
            let ip = block.split('.').map(|s| s.parse::<u8>().unwrap()).rev().collect::<Vec<_>>();
            map.set(ip.try_into().unwrap(), Status::Blocked);
        }
    } else {
        eprintln!("warning: 'list' not found");
    }

    signal::ctrl_c().await.unwrap();
}
