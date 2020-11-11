//#![forbid(unsafe_code)]

use structopt::StructOpt;
use crypto::proof_of_work::check_proof_of_work;
use xdp_module::{Event, Status, PowBytes};
use futures::{stream::StreamExt};
use redbpf::{
    load::{Loader, Loaded},
    xdp::Flags,
    HashMap,
    Module,
};
use std::{env, ptr};
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

fn start_event_handler(loaded: Loaded) {
    tokio::spawn(async move {
        let mut events = loaded.events;
        while let Some((name, events)) = events.next().await {
            for event in events {
                match name.as_str() {
                    "events" => {
                        let event = unsafe { ptr::read(event.as_ptr() as *const Event) };
                        println!("{:x?}", event);

                        with_map_ref(&loaded.module, "list", |map| {
                            match &event.pow_bytes {
                                PowBytes::Nothing => (),
                                PowBytes::NotEnough => map.set(event.pair.remote.ipv4.clone(), Status::BLOCKED),
                                PowBytes::Bytes(b) => match check_proof_of_work(b, 26.0) {
                                    Ok(()) => (),
                                    Err(()) => map.set(event.pair.remote.ipv4.clone(), Status::BLOCKED),
                                },
                            }
                        });
                    },
                    unknown => eprintln!("warning: ignored unknown event: {}", unknown),
                }
            }
        }
    });
}

fn with_map_ref<'a, 'b, F, K, V>(module: &'a Module, name: &'b str, f: F)
where
    F: FnOnce(HashMap<'a, K, V>),
    K: Clone,
    V: Clone,
{
    if let Some(base) = module.maps.iter().find(|m| m.name == name) {
        let map = HashMap::new(base).unwrap();
        f(map)
    } else {
        panic!("{} not found", name)
    }
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

    with_map_ref(&loaded.module, "list", |map| {
        for block in opts.block {
            let block: String = block;
            let mut ip = [0, 0, 0, 0];
            for (i, b) in block.split('.').map(|s| s.parse::<u8>().unwrap()).rev().enumerate() {
                ip[i] = b;
            }
            map.set(ip, Status::BLOCKED);
        }
    });

    start_event_handler(loaded);

    signal::ctrl_c().await.unwrap();
}
