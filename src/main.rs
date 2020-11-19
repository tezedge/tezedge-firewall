//#![forbid(unsafe_code)]

use structopt::StructOpt;
use crypto::proof_of_work::check_proof_of_work;
use xdp_module::{Event, Status, PowBytes};
use redbpf::{
    load::Loader,
    xdp::Flags,
    HashMap,
    Module,
};
use std::{env, ptr, sync::Arc};
use tokio::{signal, net::UnixListener, stream::{StreamExt, Stream}, sync::Mutex, io::AsyncReadExt};

#[derive(StructOpt)]
struct Opts {
    #[structopt(
        long,
        default_value = "enp4s0",
        help = "Interface name to attach the firewall"
    )]
    device: String,
    #[structopt(short, long)]
    block: Vec<String>,
    #[structopt(short, long, default_value = "26.0")]
    target: f64,
    #[structopt(short, long, default_value = "/tmp/tezedge_firewall.sock")]
    socket: String,
}

fn start_event_handler<E>(events: E, module: Arc<Mutex<Module>>, target: f64)
where
    E: Unpin + Send + Stream<Item = (String, Vec<Box<[u8]>>)> + 'static,
{
    tokio::spawn(async move {
        let mut events = events;
        while let Some((name, events)) = events.next().await {
            for event in events {
                match name.as_str() {
                    "events" => {
                        let event = unsafe { ptr::read(event.as_ptr() as *const Event) };
                        println!("{:x?}", &event);

                        let module = module.lock().await;
                        with_map_ref(&module, "list", |map| {
                            match &event.pow_bytes {
                                PowBytes::Nothing => (),
                                PowBytes::NotEnough => block_ip(map, event.pair.remote.ipv4),
                                PowBytes::Bytes(b) => match check_proof_of_work(b, target) {
                                    Ok(()) => (),
                                    Err(()) => block_ip(map, event.pair.remote.ipv4),
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

fn block_ip<'a>(map: HashMap<'a, [u8; 4], Status>, ipv4: [u8; 4]) {
    let mut status = map.get(ipv4)
        .unwrap_or(Status::empty());
    status.set(Status::BLOCKED, true);
    map.set(ipv4, status);
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
    let Opts { device, block, target, socket } = Opts::from_args();

    let code = include_bytes!(concat!(
        env!("OUT_DIR"),
        "/target/bpf/programs/xdp_module/xdp_module.elf"
    ));
    let mut loaded = Loader::load(code).expect("error loading BPF program");
    for kp in loaded.xdps_mut() {
        kp.attach_xdp(device.as_str(), Flags::Unset)
            .expect(&format!("error attaching xdp program {}", kp.name()));
    }

    with_map_ref(&loaded.module, "list", |map| {
        for block in block {
            let block: String = block;
            let mut ip = [0, 0, 0, 0];
            for (i, b) in block.split('.').map(|s| s.parse::<u8>().unwrap()).rev().enumerate() {
                ip[i] = b;
            }
            map.set(ip, Status::BLOCKED);
        }
    });

    let module = Arc::new(Mutex::new(loaded.module));
    start_event_handler(loaded.events, module.clone(), target);

    tokio::spawn(async move {
        let mut listener = UnixListener::bind(socket).unwrap();
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();

            let module = module.clone();
            tokio::spawn(async move {
                // TODO: serde, bincode, deserialize `Command` and execute it
                let mut buffer = [0; 4];
                loop {
                    stream.read_exact(buffer.as_mut()).await.unwrap();
                    let module = module.lock().await;
                    with_map_ref(&module, "list", |map| {
                        // TODO: fix the order properly
                        let ip = [buffer[3], buffer[2], buffer[1], buffer[0]];
                        block_ip(map, ip)
                    })
                }
            });
        }
    });


    signal::ctrl_c().await.unwrap();
}
