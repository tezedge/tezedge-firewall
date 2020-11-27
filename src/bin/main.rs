//#![forbid(unsafe_code)]

use structopt::StructOpt;
use crypto::proof_of_work::check_proof_of_work;
use xdp_module::{Event, EventInner, BlockingReason, Endpoint};
use redbpf::{
    load::Loader,
    xdp::Flags,
    HashMap,
    Module,
};
use std::{env, fs, io, ptr, sync::Arc, net::{SocketAddr, Ipv4Addr, IpAddr}};
use tokio::{signal, net::UnixListener, stream::{StreamExt, Stream}, sync::Mutex};
use tokio_util::codec::Framed;

use firewall::{CommandDecoder, Command};

#[derive(StructOpt)]
struct Opts {
    #[structopt(
        short,
        long,
        default_value = "enp4s0",
        help = "Interface name to attach the firewall"
    )]
    device: String,
    #[structopt(
        short,
        long,
        help = "Blacklist an IP, currently only v4 supported",
    )]
    blacklist: Vec<String>,
    #[structopt(short, long, default_value = "26.0")]
    target: f64,
    #[structopt(short, long, default_value = "/tmp/tezedge_firewall.sock")]
    socket: String,
}

async fn event_handler<E>(events: E, module: Arc<Mutex<Module>>, target: f64)
where
    E: Unpin + Send + Stream<Item = (String, Vec<Box<[u8]>>)> + 'static,
{
    let mut events = events;
    while let Some((name, events)) = events.next().await {
        for event in events {
            match name.as_str() {
                "events" => {
                    let event = unsafe { ptr::read(event.as_ptr() as *const Event) };
                    println!("{:x?}", &event);

                    let module = module.lock().await;
                    with_map_ref(&module, "blacklist", |map| {
                        let ip = event.pair.remote.ipv4;
                        match &event.event {
                            EventInner::ReceivedPow(b) => match check_proof_of_work(b, target) {
                                Ok(()) => (),
                                Err(()) => block_ip(map, IpAddr::V4(Ipv4Addr::from(ip)), BlockingReason::BadProofOfWork),
                            },
                            EventInner::NotEnoughBytesForPow => {
                                block_ip(map, IpAddr::V4(Ipv4Addr::from(ip)), BlockingReason::BadProofOfWork)
                            },
                            EventInner::BlockedAlreadyConnected { .. } => {
                                block_ip(map, IpAddr::V4(Ipv4Addr::from(ip)), BlockingReason::AlreadyConnected)
                            }
                        }
                    });
                },
                unknown => eprintln!("warning: ignored unknown event: {}", unknown),
            }
        }
    }
}

fn block_ip<'a>(map: HashMap<'a, [u8; 4], u32>, ip: IpAddr, reason: BlockingReason) {
    // TODO: store reason somewhere in userspace
    let _ = reason;
    match ip {
        IpAddr::V4(ip) => map.set(ip.octets(), 0),
        IpAddr::V6(_) => unimplemented!(),
    }
}

fn unblock_ip<'a>(map: HashMap<'a, [u8; 4], u32>, ip: IpAddr) {
    match ip {
        IpAddr::V4(ip) => map.delete(ip.octets()),
        IpAddr::V6(_) => unimplemented!(),
    }
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
    let Opts { device, blacklist, target, socket } = Opts::from_args();

    let code = include_bytes!(concat!(
        env!("OUT_DIR"),
        "/target/bpf/programs/xdp_module/xdp_module.elf"
    ));
    let mut loaded = Loader::load(code).expect("error loading BPF program");
    for kp in loaded.xdps_mut() {
        kp.attach_xdp(device.as_str(), Flags::Unset)
            .expect(&format!("error attaching xdp program {}", kp.name()));
    }

    with_map_ref(&loaded.module, "blacklist", |map| {
        for block in blacklist {
            let ip = block.parse::<Ipv4Addr>().unwrap();
            map.set(ip.octets(), 0);
        }
    });

    let module = Arc::new(Mutex::new(loaded.module));
    let events = loaded.events;
    {
        let module = module.clone();
        tokio::spawn(async move { event_handler(events, module, target).await });
    }

    tokio::spawn(async move {
        fs::remove_file(socket.clone())
            .or_else(|e| {
                if let io::ErrorKind::NotFound = e.kind() {
                    Ok(())
                } else {
                    Err(e)
                }
            })
            .unwrap();
        let mut listener = UnixListener::bind(socket).unwrap();
        loop {
            let (stream, _) = listener.accept().await.unwrap();

            let module = module.clone();
            tokio::spawn(async move {
                let mut command_stream = Framed::new(stream, CommandDecoder);
                while let Some(command) = command_stream.next().await {
                    let module = module.lock().await;
                    // if command is bad, the thread will panic, and sender should reconnect
                    match command.unwrap() {
                        Command::Block(ip) => {
                            with_map_ref(&module, "blacklist", |map| {
                                block_ip(map, ip, BlockingReason::EventFromTezedge)
                            })
                        },
                        Command::Unblock(ip) => {
                            with_map_ref(&module, "blacklist", |map| {
                                unblock_ip(map, ip)
                            })
                        },
                        Command::FilterLocalPort(port) => {
                            with_map_ref::<_, u16, u32>(&module, "node", |map| {
                                map.set(port, 0)
                            })
                        },
                        Command::FilterRemoteAddr(SocketAddr::V4(a)) => {
                            with_map_ref::<_, Endpoint, u32>(&module, "pending_peers", |map| {
                                let endpoint = Endpoint {
                                    ipv4: a.ip().octets(),
                                    port: a.port().to_be_bytes(),
                                };
                                map.set(endpoint, 0)
                            })
                        },
                        Command::Disconnected(SocketAddr::V4(_), pk) => {
                            with_map_ref::<_, [u8; 32], Endpoint>(&module, "peers", |map| {
                                map.delete(pk)
                            })
                        },
                        _ => unimplemented!(),
                    }
                }
            });
        }
    });

    signal::ctrl_c().await.unwrap();
}
