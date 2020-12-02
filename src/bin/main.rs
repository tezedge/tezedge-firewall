//#![forbid(unsafe_code)]

use std::{env, fs, io, ptr, sync::Arc, net::{SocketAddr, Ipv4Addr, IpAddr}};
use structopt::StructOpt;
use redbpf::{
    load::Loader,
    xdp::Flags,
    HashMap,
    Module,
};
use tokio::{signal, net::UnixListener, stream::{StreamExt, Stream}, sync::Mutex};
use tokio_util::codec::Framed;
use slog::Drain;

use crypto::proof_of_work::check_proof_of_work;
use xdp_module::{Event, EventInner, BlockingReason, Endpoint};
use tezedge_firewall::{CommandDecoder, Command};

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

fn logger() -> slog::Logger {
    let drain = slog_term::FullFormat::new(slog_term::TermDecorator::new().build())
        .build()
        .fuse();
    let drain = slog_async::Async::new(drain)
        .chan_size(0x8000)
        .overflow_strategy(slog_async::OverflowStrategy::Block)
        .build()
        .fuse();
    slog::Logger::root(drain, slog::o!())
}

async fn event_handler<E>(events: E, module: Arc<Mutex<Module>>, target: f64, l: &slog::Logger)
where
    E: Unpin + Send + Stream<Item = (String, Vec<Box<[u8]>>)> + 'static,
{
    let mut events = events;
    while let Some((name, events)) = events.next().await {
        for event in events {
            match name.as_str() {
                "events" => {
                    let event = unsafe { ptr::read(event.as_ptr() as *const Event) };

                    let module = module.lock().await;
                    with_map_ref(&module, "blacklist", |map| {
                        let ip = event.pair.remote.ipv4;
                        match &event.event {
                            EventInner::ReceivedPow(b) => {
                                slog::info!(l, "received proof of work: {}", hex::encode(b));
                                match check_proof_of_work(b, target) {
                                    Ok(()) => slog::info!(l, "proof of work is valid, complexity: {}", target),
                                    Err(()) => block_ip(&map, IpAddr::V4(Ipv4Addr::from(ip)), BlockingReason::BadProofOfWork, l),
                                }
                            },
                            EventInner::NotEnoughBytesForPow => {
                                slog::info!(l, "received proof of work too short");
                                block_ip(&map, IpAddr::V4(Ipv4Addr::from(ip)), BlockingReason::BadProofOfWork, l)
                            },
                            EventInner::BlockedAlreadyConnected { already_connected, try_connect } => {
                                slog::info!(l, "already connected: {}, try connect: {}", already_connected, try_connect);
                                block_ip(&map, IpAddr::V4(Ipv4Addr::from(ip)), BlockingReason::AlreadyConnected, l)
                            }
                        }
                    });
                },
                unknown => slog::error!(l, "warning: ignored unknown event: {}", unknown),
            }
        }
    }
}

fn block_ip<'a>(map: &HashMap<'a, [u8; 4], u32>, ip: IpAddr, reason: BlockingReason, l: &slog::Logger) {
    // TODO: store reason somewhere in userspace
    slog::warn!(l, "block {}, reason: {:?}", ip, reason);
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

    let l = logger();

    let code = include_bytes!(concat!(
        env!("OUT_DIR"),
        "/target/bpf/programs/xdp_module/xdp_module.elf"
    ));
    let mut loaded = Loader::load(code).expect("error loading BPF program");
    for kp in loaded.xdps_mut() {
        kp.attach_xdp(device.as_str(), Flags::Unset)
            .expect(&format!("error attaching xdp program {}", kp.name()));
        slog::debug!(l, "loaded xdp program: \"{}\"", kp.name());
    }

    with_map_ref(&loaded.module, "blacklist", |map| {
        for block in blacklist {
            let ip = block.parse::<IpAddr>().unwrap();
            block_ip(&map, ip, BlockingReason::CommandLineArgument, &l);
        }
    });

    let module = Arc::new(Mutex::new(loaded.module));
    let events = loaded.events;
    {
        let module = module.clone();
        let l = l.clone();
        tokio::spawn(async move { event_handler(events, module, target, &l).await });
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
        let mut listener = UnixListener::bind(socket.clone()).unwrap();
        slog::info!(l, "listening commands on unix domain socket: \"{}\"", socket);
        loop {
            let (stream, _) = listener.accept().await.unwrap();

            let module = module.clone();
            let l = l.clone();
            tokio::spawn(async move {
                let mut command_stream = Framed::new(stream, CommandDecoder);
                while let Some(command) = command_stream.next().await {
                    let module = module.lock().await;
                    slog::info!(l, "received command: \"{:?}\"", command);
                    // if command is bad, the thread will panic, and sender should reconnect
                    match command.unwrap() {
                        Command::Block(ip) => {
                            with_map_ref(&module, "blacklist", |map| {
                                block_ip(&map, ip, BlockingReason::EventFromTezedge, &l)
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
                        _ => slog::error!(l, "not implemented"),
                    }
                }
            });
        }
    });

    signal::ctrl_c().await.unwrap();
}
