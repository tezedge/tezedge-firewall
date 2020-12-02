//#![forbid(unsafe_code)]

use std::{env, fs, io, net::{IpAddr, Ipv4Addr, SocketAddr}, os::unix::fs::PermissionsExt, path::Path, ptr, sync::Arc};
use redbpf::{
    load::Loader,
    xdp::Flags,
    HashMap,
    Module,
};
use tokio::{signal, net::UnixListener, stream::{StreamExt, Stream}, sync::Mutex};
use tokio_util::codec::Framed;
use slog::Drain;
use structopt::StructOpt;

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
                                slog::info!(l, "Received proof of work: {}", hex::encode(b.as_ref()));
                                match check_proof_of_work(b, target) {
                                    Ok(()) => slog::info!(l, "Proof of work is valid, complexity: {}", target),
                                    Err(()) => block_ip(&map, IpAddr::V4(Ipv4Addr::from(ip)), BlockingReason::BadProofOfWork, l),
                                }
                            },
                            EventInner::NotEnoughBytesForPow => {
                                slog::info!(l, "Received proof of work too short");
                                block_ip(&map, IpAddr::V4(Ipv4Addr::from(ip)), BlockingReason::BadProofOfWork, l)
                            },
                            EventInner::BlockedAlreadyConnected { already_connected, try_connect } => {
                                slog::info!(l, "Already connected: {:?}, try connect: {:?}", already_connected, try_connect);
                                block_ip(&map, IpAddr::V4(Ipv4Addr::from(ip)), BlockingReason::AlreadyConnected, l)
                            }
                        }
                    });
                },
                unknown => slog::warn!(l, "Warning: ignored unknown event: {}", unknown),
            }
        }
    }
}

fn block_ip<'a>(map: &HashMap<'a, [u8; 4], u32>, ip: IpAddr, reason: BlockingReason, l: &slog::Logger) {
    // TODO: store reason somewhere in userspace
    slog::info!(l, "Block {}, reason: {:?}", ip, reason);
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

fn remove_socket_path(socket_path: &Path) -> Result<(), io::Error> {
    if socket_path.exists() {
        fs::remove_file(socket_path)?;
    }
    Ok(())
}

/// Need to set "anyone write/read permissions", because we run firewall as sudo, but node should not run with sudo
fn ensure_socket_permissions(socket_path: &Path, log: &slog::Logger) -> Result<(), io::Error> {
    let metadata = fs::metadata(socket_path)?;

    // if not having r/w for anyone, than try to chmod it
    if (metadata.permissions().mode() & 0o666) != 0o666 {
        const REQUIRED_PERMS: i32 = 0o766;
        slog::info!(log, "Changing permission for socket";
                   "socket_path" => socket_path.as_os_str().to_str().unwrap(),
                   "perms" => format!("{:o} -> {:o}", metadata.permissions().mode() & 0o777, REQUIRED_PERMS));
        let file = std::ffi::CString::new(
            socket_path.as_os_str().to_str().unwrap()
        ).expect(&format!("Failed to convert socket_path: {} to CString", socket_path.as_os_str().to_str().unwrap()));

        unsafe {
            let _ = libc::chmod(file.as_ptr(), REQUIRED_PERMS as u32);
        }
    }

    Ok(())
}

#[tokio::main]
async fn main() {
    let Opts { device, blacklist, target, socket } = Opts::from_args();

    let l = logger();

    let code = include_bytes!(concat!(
        env!("OUT_DIR"),
        "/target/bpf/programs/xdp_module/xdp_module.elf"
    ));
    let mut loaded = Loader::load(code).expect("Error loading BPF program");
    for kp in loaded.xdps_mut() {
        kp.attach_xdp(device.as_str(), Flags::Unset)
            .expect(&format!("Error attaching xdp program {}", kp.name()));
        slog::debug!(l, "Loaded xdp program: \"{}\"", kp.name());
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
        // remove existing file
        let socket_path = Path::new(&socket);
        if let Err(e) = remove_socket_path(socket_path) {
            slog::error!(l, "Failed to remove old file for unix domain socket"; "reason" => format!("{}", e));
            panic!("Failed to remove old file for unix domain socket, reason: {}", e)
        }

        // run socket listener
        let mut listener = UnixListener::bind(socket_path).unwrap();

        if let Err(e) = ensure_socket_permissions(&socket_path, &l) {
            slog::error!(l, "Failed to set file permissions for unix domain socket"; "reason" => format!("{}", e), "socket_path" => socket_path.as_os_str().to_str().unwrap());
            panic!("Failed to set file permissions for unix domain socket: \"{}\", reason: {}", socket_path.as_os_str().to_str().unwrap(), e)
        }

        slog::info!(l, "Listening commands on unix domain socket"; "socket_path" => socket_path.as_os_str().to_str().unwrap());
        loop {
            let (stream, _) = listener.accept().await.unwrap();

            let module = module.clone();
            let l = l.clone();
            tokio::spawn(async move {
                let mut command_stream = Framed::new(stream, CommandDecoder);
                while let Some(command) = command_stream.next().await {
                    let module = module.lock().await;
                    // if command is bad, the thread will panic, and sender should reconnect
                    let command = match command {
                        Ok(c) => c,
                        Err(e) => {
                            slog::error!(l, "Failed to receive or parse command: \"{:?}\"", e);
                            continue;
                        },
                    };
                    slog::info!(l, "Received command: \"{:?}\"", command);
                    match command {
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
                        _ => slog::error!(l, "Not implemented yet"),
                    }
                }
            });
        }
    });

    signal::ctrl_c().await.unwrap();
}
