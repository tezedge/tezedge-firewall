#![no_std]
#![no_main]

use redbpf_probes::xdp::prelude::*;
use xdp_module::{Endpoint, EndpointPair, Event, Status, PowBytes};

program!(0xFFFFFFFE, "GPL");

#[map("events")]
static mut events: PerfMap<Event> = PerfMap::with_max_entries(0x100);

#[map("blacklist")]
static mut blacklist: HashMap<[u8; 4], Status> = HashMap::with_max_entries(0x100);

#[map("whitelist")]
static mut whitelist: HashMap<Endpoint, u32> = HashMap::with_max_entries(0x100);

#[map("status")]
static mut status_map: HashMap<EndpointPair, Status> = HashMap::with_max_entries(0x10000);

#[inline(always)]
fn whitelisted(endpoint: &Endpoint) -> bool {
    let temp = Endpoint {
        ipv4: [0, 0, 0, 0],
        port: endpoint.port,
    };
    if unsafe { whitelist.get(&temp).is_some() } {
        return true;
    }

    let temp = Endpoint {
        ipv4: endpoint.ipv4,
        port: [0, 0],
    };
    if unsafe { whitelist.get(&temp).is_some() } {
        return true;
    }

    unsafe { whitelist.get(endpoint).is_some() }
}

#[xdp]
pub fn firewall(ctx: XdpContext) -> XdpResult {
    if let (Ok(Transport::TCP(tcp)), Ok(ipv4)) = (ctx.transport(), ctx.ip()) {
        // TODO: handle ipv6
        let ipv4 = unsafe { &*ipv4 };
        let tcp = unsafe { &*tcp };

        let pair = EndpointPair {
            remote: Endpoint {
                ipv4: ipv4.saddr.to_le_bytes(),
                port: tcp.source.to_le_bytes(),
            },
            local: Endpoint {
                ipv4: ipv4.daddr.to_le_bytes(),
                port: tcp.dest.to_le_bytes(),
            },
        };

        if whitelisted(&pair.remote) {
            return Ok(XdpAction::Pass);
        }

        // retrieve the status for given remote ip
        let mut status = match unsafe { blacklist.get(&pair.remote.ipv4) } {
            Some(st) => st.clone(),
            _ => Status::empty(),
        };

        let mut pow_bytes = PowBytes::Bytes([0; 56]);
        if !status.contains(Status::POW_SENT) {
            let headers_length = 14 + (((*ipv4).ihl() * 4) as usize) + (((*tcp).doff() * 4) as usize);
            if headers_length < ctx.data_end() - ctx.data_start() {
                let offset = ctx.data_start() + headers_length;
                if let Ok(data) = unsafe { ctx.ptr_at::<[u8; 60]>(offset) } {
                    let data = &unsafe { &*data }[4..];
                    match &mut pow_bytes {
                        &mut PowBytes::Bytes(ref mut b) => b.clone_from_slice(data),
                        _ => unreachable!(),
                    }
                } else {
                    pow_bytes = PowBytes::NotEnough;
                }
                status.set(Status::POW_SENT, true);
            } else {
                pow_bytes = PowBytes::Nothing;
            }
        } else {
            pow_bytes = PowBytes::Nothing;
        }

        unsafe {
            match status_map.get(&pair) {
                // status is the same, do nothing
                Some(st) if status.eq(st) => (),
                // status is changed, update status in status map and notify the userspace
                _ => {
                    blacklist.set(&pair.remote.ipv4, &status);
                    status_map.set(&pair, &status);
                    let event = Event {
                        pair: pair,
                        new_status: status.clone(),
                        pow_bytes: pow_bytes,
                    };
                    events.insert(&ctx, &MapData::new(event));
                }
            }
        }

        if status.contains(Status::BLOCKED) {
            Ok(XdpAction::Drop)
        } else {
            Ok(XdpAction::Pass)
        }
    } else {
        // not TCP
        Ok(XdpAction::Pass)
    }
}
