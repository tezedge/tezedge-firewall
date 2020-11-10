#![no_std]
#![no_main]

use redbpf_probes::xdp::prelude::*;
use xdp_module::{Endpoint, EndpointPair, Event, Status, PowBytes};

program!(0xFFFFFFFE, "GPL");

#[map("events")]
static mut events: PerfMap<Event> = PerfMap::with_max_entries(0x100);

#[map("list")]
static mut list: HashMap<[u8; 4], Status> = HashMap::with_max_entries(0x100);

#[map("status")]
static mut status_map: HashMap<EndpointPair, Status> = HashMap::with_max_entries(0x10000);

#[xdp]
pub fn firewall(ctx: XdpContext) -> XdpResult {
    if let (Ok(Transport::TCP(tcp_ptr)), Ok(ipv4)) = (ctx.transport(), ctx.ip()) {
        // TODO: handle ipv6
        let ipv4 = unsafe { &*ipv4 };
        let tcp = unsafe { &*tcp_ptr };

        let pair = EndpointPair {
            remote: Endpoint {
                ipv4: ipv4.saddr.to_be_bytes(),
                port: tcp.source.to_be_bytes(),
            },
            local: Endpoint {
                ipv4: ipv4.daddr.to_be_bytes(),
                port: tcp.dest.to_be_bytes(),
            },
        };

        let headers_length = 14 + (((*ipv4).ihl() * 4) as usize) + (((*tcp).doff() * 4) as usize);

        let mut pow_bytes = PowBytes::Bytes([0; 56]);
        if headers_length < ctx.data_end() - ctx.data_start() {
            let offset = ctx.data_start() + headers_length;
            if let Ok(data) = unsafe { ctx.ptr_at::<[u8; 60]>(offset) } {
                let data = &unsafe { &*data }[4..];
                match &mut pow_bytes {
                    &mut PowBytes::Bytes(ref mut b) => b.clone_from_slice(data),
                    _ => unreachable!(),
                }
            } else {
                pow_bytes = PowBytes::NotEnough
            }
        } else {
            pow_bytes = PowBytes::Nothing
        };

        // retrieve the status for given remote ip
        let status = match unsafe { list.get(&pair.remote.ipv4) } {
            Some(st) => st.clone(),
            // it is blacklist, allow if nothing in the list
            _ => Status::Allowed,
        };

        unsafe {
            match status_map.get(&pair) {
                // status is the same, do nothing
                Some(st) if status.eq(st) => (),
                // status is changed, update status in status map and notify the userspace
                _ => {
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

        match status {
            Status::Allowed => Ok(XdpAction::Pass),
            Status::Blocked => Ok(XdpAction::Drop),
        }
    } else {
        // not TCP
        Ok(XdpAction::Pass)
    }
}
