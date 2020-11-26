#![no_std]
#![no_main]

use redbpf_probes::xdp::prelude::*;
use xdp_module::{Endpoint, EndpointPair, Status, Event, EventInner};

program!(0xFFFFFFFE, "GPL");

type MapVoid = u32;

/// buffer for 256 events, should be enough
#[map("events")]
static mut events: PerfMap<Event> = PerfMap::with_max_entries(0x100);

/// limit is 1024 entries
#[map("blacklist")]
static mut blacklist: HashMap<[u8; 4], u32> = HashMap::with_max_entries(0x400);

/// simultaneous 1024 connections maximum
#[map("peers")]
static mut peers: HashMap<[u8; 32], Endpoint> = HashMap::with_max_entries(0x400);

#[map("pending_peers")]
static mut pending_peers: HashMap<Endpoint, MapVoid> = HashMap::with_max_entries(0x400);

#[map("node")]
static mut node: HashMap<u16, MapVoid> = HashMap::with_max_entries(1);

#[map("status")]
static mut status_map: HashMap<EndpointPair, Status> = HashMap::with_max_entries(0x1000);

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

        // check if blacklisted
        if unsafe { blacklist.get(&pair.remote.ipv4) }.is_some() {
            return Ok(XdpAction::Drop);
        }

        // check if ours message
        let incoming = unsafe { node.get(&u16::from_be_bytes(pair.local.port.clone())) }.is_some();
        if !incoming {
            return Ok(XdpAction::Pass);
        }
        let outgoing = unsafe { pending_peers.get(&pair.remote) }.is_some();
        if !outgoing {
            return Ok(XdpAction::Pass);
        }

        // check if packet has payload
        let ethernet_hrd_len = 14usize;
        let ipv4_hrd_len = ((*ipv4).ihl() * 4) as usize;
        let tcp_hrd_len = ((*tcp).doff() * 4) as usize;
        let headers_length = ethernet_hrd_len + ipv4_hrd_len + tcp_hrd_len;
        let has_payload = headers_length < ctx.data_end() - ctx.data_start();
        if !has_payload {
            return Ok(XdpAction::Pass);
        }

        // check if first message of the connection
        let mut status = unsafe { status_map.get(&pair) }.cloned().unwrap_or(Status::empty());
        if status.contains(Status::POW_SENT) {
            return Ok(XdpAction::Pass);
        }
        status.insert(Status::POW_SENT);

        // initialize event structure
        let mut event = Event {
            pair: pair.clone(),
            event: EventInner::ReceivedPow([0; 56]),
        };

        if let Ok(data) = unsafe { ctx.ptr_at::<[u8; 60]>(ctx.data_start() + headers_length) } {
            // first payload is big enough to read proof of work
            let pow_data = &unsafe { &*data }[4..];
            let mut public_key = [0; 32];
            public_key.clone_from_slice(&pow_data[..32]);
            match unsafe { peers.get(&public_key) } {
                // have no such peer connected, let's check its proof of work
                None => {
                    match &mut event.event {
                        &mut EventInner::ReceivedPow(ref mut b) => b.clone_from_slice(pow_data),
                        _ => unreachable!(),
                    }
                    unsafe { peers.set(&public_key, &pair.remote) };
                },
                // have such peer connected, let's ban him
                Some(endpoint) => {
                    event.event = EventInner::BlockedReusingPow {
                        already_connected: endpoint.clone(),
                        try_connect: pair.remote.clone(),
                    };
                    status.insert(Status::BLOCKED);
                },
            }
            
        } else {
            // first payload is too small, should not happens
            event.event = EventInner::NotEnoughBytesForPow;
            status.insert(Status::BLOCKED);
        }

        unsafe {
            status_map.set(&pair, &status);
            events.insert(&ctx, &MapData::new(event));
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
