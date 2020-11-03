#![no_std]
#![no_main]

use redbpf_probes::xdp::prelude::*;
use redbpf_probes::{bindings, helpers};
use xdp_module::{Endpoint, EndpointPair, PowEvent, ConnectionState, Validity};
use blake2::{
    Blake2b,
    digest::{
        Digest, FixedOutputDirty,
        generic_array::{GenericArray, typenum},
    },
};

program!(0xFFFFFFFE, "GPL");

#[map("pow_events")]
static mut pow_events: PerfMap<PowEvent> = PerfMap::with_max_entries(0x100);

#[map("connections")]
static mut connections: HashMap<EndpointPair, ConnectionState> = HashMap::with_max_entries(0x100);

#[map("hasher_state")]
static mut hasher_state: bindings::bpf_map_def = bindings::bpf_map_def {
    type_: bindings::bpf_map_type_BPF_MAP_TYPE_ARRAY,
    key_size: core::mem::size_of::<u32>() as u32,
    value_size: core::mem::size_of::<Blake2b>() as u32,
    max_entries: 1,
    map_flags: 0,
};

#[xdp]
pub fn firewall(ctx: XdpContext) -> XdpResult {
    if let (Ok(Transport::TCP(tcp_ptr)), Ok(ipv4)) = (ctx.transport(), ctx.ip()) {
        // TODO: handle ipv6
        let ipv4 = unsafe { &*ipv4 };
        let tcp = unsafe { &*tcp_ptr };

        let pair = EndpointPair {
            source: Endpoint {
                ipv4: ipv4.saddr.to_be_bytes(),
                port: tcp.source.to_be_bytes(),
            },
            destination: Endpoint {
                ipv4: ipv4.daddr.to_be_bytes(),
                port: tcp.dest.to_be_bytes(),
            },
        };

        let headers_length = 14 + (((*ipv4).ihl() * 4) as usize) + (((*tcp).doff() * 4) as usize);

        if tcp.syn() != 0 {
            let event = PowEvent {
                pair: pair,
                valid: Validity::NotChecked,
            };
            unsafe { pow_events.insert(&ctx, &MapData::new(event)) };
        } else {
            if let Some(_c) = unsafe { connections.get_mut(&pair) } {
            } else {
                let mut valid = false;
                if headers_length + 60 <= ctx.data_end() - ctx.data_start() {
                    let offset = ctx.data_start() + headers_length;
                    if let Ok(data) = unsafe { ctx.ptr_at::<[u8; 60]>(offset) } {
                        let data = unsafe { &*data };

                        let hash_full = unsafe {
                            let mut full = GenericArray::<u8, typenum::U64>::default();

                            let key = 0;
                            let state = unsafe {
                                helpers::bpf_map_update_elem(
                                    &mut hasher_state as *mut _ as *mut c_void,
                                    &key as *const _ as *const c_void,
                                    &Blake2b::default() as *const _ as *const c_void,
                                    bindings::BPF_ANY.into(),
                                );

                                let st = helpers::bpf_map_lookup_elem(
                                    &mut hasher_state as *mut _ as *mut c_void,
                                    &key as *const _ as *const c_void,
                                ) as *mut Blake2b;
                                &mut *st
                            };

                            state.update(&data[4..60]);
                            state.finalize_into_dirty(&mut full);
                            full
                        };

                        // 3 bytes = 24 bits, pow complexity is 24,
                        // TODO: make complexity configurable
                        valid =
                            hash_full[0x1f] == 0 && hash_full[0x1e] == 0 && hash_full[0x1d] == 0;
                    }
                }

                let state = ConnectionState {
                    valid,
                    padding: [0; 3],
                };
                unsafe { connections.set(&pair, &state) };

                let event = PowEvent {
                    pair: pair,
                    valid: if valid {
                        Validity::Valid
                    } else {
                        Validity::Invalid
                    },
                };
                unsafe { pow_events.insert(&ctx, &MapData::new(event)) };
            }
        }
    }

    Ok(XdpAction::Pass)
}
