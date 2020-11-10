#![no_std]

#[derive(Debug, Clone)]
pub struct EndpointPair {
    pub remote: Endpoint,
    pub local: Endpoint,
}

#[derive(Clone)]
pub struct Endpoint {
    pub ipv4: [u8; 4],
    pub port: [u8; 2],
}

#[derive(Debug, Clone)]
pub struct Event {
    pub pair: EndpointPair,
    pub new_status: Status,
    pub pow_bytes: PowBytes,
}

#[derive(Clone)]
#[repr(u32)]
pub enum PowBytes {
    Nothing,
    NotEnough,
    Bytes([u8; 56]),
}

#[derive(Debug, Clone, Eq, PartialEq)]
#[repr(u32)]
pub enum Status {
    Allowed,
    Blocked,
}

mod implementations {
    use core::{fmt, convert::{TryFrom, TryInto}};
    use super::{EndpointPair, Endpoint, PowBytes, Event, Status};

    impl From<EndpointPair> for [u8; 12] {
        fn from(v: EndpointPair) -> Self {
            let mut r = [0; 12];
            r[0..6].clone_from_slice(<[u8; 6]>::from(v.local).as_ref());
            r[6..12].clone_from_slice(<[u8; 6]>::from(v.remote).as_ref());
            r
        }
    }

    impl From<[u8; 12]> for EndpointPair {
        fn from(r: [u8; 12]) -> Self {
            EndpointPair {
                local: <[u8; 6]>::try_from(&r[0..6]).unwrap().into(),
                remote: <[u8; 6]>::try_from(&r[6..12]).unwrap().into(),
            }
        }
    }

    impl fmt::Debug for Endpoint {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            let ip = self.ipv4;
            let port = u16::from_le_bytes(self.port);
            write!(f, "{}.{}.{}.{}:{}", ip[3], ip[2], ip[1], ip[0], port)
        }
    }

    impl From<Endpoint> for [u8; 6] {
        fn from(v: Endpoint) -> Self {
            let mut r = [0; 6];
            r[0..4].clone_from_slice(v.ipv4.as_ref());
            r[4..6].clone_from_slice(v.port.as_ref());
            r
        }
    }

    impl From<[u8; 6]> for Endpoint {
        fn from(r: [u8; 6]) -> Self {
            Endpoint {
                ipv4: TryFrom::try_from(&r[0..4]).unwrap(),
                port: TryFrom::try_from(&r[4..6]).unwrap(),
            }
        }
    }

    impl fmt::Debug for PowBytes {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                &PowBytes::Nothing => f.debug_tuple("Nothing").finish(),
                &PowBytes::NotEnough => f.debug_tuple("NotEnough").finish(),
                &PowBytes::Bytes(ref b) => {
                    b.as_ref().into_iter().fold(&mut f.debug_tuple("Bytes"), |d, b| d.field(b)).finish()
                },
            }
        }
    }

    impl From<PowBytes> for [u8; 60] {
        fn from(v: PowBytes) -> Self {
            let mut r = [0; 60];
            match v {
                PowBytes::Nothing => [0; 60],
                PowBytes::NotEnough => {
                    r[0..4].clone_from_slice(1u32.to_le_bytes().as_ref());
                    r
                },
                PowBytes::Bytes(b) => {
                    r[0..4].clone_from_slice(2u32.to_le_bytes().as_ref());
                    r[4..].clone_from_slice(b.as_ref());
                    r
                },
            }
        }
    }

    impl From<[u8; 60]> for PowBytes {
        fn from(r: [u8; 60]) -> Self {
            let d = u32::from_le_bytes(r[0..4].try_into().unwrap());
            match d {
                0 => PowBytes::Nothing,
                1 => PowBytes::NotEnough,
                2 => {
                    let mut b = [0; 56];
                    b.clone_from_slice(&r[4..]);
                    PowBytes::Bytes(b)
                },
                _ => panic!(),
            }
        }
    }

    impl From<Event> for [u8; 76] {
        fn from(v: Event) -> Self {
            let mut r = [0; 76];
            r[0..12].clone_from_slice(<[u8; 12]>::from(v.pair).as_ref());
            r[12..16].clone_from_slice((v.new_status as u32).to_le_bytes().as_ref());
            r[16..76].clone_from_slice(<[u8; 60]>::from(v.pow_bytes).as_ref());
            r
        }
    }

    impl From<[u8; 76]> for Event {
        fn from(r: [u8; 76]) -> Self {
            let mut b = [0; 60];
            b.clone_from_slice(&r[16..76]);
            Event {
                pair: <[u8; 12]>::try_from(&r[0..12]).unwrap().into(),
                new_status: {
                    match u32::from_le_bytes(<[u8; 4]>::try_from(&r[12..16]).unwrap()) {
                        0 => Status::Allowed,
                        1 => Status::Blocked,
                        _ => panic!(),
                    }
                },
                pow_bytes: b.into(),
            }
        }
    }
}
