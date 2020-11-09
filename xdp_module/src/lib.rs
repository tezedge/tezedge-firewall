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
}

#[derive(Debug, Clone, Eq, PartialEq)]
#[repr(u32)]
pub enum Status {
    Allowed,
    Blocked,
}

mod implementations {
    use core::{fmt, convert::TryFrom};
    use super::{EndpointPair, Endpoint};

    impl From<EndpointPair> for [u8; 12] {
        fn from(v: EndpointPair) -> Self {
            let mut r = [0; 12];
            r[0..6].clone_from_slice(<[u8; 6]>::from(v.local).as_ref());
            r[6..12].clone_from_slice(<[u8; 6]>::from(v.remote).as_ref());
            r
        }
    }

    impl From<[u8; 20]> for EndpointPair {
        fn from(r: [u8; 20]) -> Self {
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
}
