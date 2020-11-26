use std::{net::{IpAddr, SocketAddr, AddrParseError}, io, string::ToString};
use serde::{Deserialize, Serialize};
use tokio_util::codec::Decoder;
use bytes::{BytesMut, Buf};
use tezos_encoding::{
    binary_reader::{BinaryReader, BinaryReaderError},
    binary_writer,
    de,
    ser,
    has_encoding,
    encoding::{Encoding, HasEncoding, Tag, TagMap, Field},
};

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum Command {
    Block(IpAddr),
    Unblock(IpAddr),
    FilterLocalPort(u16),
    FilterRemoteAddr(SocketAddr),
    Disconnected(SocketAddr, [u8; 32]),
}

#[derive(Debug)]
pub enum Error {
    WrongTag(u8),
    AddrParse(AddrParseError),
    Io(io::Error),
    Deserialization(de::Error),
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::Io(e)
    }
}

impl Command {
    fn from_inner(inner: CommandInner) -> Result<Self, Error> {
        Ok(match inner {
            CommandInner::Block(s) => Command::Block(s.parse().map_err(Error::AddrParse)?),
            CommandInner::Unblock(s) => Command::Unblock(s.parse().map_err(Error::AddrParse)?),
            CommandInner::FilterLocalPort(p) => Command::FilterLocalPort(p),
            CommandInner::FilterRemoteAddr(s) => Command::FilterRemoteAddr(s.parse().map_err(Error::AddrParse)?),
            CommandInner::Disconnected(Disconnected {
                address,
                public_key,
            }) => Command::Disconnected(address.parse().map_err(Error::AddrParse)?, public_key),
        })
    }

    pub fn as_bytes(&self) -> Result<Vec<u8>, ser::Error> {
        let inner = match self {
            Command::Block(s) => CommandInner::Block(s.to_string()),
            Command::Unblock(s) => CommandInner::Unblock(s.to_string()),
            Command::FilterLocalPort(p) => CommandInner::FilterLocalPort(*p),
            Command::FilterRemoteAddr(s) => CommandInner::FilterRemoteAddr(s.to_string()),
            Command::Disconnected(s, public_key) => CommandInner::Disconnected(Disconnected {
                address: s.to_string(),
                public_key: public_key.clone(),
            }),
        };
        binary_writer::write(&inner, &CommandInner::encoding())
    }
}

#[derive(Deserialize, Serialize)]
enum CommandInner {
    Block(String),
    Unblock(String),
    FilterLocalPort(u16),
    FilterRemoteAddr(String),
    Disconnected(Disconnected),
}

#[derive(Deserialize, Serialize)]
struct Disconnected {
    address: String,
    public_key: [u8; 32],
}

has_encoding!(CommandInner, COMMAND_ENCODING, {
    Encoding::Tags(
        std::mem::size_of::<u8>(),
        TagMap::new(vec![
            Tag::new(0x01, "Block", Encoding::String),
            Tag::new(0x02, "Unblock", Encoding::String),
            Tag::new(0x03, "FilterLocalPort", Encoding::Uint16),
            Tag::new(0x04, "FilterRemoteAddr", Encoding::String),
            Tag::new(0x05, "Disconnected", Encoding::Obj(vec![
                Field::new("address", Encoding::String),
                Field::new("public_key", Encoding::sized(32, Encoding::Bytes)),
            ])),
        ]),
    )
});

pub struct CommandDecoder;

impl Decoder for CommandDecoder {
    type Item = Command;
    type Error = Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        let len = src.len();
        match BinaryReader::new().read(&src, &CommandInner::encoding()) {
            Ok(value) => {
                src.advance(len);
                de::from_value(&value)
                    .map_err(|e| match e {
                        BinaryReaderError::DeserializationError { error } => Error::Deserialization(error),
                        _ => unreachable!(),
                    })
                    .and_then(Command::from_inner)
                    .map(Some)
            },
            Err(BinaryReaderError::Overflow { bytes }) => {
                let mut data = src.split_to(len - bytes);
                self.decode(&mut data)
            },
            Err(BinaryReaderError::Underflow { .. }) => Ok(None),
            Err(BinaryReaderError::DeserializationError { error }) => 
                Err(Error::Deserialization(error)),
            Err(BinaryReaderError::UnsupportedTag { tag }) =>
                Err(Error::WrongTag(tag as u8)),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{net::{Ipv4Addr, IpAddr}, convert::TryFrom};
    use bytes::BytesMut;
    use tokio_util::codec::Decoder;
    use super::{CommandDecoder, Command};

    #[test]
    fn basic() {
        let mut data = vec![1, 0, 0, 0, 9];
        data.extend_from_slice(b"127.0.0.1");
    
        // correct
        let mut b = BytesMut::from(data.as_slice());
        let c = CommandDecoder.decode(&mut b);
        assert_eq!(c.unwrap().unwrap(), Command::Block(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))));
        assert_eq!(b.as_ref(), b"");
    
        // overflow
        data.extend_from_slice(b"overflow");
        let mut b = BytesMut::from(data.as_slice());
        let c = CommandDecoder.decode(&mut b);
        assert_eq!(c.unwrap().unwrap(), Command::Block(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))));
        assert_eq!(b.as_ref(), b"overflow");
    
        let mut data = vec![1, 0, 0, 0, 9];
        data.extend_from_slice(b"127.0.0");
    
        // underflow
        let mut b = BytesMut::from(data.as_slice());
        let c = CommandDecoder.decode(&mut b);
        assert!(c.unwrap().is_none());
        assert_eq!(hex::encode(b.as_ref()), format!("0100000009{}", hex::encode("127.0.0")));
    }
    
    #[test]
    fn disconnected() {
        let mut data = vec![5, 0, 0, 0, 20];
        let addr = "123.145.167.189:1234";
        let pk = b"abcdefghijklmnopqrstuvwxyz012345";
        data.extend_from_slice(addr.as_bytes());
        data.extend_from_slice(pk);

        let mut b = BytesMut::from(data.as_slice());
        let c = CommandDecoder.decode(&mut b);
        assert_eq!(c.unwrap().unwrap(), Command::Disconnected(addr.parse().unwrap(), <&[u8; 32]>::try_from(pk).unwrap().clone()));
        assert_eq!(b.as_ref(), b"");
    }
}
