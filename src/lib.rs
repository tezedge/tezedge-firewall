use std::{net::{IpAddr, SocketAddr, AddrParseError}, io};
use serde::{Deserialize, Serialize};
use tokio_util::codec::Decoder;
use bytes::{BytesMut, Buf};
use tezos_encoding::{
    binary_reader::{BinaryReader, BinaryReaderError},
    de,
    has_encoding,
    encoding::{Encoding, HasEncoding, Tag, TagMap},
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
    Deserialization,
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
            CommandInner::Disconnected(s, pk) => Command::Disconnected(s.parse().map_err(Error::AddrParse)?, pk),
        })
    }
}

#[derive(Deserialize, Serialize)]
enum CommandInner {
    Block(String),
    Unblock(String),
    FilterLocalPort(u16),
    FilterRemoteAddr(String),
    Disconnected(String, [u8; 32]),
}

has_encoding!(CommandInner, COMMAND_ENCODING, {
    Encoding::Tags(
        std::mem::size_of::<u8>(),
        TagMap::new(vec![
            Tag::new(0x01, "Block", Encoding::String),
            Tag::new(0x02, "Unblock", Encoding::String),
            Tag::new(0x03, "FilterLocalPort", Encoding::Uint16),
            Tag::new(0x04, "FilterRemoteAddr", Encoding::String),
            Tag::new(0x05, "Disconnected", Encoding::String),
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
                    .map_err(|_| Error::Deserialization)
                    .and_then(Command::from_inner)
                    .map(Some)
            },
            Err(BinaryReaderError::Overflow { bytes }) => {
                let mut data = src.split_to(len - bytes);
                self.decode(&mut data)
            },
            Err(BinaryReaderError::Underflow { .. }) => Ok(None),
            Err(BinaryReaderError::DeserializationError { .. }) => 
                Err(Error::Deserialization),
            Err(BinaryReaderError::UnsupportedTag { tag }) =>
                Err(Error::WrongTag(tag as u8)),
        }
    }
}

#[cfg(test)]
#[test]
fn basic() {
    use std::net::Ipv4Addr;

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
