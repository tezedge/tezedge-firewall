use std::{io, convert::TryFrom};
use structopt::StructOpt;
use tokio::{net::TcpStream, io::{AsyncWriteExt, AsyncReadExt}};
use tezos_messages::p2p::{
    encoding::{
        connection::ConnectionMessage,
        version::NetworkVersion,
        metadata::MetadataMessage,
        ack::AckMessage,
    },
    binary_message::{BinaryMessage, BinaryChunk},
};
use tezos_conversation::{Identity, Decipher, NonceAddition};

#[derive(StructOpt)]
struct Opts {
    #[structopt(long, help = "Address at the tap interface")]
    address: String,
    #[structopt(long, help = "Identity json file")]
    identity: String,
}

enum Error {
    Io(io::Error),
    Other(Box<dyn std::error::Error>),
}

impl From<io::Error> for Error {
    fn from(v: io::Error) -> Self {
        Error::Io(v)
    }
}

#[tokio::main]
async fn main() -> Result<(), io::Error> {
    let Opts { address, identity } = StructOpt::from_args();

    match handshake(address, identity).await {
        Ok(()) => println!("Done handshake"),
        Err(Error::Io(_)) => println!("The client cannot connect to the remote node"),
        Err(Error::Other(e)) => println!("{:?}", e),
    }

    Ok(())
}

async fn handshake(address: String, identity_path: String) -> Result<(), Error> {
    let identity = Identity::from_path(identity_path.clone()).unwrap();
    let mut s = TcpStream::connect(address.clone()).await?;

    println!(
        "try handshake, identity_path: {}, attacker_address: {}, node_address: {}",
        identity_path,
        s.local_addr()?,
        s.peer_addr()?,
    );

    let decipher = connection(&mut s, identity).await?;
    let m = MetadataMessage::new(false, false);
    write_message(&decipher, 0, &mut s, &[m]).await?;
    let _ = read_message::<_, MetadataMessage>(&decipher, 0, &mut s).await?;
    let m = AckMessage::Ack;
    write_message(&decipher, 1, &mut s, &[m]).await?;
    let _ = read_message::<_, AckMessage>(&decipher, 1, &mut s).await?;

    Ok(())
}

async fn connection(stream: &mut TcpStream, identity: Identity) -> Result<Decipher, Error> {
    let chain_name = "TEZOS_ALPHANET_CARTHAGE_2019-11-28T13:02:13Z".to_string();
    let version = NetworkVersion::new(chain_name, 0, 1);
    let connection_message = ConnectionMessage::new(
        0,
        &hex::encode(identity.public_key()),
        &hex::encode(identity.proof_of_work()),
        rand::random::<[u8; 24]>().as_ref(),
        vec![version],
    );
    let chunk = connection_message
        .as_bytes()
        .map_err(|e| Error::Other(e.into()))?;
    let initiator_chunk = BinaryChunk::from_content(chunk.as_ref()).unwrap();
    stream
        .write_all(initiator_chunk.raw())
        .await?;

    let mut size_buf = [0; 2];
    stream
        .read_exact(size_buf.as_mut())
        .await?;
    let size = u16::from_be_bytes(size_buf) as usize;
    let mut chunk = vec![0; size + 2];
    chunk[..2].clone_from_slice(size_buf.as_ref());
    stream
        .read_exact(&mut chunk[2..])
        .await?;
    let responder_chunk = BinaryChunk::try_from(chunk).unwrap();

    let decipher = identity
        .decipher(initiator_chunk.raw(), responder_chunk.raw())
        .ok()
        .unwrap();
    Ok(decipher)
}

async fn write_message<T, M>(
    decipher: &Decipher,
    counter: u64,
    stream: &mut T,
    messages: &[M],
) -> Result<(), Error>
where
    T: Unpin + AsyncWriteExt,
    M: BinaryMessage,
{
    pub const CONTENT_LENGTH_MAX: usize =
        tezos_messages::p2p::binary_message::CONTENT_LENGTH_MAX - crypto::crypto_box::BOX_ZERO_BYTES;

    let mut chunks = Vec::new();
    for message in messages {
        let bytes = message.as_bytes()
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "Encoding error"))?;
        for plain in bytes.chunks(CONTENT_LENGTH_MAX) {
            let chunk = decipher
                .encrypt(plain, NonceAddition::Initiator(counter))
                .map_err(|e| Error::Other(format!("{:?}", e).into()))
                .map(|v| BinaryChunk::from_content(v.as_ref()).unwrap())?;
            chunks.extend_from_slice(chunk.raw());
        }
    }
    stream
        .write_all(chunks.as_ref())
        .await?;
    Ok(())
}

async fn read_message<T, M>(
    decipher: &Decipher,
    counter: u64,
    stream: &mut T,
) -> Result<M, Error>
where
    T: Unpin + AsyncReadExt,
    M: BinaryMessage,
{
    let mut size_buf = [0; 2];
    stream
        .read_exact(size_buf.as_mut())
        .await?;
    let size = u16::from_be_bytes(size_buf) as usize;
    let mut chunk = [0; 0x10000];
    stream
        .read_exact(&mut chunk[..size])
        .await?;

    let bytes = decipher.decrypt(&chunk[..size], NonceAddition::Responder(counter))
        .map_err(|e| Error::Other(format!("{:?}", e).into()))?;

    let message = M::from_bytes(bytes)
        .map_err(|e| Error::Other(format!("{:?}", e).into()))?;

    Ok(message)
}
