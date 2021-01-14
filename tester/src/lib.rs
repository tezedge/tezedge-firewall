use std::{
    io::{self, Read},
    convert::TryFrom,
    fs::File,
};
use tokio::{
    net::TcpStream,
    io::{AsyncWriteExt, AsyncReadExt},
};
use tezos_messages::p2p::{
    encoding::{
        connection::ConnectionMessage, version::NetworkVersion,
        metadata::MetadataMessage,
        //ack::AckMessage,
    },
    binary_message::{BinaryMessage, BinaryChunk},
};
use crypto::{
    crypto_box::{PrecomputedKey, precompute, encrypt, decrypt},
    nonce::{NoncePair, generate_nonces},
};
use tezos_identity::Identity;

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    Other(Box<dyn std::error::Error>),
}

impl From<io::Error> for Error {
    fn from(v: io::Error) -> Self {
        Error::Io(v)
    }
}

/*#[tokio::main]
async fn main() -> Result<(), io::Error> {
    let Opts { address, identity } = StructOpt::from_args();

    match handshake(address, identity).await {
        Ok(()) => println!("The client successfully done handshake with the remote node"),
        Err(Error::Io(_)) => println!("The client cannot connect to the remote node"),
        Err(Error::Other(e)) => println!("{:?}", e),
    }

    Ok(())
}*/

pub async fn handshake(address: &str, identity_path: &str) -> Result<(), Error> {
    let mut identity_file = File::open(identity_path.clone())?;
    let mut identity_json = String::new();
    identity_file.read_to_string(&mut identity_json)?;
    let identity = Identity::from_json(&identity_json).map_err(|e| Error::Other(e.into()))?;

    let mut s = TcpStream::connect(address.clone()).await?;

    println!(
        "Try handshake, identity_path: {}, our address: {}, node address: {}...",
        identity_path,
        s.local_addr()?,
        s.peer_addr()?,
    );

    let mut decipher = connection(&mut s, identity).await?;
    let m = MetadataMessage::new(false, false);
    write_message(&mut decipher, &mut s, &[m]).await?;
    let _ = read_message::<_, MetadataMessage>(&mut decipher, &mut s).await?;
    //let m = AckMessage::Ack;
    //write_message(&mut decipher, &mut s, &[m]).await?;
    //let _ = read_message::<_, AckMessage>(&mut decipher, &mut s).await?;

    Ok(())
}

pub struct Decipher {
    key: PrecomputedKey,
    nonce: NoncePair,
}

async fn connection(stream: &mut TcpStream, identity: Identity) -> Result<Decipher, Error> {
    let chain_name = "TEZOS_ALPHANET_CARTHAGE_2019-11-28T13:02:13Z".to_string();
    let version = NetworkVersion::new(chain_name, 0, 1);
    let connection_message = ConnectionMessage::new(
        0,
        &identity.public_key,
        &identity.proof_of_work_stamp,
        rand::random::<[u8; 24]>().as_ref(),
        vec![version],
    );
    let chunk = connection_message
        .as_bytes()
        .map_err(|e| Error::Other(e.into()))?;
    let initiator_chunk = BinaryChunk::from_content(chunk.as_ref()).unwrap();
    stream.write_all(initiator_chunk.raw()).await?;

    let mut size_buf = [0; 2];
    stream.read_exact(size_buf.as_mut()).await?;
    let size = u16::from_be_bytes(size_buf) as usize;
    let mut chunk = vec![0; size + 2];
    chunk[..2].clone_from_slice(size_buf.as_ref());
    stream.read_exact(&mut chunk[2..]).await?;
    let responder_chunk = BinaryChunk::try_from(chunk).unwrap();

    Ok(Decipher {
        key: precompute(&hex::encode(&responder_chunk.raw()[4..36]), &identity.secret_key)
            .map_err(|e| Error::Other(e.into()))?,
        nonce: generate_nonces(initiator_chunk.raw(), responder_chunk.raw(), false),
    })
}

async fn write_message<T, M>(
    decipher: &mut Decipher,
    stream: &mut T,
    messages: &[M],
) -> Result<(), Error>
where
    T: Unpin + AsyncWriteExt,
    M: BinaryMessage,
{
    pub const CONTENT_LENGTH_MAX: usize = tezos_messages::p2p::binary_message::CONTENT_LENGTH_MAX
        - crypto::crypto_box::BOX_ZERO_BYTES;

    let mut chunks = Vec::new();
    for message in messages {
        let bytes = message
            .as_bytes()
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "Encoding error"))?;
        for plain in bytes.chunks(CONTENT_LENGTH_MAX) {
            let chunk = encrypt(plain, &decipher.nonce.local, &decipher.key)
                .map_err(|e| Error::Other(format!("{:?}", e).into()))
                .map(|v| BinaryChunk::from_content(v.as_ref()).unwrap())?;
            decipher.nonce.local.increment();
            chunks.extend_from_slice(chunk.raw());
        }
    }
    stream.write_all(chunks.as_ref()).await?;
    Ok(())
}

async fn read_message<T, M>(decipher: &mut Decipher, stream: &mut T) -> Result<M, Error>
where
    T: Unpin + AsyncReadExt,
    M: BinaryMessage,
{
    let mut chunk_raw = [0; 0x10000];
    let read = stream.read(chunk_raw.as_mut()).await?;

    if read == 0 {
        return Err(Error::Io(io::Error::new(io::ErrorKind::UnexpectedEof, "")));
    }
    let bytes = decrypt(&chunk_raw[2..read], &decipher.nonce.remote, &decipher.key)
        .map_err(|e| Error::Other(format!("{:?}", e).into()))?;
    decipher.nonce.remote.increment();

    let message = M::from_bytes(bytes).map_err(|e| Error::Other(format!("{:?}", e).into()))?;

    Ok(message)
}
