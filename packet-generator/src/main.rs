use std::{io, convert::TryFrom};
use structopt::StructOpt;
use tokio::{net::TcpStream, io::{AsyncWriteExt, AsyncReadExt}, time};
use tezos_messages::p2p::{
    encoding::{
        connection::ConnectionMessage,
        version::NetworkVersion,
        metadata::MetadataMessage,
    },
    binary_message::{BinaryMessage, BinaryChunk},
};
use tezos_conversation::{Identity, Decipher, NonceAddition};

#[derive(StructOpt)]
struct Opts {
    #[structopt(long, help = "Address at the tap interface")]
    address: String,
}

#[tokio::main]
async fn main() -> Result<(), io::Error> {
    let Opts { address } = Opts::from_args();

    let mut s = loop {
        match TcpStream::connect(address.clone()).await {
            Ok(s) => break s,
            Err(_) => {
                println!("wait 5 seconds");
                let _ = time::sleep(time::Duration::new(5, 0)).await;
            },
        }
    };

    let decipher = handshake(&mut s, "identity_good.json".to_string()).await.unwrap();
    let m = MetadataMessage::new(false, false);
    write_message(&decipher, 0, &mut s, &[m]).await?;

    let mut s = TcpStream::connect(address.clone()).await?;
    let decipher = handshake(&mut s, "identity_bad.json".to_string()).await.unwrap();
    let m = MetadataMessage::new(false, false);
    match write_message(&decipher, 0, &mut s, &[m]).await {
        Ok(()) => println!("FAIL: should be blocked"),
        Err(e) => println!("OK: the message is blocked, error is {:?}", e),
    }

    Ok(())
}

async fn handshake(stream: &mut TcpStream, identity_path: String) -> Result<Decipher, io::Error> {
    let identity = Identity::from_path(identity_path).unwrap();

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
        .map_err(|_| io::Error::new(io::ErrorKind::Other, "Handshake error"))?;
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

pub async fn write_message<T, M>(
    decipher: &Decipher,
    counter: u64,
    stream: &mut T,
    messages: &[M],
) -> Result<(), io::Error>
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
                .map_err(|_| io::Error::new(io::ErrorKind::Other, "Encryption error"))
                .map(|v| BinaryChunk::from_content(v.as_ref()).unwrap())?;
            chunks.extend_from_slice(chunk.raw());
        }
    }
    stream
        .write_all(chunks.as_ref())
        .await?;
    Ok(())
}
