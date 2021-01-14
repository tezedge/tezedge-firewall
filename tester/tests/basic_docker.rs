use tester::{handshake, Error};

#[tokio::test]
async fn basic_connect() {
    println!("Connect to the node using valid identity");
    match handshake("firewall:9732", "identity_good.json").await {
        Ok(()) => println!("The client successfully done handshake with the remote node"),
        Err(Error::Io(_)) => panic!("The client cannot connect to the remote node"),
        Err(Error::Other(e)) => panic!("{:?}", e),
    }
}

#[tokio::test]
async fn basic_block() {
    println!("Try connect to the node using invalid identity");
    match handshake("firewall:9732", "identity_bad.json").await {
        Ok(()) => panic!("The client successfully done handshake with the remote node"),
        Err(Error::Io(_)) => println!("The client cannot connect to the remote node"),
        Err(Error::Other(e)) => panic!("{:?}", e),
    }
}
