use tezedge_firewall::{firewall, logger, Opts};

#[tokio::test]
async fn basic() {
    tokio::spawn(async {
        let opts = Opts {
            device: "eth0".to_string(),
            blacklist: vec![],
            target: 26.0,
            socket: "/tmp/tezedge_firewall.sock".to_string(),
        };
        let log = logger();
        firewall(opts, log).await;    
    });

    // try to attack
}
