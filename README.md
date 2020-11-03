# Tezos Firewall

Run `./prepare_dependencies.sh` after clone to clone and patch foreign repositories.

Run `sudo ./setcap.sh` after each rebuild.

Run the firewall `cargo run -- --device <interface name>`, for example `cargo run -- --device enp4s0`.
