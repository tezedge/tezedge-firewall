FROM simplestakingcom/tezedge-bpf-builder:latest as builder

RUN cargo install cargo-script

COPY . /root/tezedge-firewall
WORKDIR /root/tezedge-firewall

RUN ./scripts/build_.rs 5.8.18

FROM ubuntu:20.04

WORKDIR /root/tezedge-firewall
COPY --from=builder /root/tezedge-firewall/scripts/run.sh /root/tezedge-firewall/scripts/
COPY --from=builder /root/tezedge-firewall/bin /root/tezedge-firewall/bin

ARG COMPLEXITY=26.0
ENV COMPLEXITY=${COMPLEXITY}
CMD ./scripts/run.sh -d eth0 --target=${COMPLEXITY}
