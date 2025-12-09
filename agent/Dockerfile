FROM golang:1.20 as builder
WORKDIR /src
COPY ./packet_engine/go ./packet_engine/go
RUN cd packet_engine/go && go build -o /bin/packet_engine main.go syn_detector.go firewall_controller.go

FROM ubuntu:24.04
RUN apt-get update && apt-get install -y iptables iproute2 iputils-ping ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /bin/packet_engine /usr/local/bin/packet_engine
WORKDIR /opt/agent
COPY ./packet_engine/python ./packet_engine/python
CMD ["/usr/local/bin/packet_engine"]
