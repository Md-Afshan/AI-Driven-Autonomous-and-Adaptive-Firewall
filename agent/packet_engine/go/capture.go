package main

import (
    "context"
    "bytes"
    "encoding/json"
    "fmt"
    "log"
    "net/http"
    "time"

    "github.com/google/gopacket"
    "github.com/google/gopacket/layers"
    "github.com/google/gopacket/pcap"
)

// Configuration
var (
    device       = "eth0"
    snaplen int32 = 65535
    promisc       = false
    timeout       = pcap.BlockForever
    filter        = "tcp or icmp"
    mlEngineURL   = "http://ml_engine:5001/alerts"
)

// StartCapture opens a live handle and processes packets
func StartCapture() {
    handle, err := pcap.OpenLive(device, snaplen, promisc, timeout)
    if err != nil {
        log.Fatalf("pcap open failed: %v", err)
    }
    if err := handle.SetBPFFilter(filter); err != nil {
        log.Printf("failed to set bpf filter: %v", err)
    }
    packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
    ctx := context.Background()
    for packet := range packetSource.Packets() {
        go handlePacket(ctx, packet)
    }
}

type Alert struct {
    Type    string            `json:"type"`
    SrcIP   string            `json:"ip"`
    Metrics map[string]uint64 `json:"metrics,omitempty"`
}

// handlePacket inspects packet and records SYN/ACK events and triggers detectors
func handlePacket(ctx context.Context, packet gopacket.Packet) {
    networkLayer := packet.NetworkLayer()
    transportLayer := packet.TransportLayer()
    if networkLayer == nil || transportLayer == nil {
        return
    }
    src := networkLayer.NetworkFlow().Src().String()
    // For TCP, inspect flags
    if tcpLayer := packet.TransportLayer(); tcpLayer != nil {
        if tcp, ok := tcpLayer.(*layers.TCP); ok {
            isSYN := tcp.SYN
            isACK := tcp.ACK
            RecordPacket(src, isSYN, isACK)
        }
    }
    // Let detector run in background via its periodic ticker
    // When detector suspects attack, it will call EnableTCPSynCookies and we also send alert to ML engine
    // For demo: send heartbeat alerts for suspected IPs in DetectSYNFlood
}

// sendAlert posts an alert JSON to ML engine (non-blocking)
func sendAlert(alert Alert) {
    go func() {
        b, _ := json.Marshal(alert)
        client := http.Client{Timeout: 2 * time.Second}
        if _, err := client.Post(mlEngineURL, "application/json", bytes.NewReader(b)); err != nil {
            log.Printf("failed to send alert: %v", err)
        }
    }()
}

// Helper to call from DetectSYNFlood when an alert is needed
func notifyML(ip string) {
    alert := Alert{Type: "syn_flood", SrcIP: ip, Metrics: map[string]uint64{"syn_count": 0}}
    // metrics could be filled in with real counts
    sendAlert(alert)
}
