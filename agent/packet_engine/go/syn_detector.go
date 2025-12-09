package main

import (
    "fmt"
    "os/exec"
    "sync"
    "time"
)

// Simple SYN flood detector skeleton.
// Counts SYN and ACKs per source IP in 1-second windows.

type synStats struct {
    synTimestamps []time.Time
    ackTimestamps []time.Time
}

var (
    mu      sync.Mutex
    stats   = make(map[string]*synStats)
)

// RecordPacket is called by packet capture when a SYN or ACK is seen.
func RecordPacket(srcIP string, isSYN bool, isACK bool) {
    mu.Lock()
    defer mu.Unlock()
    now := time.Now()
    s, ok := stats[srcIP]
    if !ok {
        s = &synStats{}
        stats[srcIP] = s
    }
    if isSYN {
        s.synTimestamps = append(s.synTimestamps, now)
    }
    if isACK {
        s.ackTimestamps = append(s.ackTimestamps, now)
    }
}

// DetectSYNFlood scans stats and triggers alert if SYN:ACK ratio > 10 in 1s window.
func DetectSYNFlood() {
    mu.Lock()
    defer mu.Unlock()
    cutoff := time.Now().Add(-1 * time.Second)
    for ip, s := range stats {
        // trim old
        synCount := 0
        ackCount := 0
        newSyn := s.synTimestamps[:0]
        for _, t := range s.synTimestamps {
            if t.After(cutoff) {
                synCount++
                newSyn = append(newSyn, t)
            }
        }
        s.synTimestamps = newSyn

        newAck := s.ackTimestamps[:0]
        for _, t := range s.ackTimestamps {
            if t.After(cutoff) {
                ackCount++
                newAck = append(newAck, t)
            }
        }
        s.ackTimestamps = newAck

        ratio := 0.0
        if ackCount > 0 {
            ratio = float64(synCount) / float64(ackCount)
        } else if synCount > 0 {
            ratio = float64(synCount)
        }

        if synCount >= 20 && ratio > 10.0 {
            // Trigger an alert to AI Engine and log
            fmt.Printf("SYN flood suspected from %s: syn=%d ack=%d ratio=%.1f\n", ip, synCount, ackCount, ratio)
            // notify ML engine with basic metrics
            notifyML(ip)
            // Example action: enable SYN cookies
            _ = EnableTCPSynCookies()
        }
    }
}

// EnableTCPSynCookies uses system call to enable kernel SYN cookies (requires privileges).
func EnableTCPSynCookies() error {
    // sysctl -w net.ipv4.tcp_syncookies=1
    cmd := exec.Command("sysctl", "-w", "net.ipv4.tcp_syncookies=1")
    out, err := cmd.CombinedOutput()
    if err != nil {
        return fmt.Errorf("failed enable syncookies: %v output=%s", err, string(out))
    }
    fmt.Printf("Enabled tcp_syncookies: %s", string(out))
    return nil
}

// Background loop to periodically run detection.
func init() {
    go func() {
        ticker := time.NewTicker(1 * time.Second)
        for range ticker.C {
            DetectSYNFlood()
        }
    }()
}
