package main

import (
    "fmt"
    "os/exec"
)

// Minimal Go wrapper around system firewall (uses iptables via exec).
// In production prefer a more robust library or netlink integration.

func BlockIP(ip string) error {
    // iptables -I INPUT -s <ip> -j DROP
    cmd := exec.Command("/sbin/iptables", "-I", "INPUT", "-s", ip, "-j", "DROP")
    out, err := cmd.CombinedOutput()
    if err != nil {
        return fmt.Errorf("iptables block failed: %v, out=%s", err, string(out))
    }
    return nil
}

func UnblockIP(ip string) error {
    // iptables -D INPUT -s <ip> -j DROP
    cmd := exec.Command("/sbin/iptables", "-D", "INPUT", "-s", ip, "-j", "DROP")
    out, err := cmd.CombinedOutput()
    if err != nil {
        return fmt.Errorf("iptables unblock failed: %v, out=%s", err, string(out))
    }
    return nil
}

func FlushRules() error {
    cmd := exec.Command("/sbin/iptables", "-F")
    out, err := cmd.CombinedOutput()
    if err != nil {
        return fmt.Errorf("iptables flush failed: %v, out=%s", err, string(out))
    }
    return nil
}
