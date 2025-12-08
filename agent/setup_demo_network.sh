#!/bin/bash
# AI-Driven Firewall - Network Configuration Setup for 3-VM Demo
# Configures: Attacker VM -> Firewall VM -> Victim VM
# This script sets up IP forwarding, NAT, and ipset for the firewall VM

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
WAN_INTERFACE="${WAN_INTERFACE:-eth0}"
VICTIM_SUBNET="${VICTIM_SUBNET:-192.168.1.0/24}"

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}AI-Firewall Network Configuration Setup${NC}"
echo -e "${GREEN}========================================${NC}"

# Check for root privileges
if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}[ERROR] This script must be run as root!${NC}"
    echo "Usage: sudo ./setup_demo_network.sh"
    exit 1
fi

echo -e "${YELLOW}[INFO] Checking for root privileges...${NC}"
echo -e "${GREEN}[✓] Running as root${NC}"

# Enable IPv4 forwarding
echo -e "${YELLOW}[INFO] Enabling IPv4 forwarding...${NC}"
sysctl -w net.ipv4.ip_forward=1 > /dev/null
if grep -q "^net.ipv4.ip_forward = 1" /etc/sysctl.conf; then
    echo -e "${GREEN}[✓] IPv4 forwarding already enabled in /etc/sysctl.conf${NC}"
else
    echo "net.ipv4.ip_forward = 1" >> /etc/sysctl.conf
    echo -e "${GREEN}[✓] IPv4 forwarding enabled${NC}"
fi

# Flush existing iptables rules
echo -e "${YELLOW}[INFO] Flushing existing iptables rules...${NC}"
iptables -F
iptables -X
iptables -t nat -F
iptables -t nat -X
iptables -t mangle -F
iptables -t mangle -X
iptables -P INPUT ACCEPT
iptables -P FORWARD ACCEPT
iptables -P OUTPUT ACCEPT
echo -e "${GREEN}[✓] iptables rules flushed${NC}"

# Configure NAT (Masquerade) on WAN interface
echo -e "${YELLOW}[INFO] Configuring NAT (Masquerade) on interface ${WAN_INTERFACE}...${NC}"
iptables -t nat -A POSTROUTING -o "$WAN_INTERFACE" -j MASQUERADE
echo -e "${GREEN}[✓] NAT rule configured${NC}"

# Allow forwarding between interfaces
echo -e "${YELLOW}[INFO] Allowing packet forwarding...${NC}"
iptables -A FORWARD -i "$WAN_INTERFACE" -j ACCEPT
iptables -A FORWARD -o "$WAN_INTERFACE" -j ACCEPT
echo -e "${GREEN}[✓] Forwarding rules configured${NC}"

# Create ipset blacklist if it doesn't exist
echo -e "${YELLOW}[INFO] Setting up ipset blacklist...${NC}"
if ipset list blacklist >/dev/null 2>&1; then
    echo -e "${GREEN}[✓] ipset blacklist already exists${NC}"
else
    ipset create blacklist hash:ip timeout 3600
    echo -e "${GREEN}[✓] ipset blacklist created with 1-hour timeout${NC}"
fi

# Add iptables rule to drop blacklisted IPs
echo -e "${YELLOW}[INFO] Adding iptables rule for blacklist enforcement...${NC}"
iptables -I INPUT 1 -m set --match-set blacklist src -j DROP
iptables -I FORWARD 1 -m set --match-set blacklist src -j DROP
echo -e "${GREEN}[✓] Blacklist enforcement rules added${NC}"

# Display current configuration
echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}Network Configuration Summary${NC}"
echo -e "${GREEN}========================================${NC}"
echo -e "${YELLOW}IPv4 Forwarding:${NC}"
cat /proc/sys/net/ipv4/ip_forward

echo ""
echo -e "${YELLOW}Current iptables NAT rules:${NC}"
iptables -t nat -L POSTROUTING -n

echo ""
echo -e "${YELLOW}Current ipset blacklist:${NC}"
ipset list blacklist 2>/dev/null || echo "No IPs blocked yet"

echo ""
echo -e "${YELLOW}Network Interfaces:${NC}"
ip link show | grep "^[0-9]:" | awk '{print "  " $2}' | sed 's/:$//'

echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}Setup Complete!${NC}"
echo -e "${GREEN}========================================${NC}"

echo ""
echo -e "${YELLOW}Next Steps:${NC}"
echo "1. Start the SaaS Enforcer agent:"
echo -e "   ${GREEN}sudo python agent/saas_enforcer.py --mode gateway --target-ip <VICTIM_IP>${NC}"
echo ""
echo "2. Monitor alerts:"
echo -e "   ${GREEN}tail -f logs/firewall.log${NC}"
echo ""
echo "3. View blocked IPs:"
echo -e "   ${GREEN}ipset list blacklist${NC}"
echo ""

exit 0
