#!/bin/bash

##############################################################################
# Kali Linux AI Firewall Demo Attack Script
# Simulates mixed benign and malicious traffic for dashboard visualization
##############################################################################

set -e

# Configuration
TARGET_HOST="${1:-127.0.0.1}"
TARGET_PORT="${2:-8000}"
DEMO_URL="http://${TARGET_HOST}:${TARGET_PORT}"
API_KEY="secret-token"
DEMO_DURATION="${3:-60}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║   🔥 AI Firewall Live Ops Dashboard - Kali Demo Script    ║${NC}"
echo -e "${BLUE}║          Real-Time Threat Detection Visualization         ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${YELLOW}Target Dashboard:${NC} $DEMO_URL"
echo -e "${YELLOW}Duration:${NC} ${DEMO_DURATION}s"
echo -e "${YELLOW}Starting demo in 3 seconds...${NC}"
echo ""

sleep 3

# Function to send benign HTTP request
send_benign_traffic() {
    local iteration=$1
    
    echo -e "${GREEN}[BENIGN] Step 1.${iteration}: Sending legitimate HTTP request...${NC}"
    
    curl -s -X GET "$DEMO_URL/" \
        -H "User-Agent: Mozilla/5.0 (X11; Linux x86_64)" \
        -H "Accept: text/html,application/xhtml+xml" \
        -w "\n  Status: %{http_code}\n" > /dev/null 2>&1 || true
    
    # Additional benign request
    curl -s -X GET "$DEMO_URL/live-stats" \
        -H "X-API-Key: $API_KEY" \
        -w "\n  Status: %{http_code}\n" > /dev/null 2>&1 || true
    
    echo -e "${GREEN}✓ Benign traffic sent - should appear GREEN in dashboard${NC}"
    sleep 1
}

# Function to send SQL injection attack
send_sqli_attack() {
    local iteration=$1
    
    echo -e "${RED}[ATTACK] Step 2.${iteration}: Sending SQL Injection payload...${NC}"
    
    # Send SQL injection via POST to alerts endpoint (simulated)
    SQLI_PAYLOAD="' OR '1'='1'; DROP TABLE users;--"
    
    curl -s -X POST "$DEMO_URL/alerts" \
        -H "X-API-Key: $API_KEY" \
        -H "Content-Type: application/json" \
        -d "{
            \"source_ip\": \"192.168.1.$(($RANDOM % 256))\",
            \"destination_ip\": \"10.0.0.1\",
            \"attack_type\": \"SQL Injection\",
            \"confidence_score\": $(echo \"scale=3; 0.85 + 0.15 * $RANDOM / 32767\" | bc),
            \"timestamp\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\",
            \"payload_sample\": \"$SQLI_PAYLOAD\"
        }" > /dev/null 2>&1 || true
    
    echo -e "${RED}✓ SQL Injection detected - should appear RED in dashboard${NC}"
    sleep 1
}

# Function to send DDoS attack
send_ddos_attack() {
    local iteration=$1
    
    echo -e "${RED}[ATTACK] Step 3.${iteration}: Simulating DDoS attack (rapid requests)...${NC}"
    
    for i in {1..5}; do
        curl -s -X POST "$DEMO_URL/alerts" \
            -H "X-API-Key: $API_KEY" \
            -H "Content-Type: application/json" \
            -d "{
                \"source_ip\": \"$(($RANDOM % 256)).$(($RANDOM % 256)).$(($RANDOM % 256)).$(($RANDOM % 256))\",
                \"destination_ip\": \"10.0.0.2\",
                \"attack_type\": \"DDoS\",
                \"confidence_score\": $(echo \"scale=3; 0.80 + 0.20 * $RANDOM / 32767\" | bc),
                \"timestamp\": \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\",
                \"payload_sample\": \"SYN flood packet - Packet $i\"
            }" > /dev/null 2>&1 || true
        
        echo -e "  ↳ DDoS packet $i sent"
        sleep 0.2
    done
    
    echo -e "${RED}✓ DDoS attack simulated - dashboard should flash RED${NC}"
    sleep 2
}

# Function to display dashboard stats
show_dashboard_stats() {
    echo -e "\n${BLUE}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}Dashboard Statistics:${NC}"
    
    STATS=$(curl -s -X GET "$DEMO_URL/live-stats" \
        -H "X-API-Key: $API_KEY" 2>/dev/null || echo '{}')
    
    echo "$STATS" | python3 -m json.tool 2>/dev/null || echo "  (Stats unavailable - check dashboard manually)"
    echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}\n"
}

# Main demo loop
ITERATION=1
START_TIME=$(date +%s)
CURRENT_TIME=$START_TIME

echo -e "${YELLOW}Starting attack simulation loop...${NC}\n"

while [ $((CURRENT_TIME - START_TIME)) -lt $DEMO_DURATION ]; do
    CURRENT_TIME=$(date +%s)
    ELAPSED=$((CURRENT_TIME - START_TIME))
    
    echo -e "\n${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BLUE}Iteration $ITERATION (Elapsed: ${ELAPSED}s/${DEMO_DURATION}s)${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    
    # Run demo sequence
    send_benign_traffic $ITERATION
    sleep 2
    
    send_sqli_attack $ITERATION
    sleep 2
    
    send_ddos_attack $ITERATION
    sleep 3
    
    # Show stats every 2 iterations
    if [ $((ITERATION % 2)) -eq 0 ]; then
        show_dashboard_stats
    fi
    
    ITERATION=$((ITERATION + 1))
    
    # Check if we should continue
    CURRENT_TIME=$(date +%s)
    REMAINING=$((DEMO_DURATION - (CURRENT_TIME - START_TIME)))
    
    if [ $REMAINING -gt 0 ]; then
        echo -e "${YELLOW}Next iteration in 5 seconds... (${REMAINING}s remaining)${NC}"
        sleep 5
    fi
done

echo -e "\n${BLUE}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║                  Demo Complete!                            ║${NC}"
echo -e "${BLUE}║                                                            ║${NC}"
echo -e "${BLUE}║  ✓ Benign traffic should appear GREEN in dashboard        ║${NC}"
echo -e "${BLUE}║  ✓ Attacks should appear RED and trigger alerts           ║${NC}"
echo -e "${BLUE}║  ✓ Statistics should update in real-time                  ║${NC}"
echo -e "${BLUE}║  ✓ Dashboard should remain responsive                     ║${NC}"
echo -e "${BLUE}║                                                            ║${NC}"
echo -e "${BLUE}║  Open http://${TARGET_HOST}:${TARGET_PORT}/ in browser   ║${NC}"
echo -e "${BLUE}║  to view the Live Ops Dashboard                           ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════════╝${NC}"

# Show final stats
show_dashboard_stats

echo -e "${GREEN}🎉 Kali demo script completed successfully!${NC}"
