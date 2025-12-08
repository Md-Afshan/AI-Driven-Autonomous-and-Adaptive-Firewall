#!/bin/bash

###############################################################################
# Kali Linux Attack Simulation Script for AI Firewall Live Ops Dashboard
# Demonstrates benign traffic, SQL injection, and DDoS detection in real-time
# Run with: sudo bash kali_demo_attack.sh [target_host] [target_port]
###############################################################################

# Configuration
TARGET_HOST="${1:-127.0.0.1}"
TARGET_PORT="${2:-80}"
LOOP_COUNT=0
MAX_LOOPS=0  # 0 = infinite

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

###############################################################################
# Helper Functions
###############################################################################

print_header() {
    echo -e "${BLUE}================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}================================${NC}"
}

print_benign() {
    echo -e "${GREEN}[BENIGN] $1${NC}"
}

print_attack() {
    echo -e "${RED}[ATTACK] $1${NC}"
}

print_info() {
    echo -e "${YELLOW}[INFO] $1${NC}"
}

check_requirements() {
    print_header "Checking Requirements"
    
    # Check curl
    if ! command -v curl &> /dev/null; then
        echo -e "${RED}curl is not installed. Installing...${NC}"
        if command -v apt-get &> /dev/null; then
            sudo apt-get update && sudo apt-get install -y curl
        elif command -v dnf &> /dev/null; then
            sudo dnf install -y curl
        else
            echo -e "${RED}Cannot install curl. Please install it manually.${NC}"
            exit 1
        fi
    fi
    
    # Check hping3 (optional for DDoS simulation)
    if ! command -v hping3 &> /dev/null; then
        print_info "hping3 not installed. Will use curl for DDoS simulation instead."
    fi
    
    print_benign "All required tools available"
    echo ""
}

###############################################################################
# Phase 1: Benign Traffic (GREEN LOGS)
###############################################################################

phase_benign_traffic() {
    print_header "PHASE 1: BENIGN TRAFFIC (${GREEN}Expected: GREEN${NC})"
    
    local requests=(
        "GET / HTTP/1.1"
        "GET /images/logo.png HTTP/1.1"
        "GET /api/health HTTP/1.1"
        "GET /index.html HTTP/1.1"
    )
    
    for request in "${requests[@]}"; do
        print_benign "Sending benign request: $request"
        
        # Send benign HTTP GET request
        curl -s -X GET "http://${TARGET_HOST}:${TARGET_PORT}/" \
            -H "User-Agent: Mozilla/5.0 (X11; Linux x86_64)" \
            -H "Accept: text/html" \
            --max-time 2 > /dev/null 2>&1
        
        sleep 1
    done
    
    print_benign "Phase 1 complete: 4 benign requests sent"
    echo ""
}

###############################################################################
# Phase 2: SQL Injection Attacks (RED LOGS)
###############################################################################

phase_sql_injection() {
    print_header "PHASE 2: SQL INJECTION ATTACKS (${RED}Expected: RED - BLOCKED${NC})"
    
    local payloads=(
        "' OR '1'='1"
        "admin' --"
        "' UNION SELECT * FROM users --"
        "1'; DROP TABLE users; --"
        "' OR 1=1 --"
    )
    
    for payload in "${payloads[@]}"; do
        print_attack "Sending SQL injection: $payload"
        
        # Send SQL injection payload
        curl -s -X GET "http://${TARGET_HOST}:${TARGET_PORT}/?id=$payload" \
            -H "User-Agent: Exploit-Tool/1.0" \
            --max-time 2 > /dev/null 2>&1
        
        sleep 1
    done
    
    print_attack "Phase 2 complete: 5 SQL injection attempts sent"
    echo ""
}

###############################################################################
# Phase 3: DDoS Simulation (RED LOGS)
###############################################################################

phase_ddos_simulation() {
    print_header "PHASE 3: DDoS SIMULATION (${RED}Expected: RED - BLOCKED${NC})"
    
    print_attack "Starting DDoS simulation with rapid requests..."
    
    # Check if hping3 is available
    if command -v hping3 &> /dev/null; then
        print_attack "Using hping3 for SYN flood simulation"
        # Send SYN flood (requires root)
        sudo hping3 -S --flood -p ${TARGET_PORT} ${TARGET_HOST} 2>/dev/null &
        HPING_PID=$!
        sleep 3
        sudo kill $HPING_PID 2>/dev/null
    else
        # Fallback: Rapid curl requests
        print_attack "Using curl for rapid request simulation"
        for i in {1..20}; do
            curl -s -X GET "http://${TARGET_HOST}:${TARGET_PORT}/" \
                --max-time 1 > /dev/null 2>&1 &
        done
        wait
    fi
    
    print_attack "Phase 3 complete: DDoS simulation finished"
    echo ""
}

###############################################################################
# Main Loop
###############################################################################

main() {
    print_header "🛡️ AI FIREWALL ATTACK SIMULATION DEMO 🛡️"
    print_info "Target: ${TARGET_HOST}:${TARGET_PORT}"
    print_info "Loop Count: $((LOOP_COUNT + 1))/$((MAX_LOOPS > 0 ? MAX_LOOPS : 'INFINITE'))"
    echo ""
    
    check_requirements
    
    # Run attack phases
    phase_benign_traffic
    sleep 2
    
    phase_sql_injection
    sleep 2
    
    phase_ddos_simulation
    sleep 2
    
    echo ""
    print_header "Cycle Complete"
    print_info "Dashboard should show:"
    echo "  🟢 Benign traffic in GREEN"
    echo "  🔴 Attacks in RED with screen flash for high confidence"
    echo "  📊 Real-time metrics updated"
    echo ""
}

###############################################################################
# Entry Point
###############################################################################

# Check if running with sudo (required for some operations)
if [[ $EUID -ne 0 ]]; then
    print_info "Some features require root privilege. Running with sudo..."
    exec sudo bash "$0" "$@"
fi

# Main loop
while true; do
    main
    
    LOOP_COUNT=$((LOOP_COUNT + 1))
    
    if [ $MAX_LOOPS -gt 0 ] && [ $LOOP_COUNT -ge $MAX_LOOPS ]; then
        print_header "Simulation Complete"
        print_info "Total cycles executed: $LOOP_COUNT"
        exit 0
    fi
    
    print_info "Next cycle in 10 seconds... (Press Ctrl+C to stop)"
    sleep 10
done
