#!/bin/bash

# SASE Server Network Namespace Test Script

set -e

# Configuration
SERVER_PORT="12345"
SERVER_TUN_NAME="tun0"
SERVER_TUN_ADDR="10.0.0.1"
SERVER_TUN_NETMASK="255.255.255.0"
NETNS="sase_server"
PEER_IP="192.168.200.2"
LOCAL_IP="192.168.200.1"

# Cleanup
cleanup() {
    echo "Cleaning up..."
    pkill -f "target/release/sase.*server" 2>/dev/null || true
    ip link delete veth0 2>/dev/null || true
    ip netns exec $NETNS ip link delete $SERVER_TUN_NAME 2>/dev/null || true
    ip netns delete $NETNS 2>/dev/null || true
    sleep 1
}

trap cleanup EXIT

# Setup network namespace
setup_netns() {
    echo "Setting up server network namespace..."

    # Create network namespace
    ip netns add $NETNS

    # Create veth pair (connect to client namespace)
    ip link add veth0 type veth peer name veth1
    ip link set veth0 netns $NETNS

    # Configure veth0 in server namespace
    ip netns exec $NETNS ip addr add $LOCAL_IP/24 dev veth0
    ip netns exec $NETNS ip link set veth0 up
    ip netns exec $NETNS ip link set lo up

    # Add route to client namespace
    ip netns exec $NETNS ip route add default via $PEER_IP

    # Create TUN device
    echo "Creating TUN device..."
    ip netns exec $NETNS ip tuntap add name $SERVER_TUN_NAME mode tun
    ip netns exec $NETNS ip addr add $SERVER_TUN_ADDR/$SERVER_TUN_NETMASK dev $SERVER_TUN_NAME
    ip netns exec $NETNS ip link set $SERVER_TUN_NAME up
}

# Start server
start_server() {
    echo "Starting server in namespace..."
    ip netns exec $NETNS cargo run --release -- server \
        --transport tcp \
        --bind $LOCAL_IP:$SERVER_PORT \
        --tun $SERVER_TUN_NAME \
        --address $SERVER_TUN_ADDR \
        --netmask $SERVER_TUN_NETMASK \
        > server.log 2>&1 &
    sleep 3
    echo "Server: $SERVER_TUN_NAME ($SERVER_TUN_ADDR)"
}

# Show status
show_status() {
    echo ""
    echo "=== Status ==="
    echo "Server: $SERVER_TUN_NAME ($SERVER_TUN_ADDR)"
    echo "Namespace: $NETNS"
    echo "Transport: TCP"
    echo "Log: server.log"
    echo "Stop: Ctrl+C"
}

# Main
setup_netns
start_server
show_status
wait
