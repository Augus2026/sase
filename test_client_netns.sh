#!/bin/bash

# SASE Client Network Namespace Test Script

set -e

# Configuration
SERVER_IP="192.168.200.1"
SERVER_PORT="12345"
CLIENT_TUN_NAME="tun1"
CLIENT_TUN_ADDR="10.0.0.2"
CLIENT_TUN_NETMASK="255.255.255.0"
TRANSPORT="udp"
NETNS="sase_client"
PEER_IP="192.168.200.1"
LOCAL_IP="192.168.200.2"

# Cleanup
cleanup() {
    echo "Cleaning up..."
    pkill -f "target/release/sase.*client" 2>/dev/null || true
    ip link delete veth1 2>/dev/null || true
    ip netns exec $NETNS ip link delete $CLIENT_TUN_NAME 2>/dev/null || true
    ip netns delete $NETNS 2>/dev/null || true
    sleep 1
}

trap cleanup EXIT

# Setup network namespace
setup_netns() {
    echo "Setting up client network namespace..."

    # Create network namespace
    ip netns add $NETNS

    # Create veth pair (connect to server namespace)
    ip link add veth0 type veth peer name veth1
    ip link set veth1 netns $NETNS

    # Configure veth1 in client namespace
    ip netns exec $NETNS ip addr add $LOCAL_IP/24 dev veth1
    ip netns exec $NETNS ip link set veth1 up
    ip netns exec $NETNS ip link set lo up

    # Add route to server namespace
    ip netns exec $NETNS ip route add default via $PEER_IP

    # Create TUN device
    echo "Creating TUN device..."
    ip netns exec $NETNS ip tuntap add name $CLIENT_TUN_NAME mode tun
    ip netns exec $NETNS ip addr add $CLIENT_TUN_ADDR/$CLIENT_TUN_NETMASK dev $CLIENT_TUN_NAME
    ip netns exec $NETNS ip link set $CLIENT_TUN_NAME up
}

# Start client
start_client() {
    echo "Starting client in namespace..."
    ip netns exec $NETNS cargo run --release -- client \
        --transport $TRANSPORT \
        --server $SERVER_IP:$SERVER_PORT \
        --tun $CLIENT_TUN_NAME \
        --address $CLIENT_TUN_ADDR \
        --netmask $CLIENT_TUN_NETMASK \
        > client.log 2>&1 &
    sleep 5
    echo "Client: $CLIENT_TUN_NAME ($CLIENT_TUN_ADDR)"
}

# Test connectivity
test_connectivity() {
    echo "Testing connectivity..."
    if ip netns exec $NETNS ping -c 2 -W 2 $PEER_IP >/dev/null 2>&1; then
        echo "✓ Client can reach server namespace"
    else
        echo "✗ Client cannot reach server namespace"
    fi
}

# Show status
show_status() {
    echo ""
    echo "=== Status ==="
    echo "Client: $CLIENT_TUN_NAME ($CLIENT_TUN_ADDR)"
    echo "Namespace: $NETNS"
    echo "Transport: $TRANSPORT"
    echo "Server: $SERVER_IP:$SERVER_PORT"
    echo "Log: client.log"
    echo "Stop: Ctrl+C"
}

# Main
setup_netns
start_client
test_connectivity
show_status
wait
