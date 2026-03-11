#!/bin/bash

# SASE Network Namespace Test Script
# Using functions for cleaner code and minimal logging

set -e

# Configuration
SERVER_IP="192.168.147.146"
SERVER_PORT="12345"
SERVER_TUN_NAME="tun0"
SERVER_TUN_ADDR="10.0.0.1"
SERVER_TUN_NETMASK="255.255.255.0"
CLIENT_TUN_NAME="tun1"
CLIENT_TUN_ADDR="10.0.0.2"
CLIENT_TUN_NETMASK="255.255.255.0"
TRANSPORT="udp"

# Network namespaces
SERVER_NETNS="sase_server"
CLIENT_NETNS="sase_client"

# Functions
cleanup() {
    echo "Cleaning up..."
    pkill -f "target/release/sase" 2>/dev/null || true
    ip link delete veth0 2>/dev/null || true
    ip link delete veth1 2>/dev/null || true
    ip netns exec $SERVER_NETNS ip link delete $SERVER_TUN_NAME 2>/dev/null || true
    ip netns exec $CLIENT_NETNS ip link delete $CLIENT_TUN_NAME 2>/dev/null || true
    ip netns delete $SERVER_NETNS 2>/dev/null || true
    ip netns delete $CLIENT_NETNS 2>/dev/null || true
    sleep 1
}

setup_netns() {
    echo "Setting up network namespaces..."

    # Create network namespaces
    ip netns add $SERVER_NETNS
    ip netns add $CLIENT_NETNS

    # Create veth pair connecting the two namespaces
    ip link add veth0 type veth peer name veth1
    ip link set veth0 netns $SERVER_NETNS
    ip link set veth1 netns $CLIENT_NETNS

    # Configure veth0 in server namespace
    ip netns exec $SERVER_NETNS ip addr add 192.168.200.1/24 dev veth0
    ip netns exec $SERVER_NETNS ip link set veth0 up
    ip netns exec $SERVER_NETNS ip link set lo up

    # Configure veth1 in client namespace
    ip netns exec $CLIENT_NETNS ip addr add 192.168.200.2/24 dev veth1
    ip netns exec $CLIENT_NETNS ip link set veth1 up
    ip netns exec $CLIENT_NETNS ip link set lo up

    # Add routes
    ip netns exec $SERVER_NETNS ip route add default via 192.168.200.2
    ip netns exec $CLIENT_NETNS ip route add default via 192.168.200.1

    # Create TUN device for server in server namespace
    echo "Creating server TUN device in namespace..."
    ip netns exec $SERVER_NETNS ip tuntap add name $SERVER_TUN_NAME mode tun
    ip netns exec $SERVER_NETNS ip addr add $SERVER_TUN_ADDR/$SERVER_TUN_NETMASK dev $SERVER_TUN_NAME
    ip netns exec $SERVER_NETNS ip link set $SERVER_TUN_NAME up

    # Create TUN device for client in client namespace
    echo "Creating client TUN device in namespace..."
    ip netns exec $CLIENT_NETNS ip tuntap add name $CLIENT_TUN_NAME mode tun
    ip netns exec $CLIENT_NETNS ip addr add $CLIENT_TUN_ADDR/$CLIENT_TUN_NETMASK dev $CLIENT_TUN_NAME
    ip netns exec $CLIENT_NETNS ip link set $CLIENT_TUN_NAME up
}

start_server() {
    echo "Starting server in namespace..."
    ip netns exec $SERVER_NETNS cargo run --release -- server \
        --transport tcp \
        --bind 192.168.200.1:$SERVER_PORT \
        --tun $SERVER_TUN_NAME \
        --address $SERVER_TUN_ADDR \
        --netmask $SERVER_TUN_NETMASK \
        > server.log 2>&1 &
    sleep 3
    echo "Server: $SERVER_TUN_NAME ($SERVER_TUN_ADDR)"
}

start_client() {
    echo "Starting client in namespace..."
    ip netns exec $CLIENT_NETNS cargo run --release -- client \
        --transport $TRANSPORT \
        --server 192.168.200.1:$SERVER_PORT \
        --tun $CLIENT_TUN_NAME \
        --address $CLIENT_TUN_ADDR \
        --netmask $CLIENT_TUN_NETMASK \
        > client.log 2>&1 &
    sleep 5
    echo "Client: $CLIENT_TUN_NAME ($CLIENT_TUN_ADDR)"
}

test_connectivity() {
    echo "Testing connectivity..."
    if ip netns exec $SERVER_NETNS ping -c 1 -W 2 $CLIENT_TUN_ADDR >/dev/null 2>&1; then
        echo "✓ Server → Client"
    else
        echo "✗ Server → Client"
    fi
    if ip netns exec $CLIENT_NETNS ping -c 1 -W 2 $SERVER_TUN_ADDR >/dev/null 2>&1; then
        echo "✓ Client → Server"
    else
        echo "✗ Client → Server"
    fi
}

show_status() {
    echo ""
    echo "=== Status ==="
    echo "Server: $SERVER_TUN_NAME ($SERVER_TUN_ADDR)"
    echo "Client: $CLIENT_TUN_NAME ($CLIENT_TUN_ADDR)"
    echo "Transport: TCP server, UDP client"
    echo ""
    echo "Logs: server.log, client.log"
    echo "Stop: Ctrl+C"
}

# Main
trap cleanup EXIT
setup_netns
start_server
start_client
test_connectivity
show_status
wait
