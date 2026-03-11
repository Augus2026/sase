#!/bin/bash

# SASE Network Namespace Test Script
# Using functions for cleaner code and minimal logging

set -e

# Configuration
SERVER_IP="192.168.147.146"
SERVER_PORT="12345"
SERVER_TUN_NAME="tun1"
SERVER_TUN_ADDR="10.0.0.1"
SERVER_TUN_NETMASK="255.255.255.0"
CLIENT_TUN_NAME="tun0"
CLIENT_TUN_ADDR="10.0.0.2"
CLIENT_TUN_NETMASK="255.255.255.0"
TRANSPORT="udp"

# Functions
cleanup() {
    echo "Cleaning up..."
    pkill -f "target/release/sase" 2>/dev/null || true
    sudo ip link delete $SERVER_TUN_NAME 2>/dev/null || true
    sudo ip netns exec sase_client ip link delete $CLIENT_TUN_NAME 2>/dev/null || true
    sudo ip link delete veth0 2>/dev/null || true
    sudo ip link delete veth1 2>/dev/null || true
    sudo ip netns delete sase_client 2>/dev/null || true
    sleep 1
}

setup_netns() {
    echo "Setting up network namespace..."
    sudo ip netns add sase_client
    sudo ip link add veth0 type veth peer name veth1
    sudo ip link set veth1 netns sase_client
    sudo ip addr add 192.168.100.1/24 dev veth0
    sudo ip link set veth0 up
    sudo ip netns exec sase_client ip addr add 192.168.100.2/24 dev veth1
    sudo ip netns exec sase_client ip link set veth1 up
    sudo ip netns exec sase_client ip link set lo up
    sudo ip netns exec sase_client ip route add default via 192.168.100.1
}

start_server() {
    echo "Starting server..."
    cargo run --release -- server \
        --transport tcp \
        --bind 0.0.0.0:$SERVER_PORT \
        --tun $SERVER_TUN_NAME \
        --address $SERVER_TUN_ADDR \
        --netmask $SERVER_TUN_NETMASK \
        > server.log 2>&1 &
    sleep 3
    ip addr show $SERVER_TUN_NAME >/dev/null || { echo "Server TUN not created"; exit 1; }
    echo "Server: $SERVER_TUN_ADDR ($SERVER_TUN_NAME)"
}

start_client() {
    echo "Starting client..."
    sudo ip netns exec sase_client cargo run --release -- client \
        --transport $TRANSPORT \
        --server $SERVER_IP:$SERVER_PORT \
        --tun $CLIENT_TUN_NAME \
        --address $CLIENT_TUN_ADDR \
        --netmask $CLIENT_TUN_NETMASK \
        > client.log 2>&1 &
    sleep 3
    sudo ip netns exec sase_client ip addr show $CLIENT_TUN_NAME >/dev/null && echo "Client: $CLIENT_TUN_ADDR ($CLIENT_TUN_NAME)"
}

test_connectivity() {
    echo "Testing connectivity..."
    if ping -c 1 -W 2 $CLIENT_TUN_ADDR >/dev/null 2>&1; then
        echo "✓ Server → Client"
    else
        echo "✗ Server → Client"
    fi
    if sudo ip netns exec sase_client ping -c 1 -W 2 $SERVER_TUN_ADDR >/dev/null 2>&1; then
        echo "✓ Client → Server"
    else
        echo "✗ Client → Server"
    fi
}

show_status() {
    echo ""
    echo "=== Status ==="
    echo "Server TUN: $SERVER_TUN_ADDR ($SERVER_TUN_NAME)"
    echo "Client TUN: $CLIENT_TUN_ADDR ($CLIENT_TUN_NAME)"
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
