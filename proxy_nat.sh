#!/bin/bash
# proxy_nat.sh - TUN to Internet NAT proxy
# Simple script to enable TUN device traffic to access Internet via NAT

set -e

# Default values
TUN_DEV="tun0"
TUN_NET="10.0.0.0/24"
PHY_DEV=""
PHY_GW=""

# Usage
usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Configure TUN device to access Internet with NAT."
    echo ""
    echo "OPTIONS:"
    echo "  -t, --tun-dev NAME       TUN device name (default: tun0)"
    echo "  -n, --tun-net CIDR       TUN network CIDR (default: 10.0.0.0/24)"
    echo "  -p, --phy-dev NAME       Physical interface (auto-detect if not specified)"
    echo "  -g, --phy-gateway IP     Physical gateway (auto-detect if not specified)"
    echo "  -c, --cleanup            Clean up rules and exit"
    echo "  -h, --help               Show this help"
    echo ""
    echo "EXAMPLES:"
    echo "  $0                      # Auto-detect physical interface"
    echo "  $0 -p ens33 -g 192.168.1.1"
    echo "  $0 -c                   # Cleanup rules"
    exit 0
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -t|--tun-dev) TUN_DEV="$2"; shift 2 ;;
        -n|--tun-net) TUN_NET="$2"; shift 2 ;;
        -p|--phy-dev) PHY_DEV="$2"; shift 2 ;;
        -g|--phy-gateway) PHY_GW="$2"; shift 2 ;;
        -c|--cleanup)
            echo "Cleaning up rules..."
            ip rule del from ${TUN_NET} lookup 100 2>/dev/null || true
            ip route flush table 100 2>/dev/null || true
            iptables -D FORWARD -i ${TUN_DEV} -o ${PHY_DEV:-eth0} -j ACCEPT 2>/dev/null || true
            iptables -D FORWARD -i ${PHY_DEV:-eth0} -o ${TUN_DEV} -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true
            iptables -t nat -D POSTROUTING -s ${TUN_NET} -o ${PHY_DEV:-eth0} -j MASQUERADE 2>/dev/null || true
            echo "Cleanup complete"
            exit 0
            ;;
        -h|--help) usage ;;
        *) echo "Unknown option: $1"; usage ;;
    esac
done

# Auto-detect physical interface
if [ -z "$PHY_DEV" ]; then
    PHY_DEV=$(ip route | grep default | head -n1 | sed 's/.*dev \([^ ]*\).*/\1/')
    echo "Auto-detected physical interface: $PHY_DEV"
fi

# Auto-detect gateway
if [ -z "$PHY_GW" ]; then
    PHY_GW=$(ip route | grep default | grep "dev $PHY_DEV" | head -n1 | sed 's/.*via \([^ ]*\).*/\1/')
    echo "Auto-detected gateway: $PHY_GW"
fi

echo "=== Configuration ==="
echo "TUN Device: $TUN_DEV"
echo "TUN Network: $TUN_NET"
echo "Physical Device: $PHY_DEV"
echo "Gateway: $PHY_GW"
echo "====================="

# Enable IP forwarding
echo "Enabling IP forwarding..."
echo 1 > /proc/sys/net/ipv4/ip_forward

# Clean up existing rules
ip rule del from ${TUN_NET} lookup 100 2>/dev/null || true
ip route flush table 100 2>/dev/null || true

# Configure routing
echo "Configuring routing..."
ip route add default via ${PHY_GW} dev ${PHY_DEV} table 100
ip rule add from ${TUN_NET} lookup 100

# Configure iptables
echo "Configuring iptables..."
iptables -A FORWARD -i ${TUN_DEV} -o ${PHY_DEV} -j ACCEPT
iptables -A FORWARD -i ${PHY_DEV} -o ${TUN_DEV} -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -t nat -A POSTROUTING -s ${TUN_NET} -o ${PHY_DEV} -j MASQUERADE

echo ""
echo "=== Configuration Complete ==="
echo "Traffic from $TUN_NET can now access Internet via $PHY_DEV"
echo "To cleanup: $0 -c"
