#!/bin/bash
# proxy_nat.sh - TUN to Internet NAT proxy

set -e

TUN_DEV="tun0"
TUN_NET="10.0.0.0/24"
PHY_DEV=""

usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Configure TUN device to access Internet with NAT."
    echo ""
    echo "OPTIONS:"
    echo "  -t, --tun-dev NAME   TUN device name (default: tun0)"
    echo "  -n, --tun-net CIDR   TUN network CIDR (default: 10.0.0.0/24)"
    echo "  -p, --phy-dev NAME   Physical interface (auto-detect if not specified)"
    echo "  -c, --cleanup        Clean up rules and exit"
    echo "  -h, --help           Show this help"
    exit 0
}

while [[ $# -gt 0 ]]; do
    case $1 in
        -t|--tun-dev) TUN_DEV="$2"; shift 2 ;;
        -n|--tun-net) TUN_NET="$2"; shift 2 ;;
        -p|--phy-dev) PHY_DEV="$2"; shift 2 ;;
        -c|--cleanup)
            echo "Cleaning up..."
            iptables -D FORWARD -i ${TUN_DEV} -o ${PHY_DEV:-eth0} -j ACCEPT 2>/dev/null || true
            iptables -D FORWARD -i ${PHY_DEV:-eth0} -o ${TUN_DEV} -m state --state ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true
            iptables -t nat -D POSTROUTING -s ${TUN_NET} -o ${PHY_DEV:-eth0} -j MASQUERADE 2>/dev/null || true
            echo "Done"
            exit 0
            ;;
        -h|--help) usage ;;
        *) echo "Unknown option: $1"; usage ;;
    esac
done

# Auto-detect physical interface
if [ -z "$PHY_DEV" ]; then
    PHY_DEV=$(ip route | grep default | head -n1 | awk '{print $3}')
    echo "Auto-detected: $PHY_DEV"
fi

echo "TUN: $TUN_DEV ($TUN_NET) -> PHY: $PHY_DEV"

echo 1 > /proc/sys/net/ipv4/ip_forward

iptables -A FORWARD -i ${TUN_DEV} -o ${PHY_DEV} -j ACCEPT
iptables -A FORWARD -i ${PHY_DEV} -o ${TUN_DEV} -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -t nat -A POSTROUTING -s ${TUN_NET} -o ${PHY_DEV} -j MASQUERADE

echo "Done. Cleanup: $0 -c"
