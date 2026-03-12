# SASE Testing Guide

## Quick Start

### Start Server
```bash
chmod +x test_server_netns.sh
sudo ./test_server_netns.sh
```

### Start Client
```bash
chmod +x test_client_netns.sh
sudo ./test_client_netns.sh
```

## Network Topology

```
sase_server 命名空间          sase_client 命名空间
┌──────────────────────┐       ┌──────────────────────┐
│ tun0               │       │ tun1               │
│ 10.0.0.1           │<─────>│ 10.0.0.2           │
│ (TUN - VPN 网络)     │ VPN  │ (TUN - VPN 网络)     │
└──────────────────────┘       └──────────────────────┘
         │ veth0                       veth1
         │ 192.168.200.1               192.168.200.2
         └────────────────────────────────────────┘
                  TCP transport
```

## Server Script Configuration

Edit `test_server_netns.sh`:
```bash
SERVER_PORT="12345"
SERVER_TUN_NAME="tun0"
SERVER_TUN_ADDR="10.0.0.1"
SERVER_TUN_NETMASK="255.255.255.0"
NETNS="sase_server"
```

## Client Script Configuration

Edit `test_client_netns.sh`:
```bash
SERVER_IP="192.168.200.1"
SERVER_PORT="12345"
CLIENT_TUN_NAME="tun1"
CLIENT_TUN_ADDR="10.0.0.2"
CLIENT_TUN_NETMASK="255.255.255.0"
TRANSPORT="udp"
NETNS="sase_client"
```

## Useful Commands

```bash
# View server logs
tail -f server.log

# View client logs
tail -f client.log

# Check server namespace
ip netns exec sase_server ip addr show
ip netns exec sase_server ip link show

# Check client namespace
ip netns exec sase_client ip addr show
ip netns exec sase_client ip link show

# Test VPN connectivity
ip netns exec sase_server ping -c 3 10.0.0.2
ip netns exec sase_client ping -c 3 10.0.0.1
```

## Cleanup

Each script has automatic cleanup on exit (Ctrl+C).

Manual cleanup:
```bash
# Server cleanup
pkill -f "target/release/sase.*server"
ip link delete veth0
ip netns delete sase_server

# Client cleanup
pkill -f "target/release/sase.*client"
ip link delete veth1
ip netns delete sase_client
```
