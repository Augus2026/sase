#!/bin/bash
# tun2internet_smart.sh

# 配置变量
TUN_DEV="tun0"
TUN_IP="10.0.0.1"
TUN_NET="10.0.0.0/24"
PHY_DEV="eth0"
PHY_GW="192.168.1.1"  # 物理网卡的网关

# 1. 启用IP转发
echo 1 > /proc/sys/net/ipv4/ip_forward
sysctl -w net.ipv4.ip_forward=1

# 2. 清理规则（保留现有连接）
iptables -F
iptables -t nat -F
iptables -t mangle -F
iptables -X
iptables -t nat -X
iptables -t mangle -X

# 3. 设置默认策略
iptables -P INPUT ACCEPT
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

# 4. 配置路由策略（关键！）
echo "配置智能路由..."

# 添加默认路由到物理网卡（互联网）
ip route add default via ${PHY_GW} dev ${PHY_DEV} table 100

# 添加内网路由到 TUN 设备
ip route add 10.0.0.0/8 dev ${TUN_DEV} table 100
ip route add 172.16.0.0/12 dev ${TUN_DEV} table 100
ip route add 192.168.0.0/16 dev ${TUN_DEV} table 100

# 添加路由规则：来自 TUN 的流量使用新路由表
ip rule add from ${TUN_NET} lookup 100 priority 1000

# 5. 配置iptables转发
# 允许 TUN 到物理网卡
iptables -A FORWARD -i ${TUN_DEV} -o ${PHY_DEV} -j ACCEPT
# 允许回复
iptables -A FORWARD -i ${PHY_DEV} -o ${TUN_DEV} -m state --state ESTABLISHED,RELATED -j ACCEPT

# 6. 配置智能 NAT
# 使用 ipset 管理内网网段
apt-get install -y ipset 2>/dev/null || yum install -y ipset 2>/dev/null
ipset create LOCAL_NETS hash:net 2>/dev/null || ipset flush LOCAL_NETS
ipset add LOCAL_NETS 10.0.0.0/8
ipset add LOCAL_NETS 172.16.0.0/12
ipset add LOCAL_NETS 192.168.0.0/16
ipset add LOCAL_NETS 169.254.0.0/16

# 只有访问非内网地址时才进行 NAT
iptables -t nat -A POSTROUTING -s ${TUN_NET} -o ${PHY_DEV} \
    -m set ! --match-set LOCAL_NETS dst \
    -j MASQUERADE

# 7. 允许 TUN 设备间的通信（可选）
iptables -A FORWARD -i ${TUN_DEV} -o ${TUN_DEV} -j ACCEPT

# 8. 设置 MSS 钳制（优化 MTU）
iptables -t mangle -A FORWARD -o ${PHY_DEV} -p tcp --tcp-flags SYN,RST SYN \
    -j TCPMSS --clamp-mss-to-pmtu

echo "========================================="
echo "配置完成！"
echo "TUN 设备: ${TUN_DEV} (${TUN_IP})"
echo "物理设备: ${PHY_DEV}"
echo "内网网段（不走 NAT）:"
echo "  10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16"
echo "========================================="

# 测试配置
echo "测试配置..."
echo "1. 检查路由表:"
ip route show table 100
echo ""
echo "2. 检查 NAT 规则:"
iptables -t nat -L POSTROUTING -n -v