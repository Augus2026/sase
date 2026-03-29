#!/bin/bash

# ================= 配置区 =================
TUN_INTERFACE="tun1"
PHYSICAL_INTERFACE="ens33"
SUBNET="10.0.0.0/24"
# ==========================================

if [[ $EUID -ne 0 ]]; then
   echo "此脚本必须以 root 权限运行" 
   exit 1
fi

echo "正在配置 VPN 服务端网络..."

echo "1. 开启内核转发..."
sysctl -w net.ipv4.ip_forward=1 > /dev/null

# 2. 清理旧的规则
echo "2. 清理旧规则..."
iptables -t nat -D POSTROUTING -s $SUBNET -o $PHYSICAL_INTERFACE -j MASQUERADE 2>/dev/null
iptables -D FORWARD -i $TUN_INTERFACE -o $PHYSICAL_INTERFACE -j ACCEPT 2>/dev/null
iptables -D FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null
iptables -t mangle -D FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null

# 3. 设置 NAT 地址伪装
echo "3. 设置 MASQUERADE..."
iptables -t nat -A POSTROUTING -s $SUBNET -o $PHYSICAL_INTERFACE -j MASQUERADE

# 4. 放行转发流量 (Filter 表)
echo "4. 配置转发安全策略..."
iptables -A FORWARD -i $TUN_INTERFACE -o $PHYSICAL_INTERFACE -j ACCEPT
iptables -A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT

# 5. 解决 MTU/MSS 导致的断流问题
echo "5. 优化 TCP MSS..."
iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu

echo "-------------------------------------------"
echo "配置完成！"
echo "当前 NAT 规则状态："
iptables -t nat -L POSTROUTING -n -v