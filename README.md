# SASE VPN

使用 Rust 和 tun2 库实现的安全访问服务边缘 (Secure Access Service Edge) VPN 解决方案。

## 功能特性

- ✅ 基于 TUN/TAP 虚拟网络接口
- ✅ UDP 协议传输 VPN 数据包
- ✅ 自定义协议封装
- ✅ 客户端注册和认证握手
- ✅ 心跳保活机制
- ✅ 异步 I/O 处理 (Tokio)
- ✅ 完整的服务器和客户端实现

## 系统要求

- Rust 1.70+
- Linux/macOS (需要 TUN/TAP 权限)
- Windows (需要 TAP 驱动)

## 安装依赖

### Linux
```bash
# 安装 TUN/TAP 工具
sudo apt-get install iproute2
# 或
sudo yum install iproute
```

### macOS
```bash
# TUN/TAP 通常已包含在系统中
```

### Windows
```bash
# 安装 OpenVPN TAP 驱动
# https://build.openvpn.net/downloads/releases/latest-tap-windows.html
```

## 构建项目

```bash
# 克隆或导航到项目目录
cd SASE

# 构建所有二进制文件
cargo build --release

# 构建完成后，二进制文件位于:
# - target/release/sase_server
# - target/release/sase_client
```

## 使用方法

### 启动服务器

```bash
# 基本用法 (使用默认配置)
cargo run --bin sase_server

# 或使用已构建的二进制文件
./target/release/sase_server

# 自定义配置
cargo run --bin sase_server -- \
  --bind 0.0.0.0:9999 \        # 绑定地址
  --tun tun0 \                  # TUN 设备名
  --address 10.0.0.1 \          # TUN 设备 IP
  --netmask 255.255.255.0 \     # 子网掩码
  --mtu 1500 \                  # MTU 大小
  --verbose                     # 详细日志
```

### 启动客户端

```bash
# 基本用法 (连接到本地服务器)
cargo run --bin sase_client

# 自定义配置
cargo run --bin sase_client -- \
  --server 127.0.0.1:9999 \     # 服务器地址
  --tun tun1 \                   # TUN 设备名
  --address 10.0.0.2 \           # TUN 设备 IP
  --netmask 255.255.255.0 \      # 子网掩码
  --mtu 1500 \                   # MTU 大小
  --verbose                      # 详细日志
```

### 需要管理员权限

在 Linux/macOS 上运行需要 root 权限:

```bash
# Linux
sudo ./target/release/sase_server

# macOS
sudo ./target/release/sase_client
```

## 协议格式

### 数据包头结构 (14 字节)

```
+--------+--------+----------+----------+--------+
| Magic  | Type   | ClientID | Sequence | Length |
| 4 bytes| 1 byte | 4 bytes  | 4 bytes  | 2 bytes|
+--------+--------+----------+----------+--------+
```

- **Magic**: `0x53415345` ("SASE")
- **Type**:
  - `0x01` - 数据包
  - `0x02` - 握手
  - `0x03` - 心跳
  - `0x04` - 断开连接
- **ClientID**: 客户端唯一标识符
- **Sequence**: 包序号
- **Length**: 数据载荷长度

### 连接流程

1. 客户端发送握手包到服务器
2. 服务器响应并分配 ClientID
3. 客户端开始通过 TUN 接口发送数据
4. 服务器将数据转发到对应客户端
5. 定期发送心跳保活

## 配置说明

### 服务器默认配置

- **绑定地址**: `0.0.0.0:9999`
- **TUN 设备**: `tun0`
- **TUN 地址**: `10.0.0.1`
- **子网掩码**: `255.255.255.0`
- **MTU**: `1500`

### 客户端默认配置

- **服务器地址**: `127.0.0.1:9999`
- **TUN 设备**: `tun0`
- **TUN 地址**: `10.0.0.2`
- **子网掩码**: `255.255.255.0`
- **MTU**: `1500`

## 测试连接

```bash
# 1. 启动服务器
sudo ./target/release/sase_server --verbose

# 2. 在另一个终端启动客户端
sudo ./target/release/sase_client --verbose

# 3. 测试连通性
ping 10.0.0.1  # 从客户端 ping 服务器 TUN 地址
```

## 日志级别

```bash
# 只显示错误
RUST_LOG=error cargo run --bin sase_server

# 显示信息
RUST_LOG=info cargo run --bin sase_server

# 显示详细调试信息
RUST_LOG=debug cargo run --bin sase_server --verbose
```

## 项目结构

```
SASE/
├── Cargo.toml              # 项目配置和依赖
├── README.md               # 项目文档
└── src/
    ├── common/
    │   ├── mod.rs          # 公共类型定义
    │   └── tun.rs          # TUN 设备工具函数
    ├── server/
    │   └── main.rs         # 服务器实现
    └── client/
        └── main.rs         # 客户端实现
```

## 技术栈

- **tun2**: TUN/TAP 设备抽象层
- **tokio**: 异步运行时
- **etherparse**: 网络数据包解析
- **clap**: 命令行参数解析
- **anyhow**: 错误处理
- **log/env_logger**: 日志记录

## 安全注意事项

⚠️ **当前实现的限制**:

- 没有加密功能 (数据明文传输)
- 没有身份验证机制
- 不适合生产环境使用
- 仅用于学习和开发目的

## 未来改进方向

- [ ] 添加数据加密 (AES-256-GCM)
- [ ] 实现完整的身份验证
- [ ] 支持多客户端路由
- [ ] 添加配置文件支持
- [ ] 实现 TCP 作为备选传输协议
- [ ] 添加 Web 管理界面
- [ ] 支持更多平台

## 许可证

MIT License

## 贡献

欢迎提交 Issue 和 Pull Request!
