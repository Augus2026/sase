# SASE VPN

cargo run --release -- client --transport udp --server 192.168.147.146:12345
cargo run --release -- server --transport tcp --bind 0.0.0.0:12345 --tun tun1 --address 10.0.0.1

<div align="center">
**Simple And Secure VPN** - 基于 Rust 的高性能 VPN 解决方案

[![Rust](https://img.shields.io/badge/rust-1.70%2B-orange.svg)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey.svg)]()

</div>

---

## 📖 目录

- [项目简介](#项目简介)
- [核心特性](#核心特性)
- [快速开始](#快速开始)
- [使用指南](#使用指南)
- [协议设计](#协议设计)
- [架构概览](#架构概览)
- [配置说明](#配置说明)
- [开发文档](#开发文档)
- [安全警示](#安全警示)
- [路线图](#路线图)

---

## 🎯 项目简介

SASE (Simple And Secure VPN) 是一个使用 Rust 编写的现代 VPN 解决方案，采用模块化架构设计，支持多种传输协议，提供高性能的网络安全隧道服务。

### 设计理念

- **高性能** - 利用 Rust 的零成本抽象和 Tokio 异步运行时
- **模块化** - 清晰的代码结构，易于扩展和维护
- **跨平台** - 支持 Linux、macOS 和 Windows 系统
- **灵活性** - 支持多种传输协议和配置选项
- **安全性** - 为加密和安全预留完善的架构设计

---

## ✨ 核心特性

### 技术特性

- ✅ **多协议支持** - UDP、TCP 和 WS (WebSocket) 传输协议
- ✅ **TUN/TAP 接口** - 支持第 3 层网络隧道
- ✅ **异步 I/O** - 基于 Tokio 的高性能异步处理
- ✅ **自定义协议** - 高效的二进制数据封装
- ✅ **客户端管理** - 支持多客户端连接和状态跟踪
- ✅ **心跳机制** - 自动检测和维护连接状态
- ✅ **模块化编解码** - 可扩展的协议编解码系统
- ✅ **结构化日志** - 完善的日志记录和调试支持

### 技术栈

| 组件 | 技术 | 版本 |
|------|------|------|
| 语言 | Rust | 1.70+ |
| 运行时 | Tokio | 1.40 |
| 网络接口 | tun2 | 4.0 |
| 协议解析 | etherparse | 0.19 |
| WebSocket | tokio-tungstenite | 0.24 |
| CLI 框架 | clap | 4.5 |
| 序列化 | serde | 1.0 |

---

## 🚀 快速开始

### 系统要求

| 平台 | 最低要求 |
|------|----------|
| **Rust** | 1.70 或更高版本 |
| **Linux** | root 权限，TUN/TAP 内核支持 |
| **macOS** | root 权限，TUN/TAP 支持 |
| **Windows** | WinTUN 或 OpenVPN TAP 驱动 |

### 安装依赖

<details>
<summary><b>Linux 系统</b></summary>

```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install iproute2 build-essential

# CentOS/RHEL
sudo yum install iproute gcc make

# Arch Linux
sudo pacman -S iproute base-devel
```
</details>

<details>
<summary><b>macOS 系统</b></summary>

```bash
# 安装 Homebrew (如果尚未安装)
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# 安装 TUN/TAP 工具
brew install tuntap
```
</details>

<details>
<summary><b>Windows 系统</b></summary>

```bash
# WinTUN 会通过 tun2 crate 自动下载
# 或手动安装 OpenVPN TAP 驱动
# https://build.openvpn.net/downloads/releases/latest-tap-windows.html
```
</details>

### 编译安装

```bash
# 1. 克隆项目
git clone <repository-url>
cd SASE

# 2. Debug 模式编译 (快速编译，便于开发调试)
cargo build

# 3. Release 模式编译 (优化性能，生产环境推荐)
cargo build --release

# 编译产物位置:
# Windows: target/release/sase.exe
# Linux/macOS: target/release/sase
```

### 快速测试

```bash
# 终端 1: 启动服务器 (TCP 协议)
sudo ./target/release/sase server --transport tcp --bind 0.0.0.0:12345 --tun tun0 --address 10.0.0.1

# 终端 2: 启动客户端 (连接到服务器)
sudo ./target/release/sase client --transport tcp --server 127.0.0.1:12345

# 终端 3: 测试网络连接 (在客户端上)
ping 10.0.0.1
```

---

## 📚 使用指南

### 命令行界面

```bash
sase <COMMAND>

命令:
  server  启动 VPN 服务器
  client  启动 VPN 客户端
  help    显示帮助信息

全局选项:
  -h, --help              显示帮助信息
  -V, --version           显示版本信息
  -l, --log-level <LEVEL> 设置日志级别 (error/warn/info/debug/trace)
```

### 服务器模式

```bash
# 基本用法 (使用默认配置)
sase server

# 完整配置示例 (TCP 协议)
sase server \
  --transport tcp \
  --bind 0.0.0.0:12345 \
  --tun tun0 \
  --address 10.0.0.1 \
  --netmask 255.255.255.0 \
  --mtu 1500 \
  --log-level debug

# UDP 协议示例
sase server \
  --transport udp \
  --bind 0.0.0.0:9999 \
  --tun tun1 \
  --address 10.0.0.1

# WS 协议示例
sase server \
  --transport ws \
  --bind 0.0.0.0:8443 \
  --tun tun2 \
  --address 10.0.0.1
```

**服务器参数说明：**

| 参数 | 简写 | 默认值 | 说明 |
|------|------|--------|------|
| `--transport` | 无 | `tcp` | 传输协议 (tcp/udp/ws) |
| `--bind` | `-b` | `0.0.0.0:12345` | 监听地址和端口 |
| `--tun` | `-u` | `tun0` | TUN 设备名称 |
| `--address` | `-a` | `10.0.0.1` | TUN 设备 IP 地址 |
| `--netmask` | `-n` | `255.255.255.0` | 子网掩码 |
| `--mtu` | `-m` | `1500` | 最大传输单元 |
| `--log-level` | `-l` | `info` | 日志级别 |

### 客户端模式

```bash
# 基本用法 (连接到本地服务器)
sase client

# 连接到远程服务器 (TCP 协议)
sase client \
  --transport tcp \
  --server 192.168.1.100:12345

# 完整配置示例
sase client \
  --transport udp \
  --server 192.168.1.100:9999 \
  --log-level debug
```

# 完整配置示例
sase client \
  --transport udp \
  --server 192.168.1.100:9999 \
  --log-level debug

# WS 协议示例
sase client \
  --transport ws \
  --server 192.168.1.100:8443 \
  --log-level debug
```

**客户端参数说明：**

| 参数 | 简写 | 默认值 | 说明 |
|------|------|--------|------|
| `--transport` | 无 | `tcp` | 传输协议 (tcp/udp/ws) |
| `--server` | `-s` | `127.0.0.1:12345` | 服务器地址和端口 |
| `--log-level` | `-l` | `info` | 日志级别 |

### 日志控制

```bash
# 通过命令行设置日志级别
sase server --log-level error    # 仅错误
sase server --log-level warn     # 警告及以上
sase server --log-level info     # 信息及以上 (默认)
sase server --log-level debug    # 调试信息
sase server --log-level trace    # 追踪信息

# 通过环境变量设置日志级别
RUST_LOG=error sase server
RUST_LOG=sase=debug sase client
```

---

## 🔧 协议设计

### 消息类型

SASE 使用结构化的消息协议，支持多种消息类型：

| 类型值 | 名称 | 说明 |
|--------|------|------|
| `0x01` | Handshake | 客户端注册和认证 |
| `0x02` | Data | 网络数据传输 |
| `0x03` | KeepAlive | 心跳保活机制 |
| `0x04` | Disconnect | 断开连接通知 |

### 协议结构

```rust
// 消息类型枚举
pub enum MessageType {
    Handshake = 1,
    Data = 2,
    KeepAlive = 3,
    Disconnect = 4,
}

// 消息结构
pub struct Message {
    pub message_type: u8,    // 消息类型
    pub data: Vec<u8>,       // 消息数据
}
```

### 连接流程

```
客户端                                    服务器
  |                                        |
  |----- Handshake (ClientID=0) --------->|
  |                                        |
  |                                         [分配 ClientID]
  |<---- Handshake (ClientID=1) ----------|
  |                                        |
  |======== VPN 隧道已建立 =========|
  |                                        |
  |<==== KeepAlive (定期) ==============|
  |----- KeepAlive (响应) --------------->|
  |                                        |
  |----- Data (网络包) ------------------>|
  |<==== Data (网络包) ===================|
  |                                        |
  |----- Disconnect (可选) ------------->|
```

### 传输协议

#### TCP 传输
- 提供可靠的连接建立和数据传输
- 适合不稳定网络环境
- 内置连接保活机制

#### UDP 传输
- 低延迟，高性能
- 适合稳定网络环境
- 需要应用层可靠性保证

#### WS (WebSocket) 传输
- 基于 WebSocket 协议的安全传输
- 适合通过代理和防火墙的场景
- 支持 TLS 加密（需要配置证书，使用 wss:// 前缀）
- 跨浏览器兼容性强

---

## 🏗️ 架构概览

### 项目结构

```
SASE/
├── Cargo.toml                  # 项目配置和依赖管理
├── README.md                   # 项目文档
└── src/
    ├── main.rs                 # CLI 入口点
    ├── common.rs               # 公共类型定义
    ├── tun_config.rs           # TUN 接口配置
    ├── sase_server.rs          # 服务器实现
    ├── sase_client.rs          # 客户端实现
    ├── codec/                  # 协议编解码模块
    │   ├── mod.rs
    │   ├── codec.rs           # 编解码器实现
    │   └── message.rs         # 消息类型定义
    └── transport/              # 传输层模块
        ├── mod.rs
        └── transport.rs       # 传输抽象
```

### 核心模块

#### `main.rs` - 应用入口
- 命令行参数解析 (clap)
- 子命令路由 (server/client)
- 日志系统初始化

#### `sase_server.rs` - 服务器
- 传输层抽象实现
- 客户端连接管理
- TUN 接口数据处理
- 消息路由和转发

#### `sase_client.rs` - 客户端
- 服务器连接和握手
- TUN 接口创建和配置
- 数据包序列化传输
- 心跳保活机制

#### `codec/` - 编解码模块
- 消息序列化/反序列化
- 协议类型定义
- 扩展的编解码器

#### `transport/` - 传输层
- TCP/UDP 传输抽象
- 连接管理
- 数据收发接口

### 技术架构

```
┌─────────────────────────────────────────────────┐
│              应用层 (CLI)                        │
│              main.rs                            │
└──────────────────┬──────────────────────────────┘
                   │
        ┌──────────┴──────────┐
        │                     │
┌───────▼────────┐  ┌────────▼─────────┐
│   Server      │  │     Client       │
│ sase_server.rs│  │ sase_client.rs  │
└───────┬────────┘  └────────┬────────┘
        │                     │
        └──────────┬──────────┘
                   │
        ┌──────────▼──────────┐
        │    Codec Module     │
        │  (message.rs)       │
        └──────────┬──────────┘
                   │
        ┌──────────▼──────────┐
        │  Transport Module   │
        │ (transport.rs)      │
        └──────────┬──────────┘
                   │
        ┌──────────▼──────────┐
        │   Tokio Runtime     │
        │  (Async I/O)        │
        └─────────────────────┘
```

---

## ⚙️ 配置说明

### 默认配置

#### 服务器默认值

| 配置项 | 默认值 | 说明 |
|--------|--------|------|
| 传输协议 | `tcp` | TCP 连接 (支持 tcp/udp/ws) |
| 绑定地址 | `0.0.0.0:12345` | 监听所有网络接口 |
| TUN 设备 | `tun0` | 虚拟网络设备 |
| TUN 地址 | `10.0.0.1` | 虚拟网络 IP |
| 子网掩码 | `255.255.255.0` | 网络掩码 |
| MTU | `1500` | 最大传输单元 |

#### 客户端默认值

| 配置项 | 默认值 | 说明 |
|--------|--------|------|
| 传输协议 | `tcp` | TCP 连接 (支持 tcp/udp/ws) |
| 服务器地址 | `127.0.0.1:12345` | 本地服务器 |
| TUN 设备 | `tun0` | 虚拟网络设备 |
| TUN 地址 | `10.0.0.2` | 虚拟网络 IP |
| 子网掩码 | `255.255.255.0` | 网络掩码 |
| 心跳间隔 | `10 秒` | 保活包间隔 |

### 网络拓扑

```
服务器网络环境                    客户端网络环境
(10.0.0.1)                      (10.0.0.2)
    │                                 │
    │ tun0                            │ tun1
    │                                 │
    │ VPN 隧道 (TCP/UDP:12345)       │
    └─────────────────────────────────┘
           公共网络/互联网
```

---

## 🛠️ 开发文档

### 开发环境配置

```bash
# 安装 Rust 工具链
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# 安装开发工具
cargo install cargo-watch   # 自动重新编译
cargo install cargo-edit     # 依赖管理
```

### 开发工作流

```bash
# 监视文件变化并自动重新编译
cargo watch -x 'run -- server'

# 运行测试
cargo test

# 代码检查
cargo check

# 代码格式化
cargo fmt

# Linter 检查
cargo clippy

# 生成文档
cargo doc --open
```

### 调试技巧

```bash
# 启用详细日志
cargo run -- server --log-level trace

# 使用 Rust 调试器
rust-gdb ./target/debug/sase server

# 内存分析
valgrind --leak-check=full ./target/release/sase server
```

### 代码规范

- 遵循 Rust 官方代码风格指南
- 使用 `cargo fmt` 自动格式化代码
- 通过 `cargo clippy` 进行代码质量检查
- 为公共 API 添加文档注释
- 为关键逻辑添加单元测试

---

## ⚠️ 安全警示

<div align="center">

**🚨 重要警告：本项目当前不适合生产环境使用 🚨**

</div>

### 当前限制

- ❌ **无加密保护** - 数据以明文形式传输
- ❌ **无身份认证** - 缺乏客户端身份验证机制
- ❌ **无完整性校验** - 数据可能被中间人篡改
- ❌ **无重放攻击防护** - 数据包可能被截获和重放
- ❌ **无前向保密** - 密钥泄露会影响历史通信安全

### 适用场景

✅ **学习和研究** - 理解 VPN 原理和 Rust 网络编程
✅ **开发测试** - 本地网络开发和测试
✅ **原型验证** - 作为复杂系统的基础框架
✅ **教育用途** - 网络安全和系统编程教学

❌ **生产部署** - 需要安全加密的实际环境
❌ **敏感数据** - 传输私密或机密信息
❌ **公共网络** - 在不受信任的互联网环境中使用

### 安全建议

如需在生产环境使用，建议采取以下措施：

1. **启用加密** - 实现强加密算法 (AES-256-GCM, ChaCha20-Poly1305)
2. **身份认证** - 添加数字证书或预共享密钥机制
3. **使用成熟方案** - 推荐使用 [WireGuard](https://www.wireguard.com/) 等生产级 VPN 解决方案

---

## 🗺️ 路线图

### 已完成 ✅

- [x] 基础 TUN/TAP 接口支持
- [x] TCP 传输协议实现
- [x] UDP 传输协议实现
- [x] WS (WebSocket) 传输协议实现
- [x] 客户端-服务器架构
- [x] 握手和保活机制
- [x] 统一 CLI 界面
- [x] 模块化编解码系统
- [x] 结构化日志记录

### 开发中 🚧

#### 高优先级

- [ ] **安全加密层**
  - 密钥交换协议 (ECDH)
  - 数据包加密/解密
  - 密钥轮换机制

- [ ] **身份认证系统**
  - 预共享密钥 (PSK) 支持
  - 数字证书认证 (X.509)
  - 客户端白名单机制

- [ ] **数据完整性保护**
  - HMAC 消息认证码
  - 防重放攻击机制
  - 时间戳验证

#### 中优先级

- [ ] **配置文件支持**
  - TOML/YAML 配置格式
  - 多配置文件管理
  - 配置热重载功能

- [ ] **路由功能增强**
  - 客户端间通信支持
  - 多网段路由配置
  - 动态路由表管理

- [ ] **性能优化**
  - 零拷贝 I/O 优化
  - 批量数据包处理
  - CPU 亲和性配置

#### 低优先级

- [ ] **管理界面**
  - Web Dashboard
  - REST API 接口
  - 实时监控面板

- [ ] **高级特性**
  - IPv6 协议支持
  - 数据压缩功能
  - 多路复用传输

- [ ] **平台扩展**
  - Android 客户端 (实验性)
  - iOS 客户端 (实验性)
  - FreeBSD 系统支持

---

## 📄 许可证

本项目采用 MIT 许可证 - 详见 [LICENSE](LICENSE) 文件

```
MIT License

Copyright (c) 2025 SASE VPN Contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

## 🤝 贡献指南

我们欢迎所有形式的贡献！

### 贡献流程

1. Fork 本仓库到你的 GitHub 账户
2. 创建特性分支 (`git checkout -b feature/AmazingFeature`)
3. 提交你的更改 (`git commit -m 'Add some AmazingFeature'`)
4. 推送到分支 (`git push origin feature/AmazingFeature`)
5. 开启 Pull Request

### 代码规范

- 遵循 Rust 代码规范 (`cargo fmt`)
- 通过 Clippy 检查 (`cargo clippy`)
- 为新功能添加测试用例
- 更新相关文档
- 保持清晰的提交信息

### 问题报告

请在 [Issues](https://github.com/yourusername/SASE/issues) 中报告 bug 或提出功能请求。

---

## 📞 联系方式

- **项目主页**: [GitHub Repository](https://github.com/yourusername/SASE)
- **问题反馈**: [Issue Tracker](https://github.com/yourusername/SASE/issues)
- **功能讨论**: [Discussions](https://github.com/yourusername/SASE/discussions)

---

## 🙏 致谢

本项目基于以下优秀的开源项目和库：

- [tun2](https://github.com/vvvparty/tun2) - 跨平台 TUN/TAP 设备抽象
- [Tokio](https://tokio.rs/) - 异步运行时框架
- [Clap](https://github.com/clap-rs/clap) - 命令行参数解析框架
- [WireGuard](https://www.wireguard.com/) - 现代 VPN 协议设计参考
- [etherparse](https://github.com/JulianSchmid/etherparse) - 以太网/IP 协议解析库

---

<div align="center">

**使用 ❤️ 和 Rust 构建高性能 VPN 解决方案**

[⬆ 返回顶部](#sase-vpn)

</div>
