# SASE VPN

<div align="center">

**Simple And Secure VPN** - 用 Rust 实现的轻量级 VPN 解决方案

[![Rust](https://img.shields.io/badge/rust-1.70%2B-orange.svg)](https://www.rust-lang.org/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

</div>

---

## 📖 目录

- [简介](#简介)
- [功能特性](#功能特性)
- [快速开始](#快速开始)
- [使用方法](#使用方法)
- [协议说明](#协议说明)
- [架构设计](#架构设计)
- [配置参考](#配置参考)
- [开发指南](#开发指南)
- [安全警告](#安全警告)
- [路线图](#路线图)

---

## 🎯 简介

SASE (Simple And Secure VPN) 是一个使用 Rust 编写的高性能 VPN 解决方案。它采用自定义协议实现客户端-服务器通信，通过 TUN/TAP 虚拟网络接口提供安全的网络隧道服务。

### 设计理念

- **简洁性**: 最小化的代码复杂度，易于理解和维护
- **安全性**: 虽然当前版本未加密，但架构设计为后续加密预留空间
- **高性能**: 基于 Rust 的零成本抽象和内存安全保证
- **跨平台**: 支持 Linux、macOS 和 Windows

---

## ✨ 功能特性

### 核心功能

- ✅ **TUN/TAP 虚拟网络接口** - 支持 L3 层网络隧道
- ✅ **UDP 传输协议** - 低延迟的数据包传输
- ✅ **自定义二进制协议** - 高效的数据封装
- ✅ **客户端注册与认证** - 握手机制分配唯一 ID
- ✅ **心跳保活机制** - 自动检测连接状态
- ✅ **多客户端支持** - 服务器可同时处理多个客户端
- ✅ **命令行界面** - 统一的 CLI 工具，支持子命令

### 技术亮点

- 🚀 基于 Rust 的高性能异步 I/O (Tokio)
- 🛡️ 内存安全保证，无需 GC
- 🔧 灵活的配置系统
- 📊 结构化日志输出
- 🧪 模块化代码设计

---

## 🚀 快速开始

### 系统要求

| 平台 | 要求 |
|------|------|
| **Rust** | 1.70 或更高版本 |
| **Linux** | root 权限，TUN/TAP 支持 |
| **macOS** | root 权限，TUN/TAP 支持 |
| **Windows** | TAP 驱动 (WinTUN 或 OpenVPN TAP) |

### 安装依赖

<details>
<summary><b>Linux</b></summary>

```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install iproute2 build-essential

# CentOS/RHEL
sudo yum install iproute build-essential

# Arch Linux
sudo pacman -S iproute base-devel
```
</details>

<details>
<summary><b>macOS</b></summary>

```bash
# 安装 Homebrew (如果尚未安装)
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# 安装 TUN/TAP 工具
brew install tuntap
```
</details>

<details>
<summary><b>Windows</b></summary>

```bash
# WinTUN 会自动通过 tun2 crate 下载
# 或手动安装 OpenVPN TAP 驱动
# https://build.openvpn.net/downloads/releases/latest-tap-windows.html
```
</details>

### 构建项目

```bash
# 1. 克隆仓库 (如果适用)
cd SASE

# 2. Debug 模式构建 (快速编译)
cargo build

# 3. Release 模式构建 (优化性能)
cargo build --release

# 构建产物位置:
# Windows: target/release/sase.exe
# Linux/macOS: target/release/sase
```

### 快速测试

```bash
# 终端 1: 启动服务器
sudo ./target/release/sase server

# 终端 2: 启动客户端
sudo ./target/release/sase client

# 终端 3: 测试连接 (在客户端上)
ping 10.0.0.1
```

---

## 📚 使用方法

### 命令概览

```bash
sase <COMMAND>

命令:
  server  启动 VPN 服务器
  client  启动 VPN 客户端
  help    显示帮助信息

选项:
  -h, --help     显示帮助
  -V, --version  显示版本信息
```

### 服务器模式

```bash
# 基本用法 (使用默认配置)
sase server

# 完整配置示例
sase server \
  --bind 0.0.0.0:9999 \
  --tun tun0 \
  --address 10.0.0.1 \
  --netmask 255.255.255.0 \
  --mtu 1500 \
  --verbose

# 参数说明
# -b, --bind <ADDR>        UDP 绑定地址 (默认: 0.0.0.0:9999)
# -t, --tun <NAME>         TUN 设备名称 (默认: tun0)
# -a, --address <IP>       TUN 设备 IP 地址 (默认: 10.0.0.1)
# -n, --netmask <MASK>     子网掩码 (默认: 255.255.255.0)
# -m, --mtu <SIZE>         最大传输单元 (默认: 1500)
# -v, --verbose            启用详细日志
```

### 客户端模式

```bash
# 基本用法 (连接到本地服务器)
sase client

# 连接到远程服务器
sase client \
  --server 192.168.1.100:9999 \
  --tun tun1 \
  --address 10.0.0.2 \
  --netmask 255.255.255.0 \
  --mtu 1500 \
  --verbose

# 参数说明
# -s, --server <ADDR>      服务器地址 (默认: 127.0.0.1:9999)
# -t, --tun <NAME>         TUN 设备名称 (默认: tun0)
# -a, --address <IP>       TUN 设备 IP 地址 (默认: 10.0.0.2)
# -n, --netmask <MASK>     子网掩码 (默认: 255.255.255.0)
# -m, --mtu <SIZE>         最大传输单元 (默认: 1500)
# -v, --verbose            启用详细日志
```

### 日志控制

```bash
# 设置日志级别
RUST_LOG=error sase server   # 仅错误
RUST_LOG=warn sase server    # 警告及以上
RUST_LOG=info sase server    # 信息及以上 (默认)
RUST_LOG=debug sase server   # 调试信息
RUST_LOG=trace sase server   # 追踪信息

# 结合 verbose 标志
sase server --verbose        # 启用详细日志 (等同于 RUST_LOG=debug)
```

---

## 🔧 协议说明

### 数据包结构

SASE 使用自定义的二进制协议，所有数据包包含 15 字节的固定头部:

```
+--------+--------+----------+----------+--------+==========+
| Magic  | Type   | ClientID | Sequence | Length |  Payload |
| 4 bytes| 1 byte | 4 bytes  | 4 bytes  | 2 bytes| Variable |
+--------+--------+----------+----------+--------+==========+
```

| 字段 | 大小 | 说明 |
|------|------|------|
| **Magic** | 4 bytes | 协议魔数: `0x53415345` ("SASE") |
| **Type** | 1 byte | 数据包类型 (见下表) |
| **ClientID** | 4 bytes | 客户端唯一标识符 |
| **Sequence** | 4 bytes | 数据包序列号 |
| **Length** | 2 bytes | Payload 长度 (0-65535) |
| **Payload** | Variable | 实际数据 (可选) |

### 数据包类型

| 类型值 | 名称 | 说明 |
|--------|------|------|
| `0x01` | DATA | 网络数据包 |
| `0x02` | HANDSHAKE | 握手/认证包 |
| `0x03` | KEEPALIVE | 心跳保活包 |
| `0x04` | DISCONNECT | 断开连接通知 |

### 连接建立流程

```
客户端                                    服务器
  |                                        |
  |----- HANDSHAKE (ClientID=0) --------->|
  |                                        |
  |                                         [分配 ClientID]
  |<---- HANDSHAKE (ClientID=1) ----------|
  |                                        |
  |======== VPN 隧道已建立 =========|
  |                                        |
  |<==== KEEPALIVE (每 10 秒) ==========|
  |                                        |
  |----- DATA (Seq=1) ------------------>|
  |----- DATA (Seq=2) ------------------>|
  |                                        |
  |<==== DATA (Seq=1) ===================|
```

---

## 🏗️ 架构设计

### 项目结构

```
SASE/
├── Cargo.toml              # 项目配置和依赖管理
├── README.md               # 项目文档
└── src/
    ├── main.rs             # 统一 CLI 入口点
    ├── common.rs           # 共享类型和协议定义
    ├── sase_server.rs      # VPN 服务器实现
    └── sase_client.rs      # VPN 客户端实现
```

### 模块说明

#### `main.rs` - CLI 入口
- 使用 `clap` 解析命令行参数
- 子命令路由 (`server` / `client`)
- 日志系统初始化

#### `common.rs` - 共享模块
- **配置结构** (`ServerConfig`, `ClientConfig`)
- **常量定义** (MTU、端口等)
- **TUN I/O 任务** (`tun_io_task`)
- **IP 包信息打印** (`print_packet_info`)

#### `sase_server.rs` - 服务器
- UDP socket 监听和数据处理
- 客户端注册和状态管理
- TUN 接口数据转发
- 心跳响应机制

#### `sase_client.rs` - 客户端
- 服务器连接和握手
- TUN 接口创建和配置
- 数据包序列化传输
- 心跳定时器

### 技术栈

| 依赖 | 版本 | 用途 |
|------|------|------|
| [tun2](https://crates.io/crates/tun2) | 1.0 | TUN/TAP 设备抽象 |
| [tokio](https://crates.io/crates/tokio) | 1.40 | 异步运行时 |
| [clap](https://crates.io/crates/clap) | 4.5 | CLI 参数解析 |
| [anyhow](https://crates.io/crates/anyhow) | 1.0 | 错误处理 |
| [log](https://crates.io/crates/log) | 0.4 | 日志门面 |
| [env_logger](https://crates.io/crates/env_logger) | 0.11 | 日志实现 |

---

## ⚙️ 配置参考

### 默认配置

#### 服务器

| 参数 | 默认值 | 说明 |
|------|--------|------|
| 绑定地址 | `0.0.0.0:9999` | UDP 监听地址 |
| TUN 设备 | `tun0` | 虚拟网卡名称 |
| TUN 地址 | `10.0.0.1` | 虚拟网卡 IP |
| 子网掩码 | `255.255.255.0` | 网络掩码 |
| MTU | `1500` | 最大传输单元 |

#### 客户端

| 参数 | 默认值 | 说明 |
|------|--------|------|
| 服务器地址 | `127.0.0.1:9999`` | 服务器 UDP 地址 |
| TUN 设备 | `tun0` | 虚拟网卡名称 |
| TUN 地址 | `10.0.0.2` | 虚拟网卡 IP |
| 子网掩码 | `255.255.255.0` | 网络掩码 |
| MTU | `1500` | 最大传输单元 |
| 心跳间隔 | `10 秒` | 保活包发送间隔 |

### 网络拓扑示例

```
服务器侧                          客户端侧
(10.0.0.1)                       (10.0.0.2)
    |                                 |
    | tun0                           tun1
    |                                 |
    +----------- UDP 9999 -----------+
        Internet/VPN 隧道
```

---

## 🛠️ 开发指南

### 环境配置

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
cargo watch -x run -- server

# 运行测试
cargo test

# 检查代码 (不编译)
cargo check

# 格式化代码
cargo fmt

# Linter 检查
cargo clippy

# 生成文档
cargo doc --open
```

### 添加新功能

1. 在 `common.rs` 中定义共享类型
2. 在 `sase_server.rs` 或 `sase_client.rs` 中实现逻辑
3. 更新命令行参数 (如需要)
4. 添加测试用例
5. 更新文档

### 调试技巧

```bash
# 启用详细日志
RUST_LOG=trace sase server --verbose

# 使用 Rust 调试器
rust-lldb ./target/debug/sase server

# 内存泄漏检测
valgrind --leak-check=full ./target/release/sase server
```

---

## ⚠️ 安全警告

<div align="center">

**🚨 重要: 本项目当前不适合生产环境使用 🚨**

</div>

### 当前限制

- ❌ **无加密**: 所有数据以明文传输
- ❌ **无身份验证**: 任何人都可以连接到服务器
- ❌ **无完整性保护**: 数据可能被中间人篡改
- ❌ **无重放攻击防护**: 数据包可能被截获和重放
- ❌ **无前向保密**: 密钥泄露会影响所有历史通信

### 适用场景

✅ **学习和研究** - 理解 VPN 原理和 Rust 网络编程
✅ **本地测试** - 开发和测试网络应用
✅ **原型开发** - 作为更复杂系统的基础

❌ **生产环境** - 需要安全加密的场景
❌ **敏感数据** - 传输私密信息的场景
❌ **不受信任网络** - 公共互联网环境

### 安全最佳实践

如果要在生产环境使用，建议:

1. **启用加密**: 添加 AES-256-GCM 或 ChaCha20-Poly1305
2. **身份验证**: 实现证书或预共享密钥认证
3. **使用 WireGuard**: 对于生产环境，推荐使用成熟的 [WireGuard](https://www.wireguard.com/) VPN

---

## 🗺️ 路线图

### 已完成 ✅

- [x] 基础 TUN/TAP 支持
- [x] UDP 数据传输
- [x] 客户端-服务器架构
- [x] 握手和保活机制
- [x] 统一 CLI 界面

### 计划中 🚧

#### 优先级: 高

- [ ] **数据加密** (AES-256-GCM)
  - 密钥交换 (ECDH)
  - 数据包加密/解密
  - 密钥轮换机制

- [ ] **身份验证**
  - 预共享密钥 (PSK)
  - 数字证书 (X.509)
  - 客户端白名单

- [ ] **数据完整性**
  - HMAC 签名
  - 防重放攻击
  - 时间戳验证

#### 优先级: 中

- [ ] **配置文件**
  - TOML/YAML 配置
  - 多配置文件支持
  - 热重载

- [ ] **路由功能**
  - 客户端间通信
  - 多网段支持
  - 路由表管理

- [ ] **性能优化**
  - 零拷贝 I/O
  - 批量数据包处理
  - CPU 亲和性优化

#### 优先级: 低

- [ ] **管理界面**
  - Web Dashboard
  - REST API
  - 实时监控

- [ ] **高级特性**
  - TCP 传输模式
  - 多路复用
  - 压缩支持
  - IPv6 支持

- [ ] **平台支持**
  - Android (实验性)
  - iOS (实验性)
  - FreeBSD

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

## 🤝 贡献

我们欢迎所有形式的贡献!

### 如何贡献

1. Fork 本仓库
2. 创建特性分支 (`git checkout -b feature/AmazingFeature`)
3. 提交更改 (`git commit -m 'Add some AmazingFeature'`)
4. 推送到分支 (`git push origin feature/AmazingFeature`)
5. 开启 Pull Request

### 贡献指南

- 遵循 Rust 代码规范 (`cargo fmt`)
- 通过 Clippy 检查 (`cargo clippy`)
- 添加测试用例
- 更新相关文档
- 保持提交信息清晰

### 报告问题

请在 [Issues](https://github.com/yourusername/SASE/issues) 中报告 bug 或提出功能请求。

---

## 📞 联系方式

- **项目主页**: [GitHub Repository](https://github.com/yourusername/SASE)
- **问题反馈**: [Issue Tracker](https://github.com/yourusername/SASE/issues)
- **讨论区**: [Discussions](https://github.com/yourusername/SASE/discussions)

---

## 🙏 致谢

本项目基于以下优秀的开源项目:

- [tun2](https://github.com/vvvparty/tun2) - TUN/TAP 设备抽象
- [Tokio](https://tokio.rs/) - 异步运行时
- [Clap](https://github.com/clap-rs/clap) - CLI 框架
- [WireGuard](https://www.wireguard.com/) - 现代 VPN 协议参考

---

<div align="center">

**用 ❤️ 和 Rust 构建**

[⬆ 返回顶部](#sase-vpn)

</div>
