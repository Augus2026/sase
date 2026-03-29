//! 数据包分流测试工具
//!
//! 用法:
//!   cargo run --bin routing_test                        # 运行内置测试
//!   cargo run --bin routing_test -- --interactive       # 交互模式
//!   cargo run --bin routing_test -- --packet 192.168.1.100,10.0.0.5,80,tcp

use clap::Parser;
use sase_routing::{
    action::RoutingAction,
    context::PacketContext,
    engine::{HotReloadableEngine, RoutingEngine},
    rule::Protocol,
};
use std::io::Write;
use std::net::Ipv4Addr;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "routing_test")]
#[command(about = "数据包分流规则测试工具", long_about = None)]
struct Args {
    /// 规则配置文件路径
    #[arg(short, long, default_value = "config/rules.toml")]
    rules: PathBuf,

    /// 交互模式
    #[arg(short, long)]
    interactive: bool,

    /// 测试单个数据包: src_ip,dst_ip,dst_port,protocol
    /// 例如: --packet 192.168.1.100,8.8.8.8,443,tcp
    #[arg(short, long)]
    packet: Option<String>,

    /// 批量测试模式
    #[arg(long)]
    batch: bool,
}

fn parse_packet(s: &str) -> Option<(Ipv4Addr, Ipv4Addr, Option<u16>, Protocol)> {
    let parts: Vec<&str> = s.split(',').collect();
    if parts.len() < 2 {
        return None;
    }

    let src_ip: Ipv4Addr = parts[0].parse().ok()?;
    let dst_ip: Ipv4Addr = parts[1].parse().ok()?;
    let dst_port = if parts.len() > 2 && !parts[2].is_empty() {
        Some(parts[2].parse().ok()?)
    } else {
        None
    };
    let protocol = if parts.len() > 3 {
        match parts[3].to_lowercase().as_str() {
            "tcp" => Protocol::Tcp,
            "udp" => Protocol::Udp,
            "icmp" => Protocol::Icmp,
            _ => Protocol::Tcp,
        }
    } else {
        Protocol::Tcp
    };

    Some((src_ip, dst_ip, dst_port, protocol))
}

fn action_icon(action: &RoutingAction) -> &'static str {
    match action {
        RoutingAction::Direct => "📡",
        RoutingAction::Intranet => "🏠",
        RoutingAction::Proxy => "🌐",
        RoutingAction::Drop => "🚫",
    }
}

fn action_name(action: &RoutingAction) -> &'static str {
    match action {
        RoutingAction::Direct => "直连",
        RoutingAction::Intranet => "内网",
        RoutingAction::Proxy => "代理",
        RoutingAction::Drop => "阻断",
    }
}

fn print_header(title: &str) {
    println!("{}", "=".repeat(60));
    println!("{}", title);
    println!("{}", "=".repeat(60));
}

fn print_decision(decision: &sase_routing::decision::RoutingDecision, packet: &PacketContext) {
    println!();
    println!("┌{}", "─".repeat(58));
    println!("│ 📥 数据包信息:");
    println!("│    源 IP:    {}", packet.src_ip);
    println!("│    目标 IP:  {}", packet.dst_ip);
    println!(
        "│    目标端口: {}",
        packet.dst_port.map_or("N/A".to_string(), |p| p.to_string())
    );
    println!("│    协议:     {}", packet.protocol);
    println!("├{}", "─".repeat(58));
    println!("│ 🔀 路由决策:");
    println!(
        "│    动作:     {} {}",
        action_icon(&decision.action),
        action_name(&decision.action)
    );

    if decision.is_default {
        println!("│    规则:     (默认动作)");
    } else {
        println!(
            "│    规则:     {} (ID: {})",
            decision.rule_name.as_deref().unwrap_or("N/A"),
            decision.rule_id.unwrap_or(0)
        );
    }
    println!("└{}", "─".repeat(58));
}

fn test_single_packet(
    engine: &RoutingEngine,
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    dst_port: Option<u16>,
    protocol: Protocol,
) {
    let packet = PacketContext::new(src_ip, dst_ip, None, dst_port, protocol);
    let decision = engine.match_packet(&packet);
    print_decision(&decision, &packet);
}

fn test_builtin_scenarios(engine: &RoutingEngine) {
    println!();
    println!("{}", "=".repeat(60));
    println!("🧪 运行内置测试场景");
    println!("{}", "=".repeat(60));

    let scenarios = vec![
        ("内网流量-10段", "192.168.1.100", "10.0.0.5", Some(80), Protocol::Tcp),
        ("内网流量-172段", "192.168.1.100", "172.16.0.1", Some(443), Protocol::Tcp),
        ("内网流量-192段", "192.168.1.100", "192.168.2.1", Some(22), Protocol::Tcp),
        ("HTTPS代理", "192.168.1.100", "8.8.8.8", Some(443), Protocol::Tcp),
        ("HTTP直连", "192.168.1.100", "8.8.8.8", Some(80), Protocol::Tcp),
        ("SSH阻断", "192.168.1.100", "1.2.3.4", Some(22), Protocol::Tcp),
        ("DNS查询", "192.168.1.100", "8.8.8.8", Some(53), Protocol::Udp),
        ("ICMP", "192.168.1.100", "8.8.8.8", None, Protocol::Icmp),
        ("普通流量", "192.168.1.100", "93.184.216.34", Some(80), Protocol::Tcp),
    ];

    let mut stats: std::collections::HashMap<RoutingAction, u32> = std::collections::HashMap::new();

    for (name, src, dst, port, proto) in scenarios {
        println!("\n📌 场景: {}", name);
        let src_ip: Ipv4Addr = src.parse().unwrap();
        let dst_ip: Ipv4Addr = dst.parse().unwrap();
        let packet = PacketContext::new(src_ip, dst_ip, None, port, proto);
        let decision = engine.match_packet(&packet);
        print_decision(&decision, &packet);

        *stats.entry(decision.action).or_insert(0) += 1;
    }

    // 打印统计
    println!();
    println!("{}", "=".repeat(60));
    println!("📊 测试统计");
    println!("{}", "=".repeat(60));
    for (action, count) in &stats {
        println!(
            "   {} {}: {} 次",
            action_icon(action),
            action_name(action),
            count
        );
    }
}

fn interactive_mode(engine: &HotReloadableEngine, rules_path: &PathBuf) {
    print_header("🎮 交互模式");

    println!();
    println!("输入格式: src_ip,dst_ip,dst_port,protocol");
    println!("示例: 192.168.1.100,10.0.0.5,80,tcp");
    println!();
    println!("命令:");
    println!("   test   - 运行内置测试场景");
    println!("   reload - 重载配置文件");
    println!("   stats  - 显示统计信息");
    println!("   quit   - 退出");
    println!("{}", "=".repeat(60));

    loop {
        print!("\n> ");
        std::io::stdout().flush().ok();

        let mut input = String::new();
        std::io::stdin().read_line(&mut input).ok();
        let input = input.trim();

        if input.is_empty() {
            continue;
        }

        match input.to_lowercase().as_str() {
            "quit" | "exit" | "q" => {
                println!("👋 再见!");
                break;
            }
            "test" | "t" => {
                match RoutingEngine::from_file(rules_path) {
                    Ok(e) => test_builtin_scenarios(&e),
                    Err(e) => println!("❌ 加载配置失败: {}", e),
                }
            }
            "reload" | "r" => match engine.reload(rules_path) {
                Ok(_) => {
                    println!("✅ 配置已重载");
                    println!("   当前规则数: {}", engine.rule_count());
                }
                Err(e) => println!("❌ 重载失败: {}", e),
            },
            "stats" | "s" => {
                println!();
                println!("📊 引擎状态:");
                println!("   规则数量:   {}", engine.rule_count());
                println!(
                    "   默认动作:   {} {}",
                    action_icon(&engine.default_action()),
                    action_name(&engine.default_action())
                );
            }
            _ => {
                if let Some((src_ip, dst_ip, dst_port, protocol)) = parse_packet(input) {
                    let packet = PacketContext::new(src_ip, dst_ip, None, dst_port, protocol);
                    let decision = engine.match_packet(&packet);
                    print_decision(&decision, &packet);
                } else {
                    println!("❌ 无效输入格式。使用: src_ip,dst_ip,dst_port,protocol");
                    println!("   示例: 192.168.1.100,10.0.0.5,80,tcp");
                }
            }
        }
    }
}

fn main() {
    print_header("🚀 SASE 数据包分流规则测试工具");

    let args = Args::parse();

    // 加载配置
    let engine = match HotReloadableEngine::from_file(&args.rules) {
        Ok(e) => {
            println!();
            println!("✅ 配置加载成功: {}", args.rules.display());
            println!("   规则数量:   {}", e.rule_count());
            println!(
                "   默认动作:   {} {}",
                action_icon(&e.default_action()),
                action_name(&e.default_action())
            );
            e
        }
        Err(e) => {
            eprintln!();
            eprintln!("❌ 配置加载失败: {}", e);
            eprintln!("   请确保配置文件存在: {}", args.rules.display());
            std::process::exit(1);
        }
    };

    if args.interactive {
        interactive_mode(&engine, &args.rules);
    } else if let Some(packet_str) = args.packet {
        if let Some((src_ip, dst_ip, dst_port, protocol)) = parse_packet(&packet_str) {
            match RoutingEngine::from_file(&args.rules) {
                Ok(e) => test_single_packet(&e, src_ip, dst_ip, dst_port, protocol),
                Err(e) => {
                    eprintln!("❌ 加载配置失败: {}", e);
                    std::process::exit(1);
                }
            }
        } else {
            eprintln!("❌ 无效的数据包格式: {}", packet_str);
            std::process::exit(1);
        }
    } else if args.batch {
        match RoutingEngine::from_file(&args.rules) {
            Ok(e) => test_builtin_scenarios(&e),
            Err(e) => {
                eprintln!("❌ 加载配置失败: {}", e);
                std::process::exit(1);
            }
        }
    } else {
        // 默认运行内置测试
        match RoutingEngine::from_file(&args.rules) {
            Ok(e) => test_builtin_scenarios(&e),
            Err(e) => {
                eprintln!("❌ 加载配置失败: {}", e);
                std::process::exit(1);
            }
        }
    }
}
