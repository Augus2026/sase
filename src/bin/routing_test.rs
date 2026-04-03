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
struct Args {
    #[arg(short, long, default_value = "config/rules.toml")]
    rules: PathBuf,

    #[arg(short, long)]
    interactive: bool,

    #[arg(short, long)]
    packet: Option<String>,

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

fn action_name(action: &RoutingAction) -> &'static str {
    match action {
        RoutingAction::Direct => "direct",
        RoutingAction::Proxy => "proxy",
        RoutingAction::Drop => "drop",
    }
}

fn print_header(title: &str) {
    println!("{}", "=".repeat(60));
    println!("{}", title);
    println!("{}", "=".repeat(60));
}

fn print_decision(decision: &sase_routing::decision::RoutingDecision, packet: &PacketContext) {
    println!();
    println!("packet: {}", packet);
    println!("action: {}", action_name(&decision.action));
    if decision.is_default {
        println!("rule: default");
    } else {
        println!(
            "rule: {} (id: {})",
            decision.rule_name.as_deref().unwrap_or("N/A"),
            decision.rule_id.unwrap_or(0)
        );
    }
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
    print_header("built-in routing scenarios");

    let scenarios = vec![
        ("private-10", "192.168.1.100", "10.0.0.5", Some(80), Protocol::Tcp),
        (
            "private-172",
            "192.168.1.100",
            "172.16.0.1",
            Some(443),
            Protocol::Tcp,
        ),
        (
            "private-192",
            "192.168.1.100",
            "192.168.2.1",
            Some(22),
            Protocol::Tcp,
        ),
        ("https-proxy", "192.168.1.100", "8.8.8.8", Some(443), Protocol::Tcp),
        ("http-direct", "192.168.1.100", "8.8.8.8", Some(80), Protocol::Tcp),
        ("ssh-drop", "192.168.1.100", "1.2.3.4", Some(22), Protocol::Tcp),
        ("dns", "192.168.1.100", "8.8.8.8", Some(53), Protocol::Udp),
        ("icmp", "192.168.1.100", "8.8.8.8", None, Protocol::Icmp),
    ];

    let mut stats: std::collections::HashMap<RoutingAction, u32> = std::collections::HashMap::new();

    for (name, src, dst, port, proto) in scenarios {
        println!("\nscenario: {}", name);
        let src_ip: Ipv4Addr = src.parse().unwrap();
        let dst_ip: Ipv4Addr = dst.parse().unwrap();
        let packet = PacketContext::new(src_ip, dst_ip, None, port, proto);
        let decision = engine.match_packet(&packet);
        print_decision(&decision, &packet);
        *stats.entry(decision.action).or_insert(0) += 1;
    }

    println!();
    print_header("stats");
    for (action, count) in &stats {
        println!("{}: {}", action_name(action), count);
    }
}

fn interactive_mode(engine: &HotReloadableEngine, rules_path: &PathBuf) {
    print_header("interactive mode");
    println!("input format: src_ip,dst_ip,dst_port,protocol");
    println!("example: 192.168.1.100,10.0.0.5,80,tcp");
    println!("commands: test | reload | stats | quit");

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
            "quit" | "exit" | "q" => break,
            "test" | "t" => match RoutingEngine::from_file(rules_path) {
                Ok(e) => test_builtin_scenarios(&e),
                Err(e) => println!("load failed: {}", e),
            },
            "reload" | "r" => match engine.reload(rules_path) {
                Ok(_) => println!("reloaded: {} rules", engine.rule_count()),
                Err(e) => println!("reload failed: {}", e),
            },
            "stats" | "s" => {
                println!("rule count: {}", engine.rule_count());
                println!("default action: {}", action_name(&engine.default_action()));
            }
            _ => {
                if let Some((src_ip, dst_ip, dst_port, protocol)) = parse_packet(input) {
                    let packet = PacketContext::new(src_ip, dst_ip, None, dst_port, protocol);
                    let decision = engine.match_packet(&packet);
                    print_decision(&decision, &packet);
                } else {
                    println!("invalid input");
                }
            }
        }
    }
}

fn main() {
    print_header("SASE routing test");

    let args = Args::parse();
    let engine = match HotReloadableEngine::from_file(&args.rules) {
        Ok(e) => e,
        Err(e) => {
            eprintln!("failed to load rules: {}", e);
            std::process::exit(1);
        }
    };

    println!("loaded {} rules", engine.rule_count());
    println!("default action: {}", action_name(&engine.default_action()));

    if args.interactive {
        interactive_mode(&engine, &args.rules);
    } else if let Some(packet_str) = args.packet {
        if let Some((src_ip, dst_ip, dst_port, protocol)) = parse_packet(&packet_str) {
            match RoutingEngine::from_file(&args.rules) {
                Ok(e) => test_single_packet(&e, src_ip, dst_ip, dst_port, protocol),
                Err(e) => {
                    eprintln!("failed to load rules: {}", e);
                    std::process::exit(1);
                }
            }
        } else {
            eprintln!("invalid packet format: {}", packet_str);
            std::process::exit(1);
        }
    } else if args.batch {
        match RoutingEngine::from_file(&args.rules) {
            Ok(e) => test_builtin_scenarios(&e),
            Err(e) => {
                eprintln!("failed to load rules: {}", e);
                std::process::exit(1);
            }
        }
    } else {
        match RoutingEngine::from_file(&args.rules) {
            Ok(e) => test_builtin_scenarios(&e),
            Err(e) => {
                eprintln!("failed to load rules: {}", e);
                std::process::exit(1);
            }
        }
    }
}
