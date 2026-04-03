mod codec;
mod common;
mod sase_client;
mod sase_server;
mod transport;
mod tun_config;

use anyhow::Result;
use clap::{Parser, Subcommand};
use log::info;

#[derive(Parser, Debug)]
#[command(name = "sase")]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[arg(short, long)]
    log_level: Option<String>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    Server {
        #[arg(short, long)]
        transport_type: Option<String>,

        #[arg(short, long)]
        bind_addr: Option<String>,

        #[arg(short = 'u', long)]
        tun: Option<String>,

        #[arg(short = 'a', long)]
        address: Option<String>,

        #[arg(short = 'n', long)]
        netmask: Option<String>,

        #[arg(short = 'm', long)]
        mtu: Option<usize>,

        #[arg(short, long)]
        cert_path: Option<String>,

        #[arg(short, long)]
        key_path: Option<String>,

        #[arg(long)]
        token: Option<String>,

        /// 路由规则配置文件路径
        #[arg(long)]
        rules: Option<String>,
    },
    Client {
        #[arg(short, long)]
        transport_type: Option<String>,

        #[arg(short, long)]
        server_addr: Option<String>,

        #[arg(short, long)]
        ca_cert_path: Option<String>,

        #[arg(long)]
        token: Option<String>,

        /// 路由规则配置文件路径
        #[arg(long)]
        rules: Option<String>,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let log_level = cli.log_level.unwrap_or_else(|| "info".to_string());

    match cli.command {
        Commands::Server {
            transport_type,
            bind_addr,
            tun,
            address,
            netmask,
            mtu,
            cert_path,
            key_path,
            token,
            rules,
        } => {
            env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(log_level))
                .init();

            info!("Starting SASE VPN Server");
            sase_server::run_server_with_args(
                transport_type,
                bind_addr,
                tun,
                address,
                netmask,
                mtu,
                cert_path,
                key_path,
                token,
                rules,
            )
            .await
        }
        Commands::Client {
            transport_type,
            server_addr,
            ca_cert_path,
            token,
            rules,
        } => {
            env_logger::Builder::from_env(env_logger::Env::default().default_filter_or(log_level))
                .init();

            info!("Starting SASE VPN Client");
            sase_client::run_client_with_args(transport_type, server_addr, ca_cert_path, token, rules)
                .await
        }
    }
}
