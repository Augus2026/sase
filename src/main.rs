mod common;
mod codec;
mod transport;
mod sase_client;
mod sase_server;
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
        bind: Option<String>,

        #[arg(short = 'u', long)]
        tun: Option<String>,

        #[arg(short = 'a', long)]
        address: Option<String>,

        #[arg(short = 'n', long)]
        netmask: Option<String>,

        #[arg(short = 'm', long)]
        mtu: Option<usize>,

        #[arg(short, long)]
        transport: Option<String>,
    },
    Client {
        #[arg(short, long)]
        server: Option<String>,

        #[arg(short = 'u', long)]
        tun: Option<String>,

        #[arg(short = 'a', long)]
        address: Option<String>,

        #[arg(short = 'n', long)]
        netmask: Option<String>,

        #[arg(short = 'm', long)]
        mtu: Option<usize>,

        #[arg(short, long)]
        transport: Option<String>,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let log_level = cli.log_level.unwrap_or_else(|| "info".to_string());

    match cli.command {
        Commands::Server {
            bind,
            tun,
            address,
            netmask,
            mtu,
            transport,
        } => {
            env_logger::Builder::from_env(
                env_logger::Env::default().default_filter_or(log_level),
            )
            .init();

            info!("Starting SASE VPN Server");
            sase_server::run_server_with_args(bind, tun, address, netmask, mtu, transport).await
        }
        Commands::Client {
            server,
            tun,
            address,
            netmask,
            mtu,
            transport,
        } => {
            env_logger::Builder::from_env(
                env_logger::Env::default().default_filter_or(log_level),
            )
            .init();

            info!("Starting SASE VPN Client");
            sase_client::run_client_with_args(server, tun, address, netmask, mtu, transport).await
        }
    }
}
