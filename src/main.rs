mod sase_client;
mod sase_server;
mod common;

use anyhow::Result;
use clap::{Parser, Subcommand};
use log::info;

/// SASE - Simple And Secure VPN
#[derive(Parser, Debug)]
#[command(name = "sase")]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Start the VPN server
    Server {
        /// Bind address (default: 0.0.0.0:12345)
        #[arg(short, long)]
        bind: Option<String>,

        /// TUN device name (default: tun0)
        #[arg(short, long)]
        tun: Option<String>,

        /// TUN device address (default: 10.0.0.1)
        #[arg(short, long)]
        address: Option<String>,

        /// Netmask (default: 255.255.255.0)
        #[arg(short = 'n', long)]
        netmask: Option<String>,

        /// MTU (default: 1500)
        #[arg(short, long)]
        mtu: Option<usize>,

        /// Socket receive buffer size in MB (default: 2)
        #[arg(long)]
        recv_buffer: Option<usize>,

        /// Socket send buffer size in MB (default: 2)
        #[arg(long)]
        send_buffer: Option<usize>,

        /// Verbose logging
        #[arg(short, long)]
        verbose: bool,
    },
    /// Start the VPN client
    Client {
        /// Server address (default: 127.0.0.1:9999)
        #[arg(short, long)]
        server: Option<String>,

        /// TUN device name (default: tun0)
        #[arg(short, long)]
        tun: Option<String>,

        /// TUN device address (default: 10.0.0.2)
        #[arg(short, long)]
        address: Option<String>,

        /// Netmask (default: 255.255.255.0)
        #[arg(short = 'n', long)]
        netmask: Option<String>,

        /// MTU (default: 1500)
        #[arg(short, long)]
        mtu: Option<usize>,

        /// Socket receive buffer size in MB (default: 2)
        #[arg(long)]
        recv_buffer: Option<usize>,

        /// Socket send buffer size in MB (default: 2)
        #[arg(long)]
        send_buffer: Option<usize>,

        /// Verbose logging
        #[arg(short, long)]
        verbose: bool,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Server {
            bind,
            tun,
            address,
            netmask,
            mtu,
            recv_buffer,
            send_buffer,
            verbose,
        } => {
            env_logger::Builder::from_env(
                env_logger::Env::default().default_filter_or(if verbose { "debug" } else { "info" }),
            )
            .init();

            info!("Starting SASE VPN Server");
            sase_server::run_server_with_args(bind, tun, address, netmask, mtu, recv_buffer, send_buffer).await
        }
        Commands::Client {
            server,
            tun,
            address,
            netmask,
            mtu,
            recv_buffer,
            send_buffer,
            verbose,
        } => {
            env_logger::Builder::from_env(
                env_logger::Env::default().default_filter_or(if verbose { "debug" } else { "info" }),
            )
            .init();

            info!("Starting SASE VPN Client");
            sase_client::run_client_with_args(server, tun, address, netmask, mtu, recv_buffer, send_buffer).await
        }
    }
}
