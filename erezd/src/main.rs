use std::time::Duration;

use clap::{Parser, Subcommand};
use snafu::{ResultExt, Snafu};

use erezd::{
    bgp,
    bpf::{self},
    config::{self, DecapConfig, EncapConfig},
    director,
    interface::{self, Interface},
    telemetry,
};
use tokio_util::{sync::CancellationToken, task::TaskTracker};
use tracing::{info, warn};

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(transparent)]
    Bgp {
        #[snafu(backtrace)]
        source: bgp::Error,
    },
    #[snafu(transparent)]
    Bpf {
        #[snafu(backtrace)]
        source: bpf::Error,
    },
    #[snafu(transparent)]
    Config {
        #[snafu(backtrace)]
        source: config::Error,
    },
    #[snafu(transparent)]
    Director {
        #[snafu(backtrace)]
        source: director::Error,
    },
    #[snafu(transparent)]
    Interface {
        #[snafu(backtrace)]
        source: interface::Error,
    },
    #[snafu(transparent)]
    Telemetry {
        #[snafu(backtrace)]
        source: telemetry::Error,
    },
    #[snafu(whatever, display("{message}"))]
    Whatever {
        message: String,
        #[snafu(source(from(anyhow::Error, Some)))]
        source: Option<anyhow::Error>,
        backtrace: snafu::Backtrace,
    },
}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Parser)]
#[command(version, about, long_about = None)]
struct Args {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    // Run the encapsulation daemon.
    Encap {
        /// Path to the config file.
        #[arg(long, default_value_t = String::from("config.toml"))]
        config: String,
    },
    // Run the decapsulation daemon.
    Decap {
        /// Path to the config file.
        #[arg(long, default_value_t = String::from("config.toml"))]
        config: String,
    },
}

#[tokio::main]
#[snafu::report]
async fn main() -> Result<()> {
    let args = Args::parse();
    match args.command {
        Commands::Encap { config } => {
            let config = EncapConfig::load(&config).await?;
            telemetry::init(&config.telemetry.level)?;
            info!(?config, "Loaded config");

            let token = CancellationToken::new();
            let tracker = TaskTracker::new();

            let (speaker, bgp_updates_rx) = bgp::Speaker::new(config.bgp, token.clone())
                .whatever_context::<_, Error>("Failed to create BGP speaker")?;
            let iface = Interface::lookup(&config.ebpf.interface).whatever_context::<_, Error>(
                format!("Failed to lookup interface: {}", config.ebpf.interface),
            )?;
            bpf::attach_erez_encap(&iface, &config.telemetry.level)
                .whatever_context::<_, Error>("Failed to attach erez_encap")?;
            let director = director::Director::new(bgp_updates_rx, iface.clone(), token.clone())
                .whatever_context::<_, Error>("Failed to create Director")?;

            tracker.spawn(speaker.run());
            tracker.spawn(director.run());
            tracker.spawn_blocking({
                let iface = iface.clone();
                let token = token.clone();
                move || bpf::tail_erez_encap_logs(&iface, &token)
            });

            graceful_shutdown(&iface, tracker, token).await?;
        }
        Commands::Decap { config } => {
            let config = DecapConfig::load(&config).await?;
            telemetry::init(&config.telemetry.level)?;
            info!(?config, "Loaded config");

            let token = CancellationToken::new();
            let tracker = TaskTracker::new();

            let iface = Interface::lookup(&config.ebpf.interface).whatever_context::<_, Error>(
                format!("Failed to lookup interface: {}", config.ebpf.interface),
            )?;
            bpf::attach_erez_decap(&iface, &config.telemetry.level)
                .whatever_context::<_, Error>("Failed to attach erez_decap")?;

            tracker.spawn_blocking({
                let iface = iface.clone();
                let token = token.clone();
                move || bpf::tail_erez_encap_logs(&iface, &token)
            });

            graceful_shutdown(&iface, tracker, token).await?;
        }
    }

    Ok(())
}

async fn graceful_shutdown(
    iface: &Interface,
    tracker: TaskTracker,
    token: CancellationToken,
) -> Result<()> {
    erez_lib::signal::shutdown_signal().await;
    info!("Shutting down");

    bpf::detach(iface).whatever_context::<_, Error>("Failed to detach Erez programs")?;
    info!("Detached Erez programs");

    token.cancel();
    tracker.close();
    info!("Draining tasks");
    tokio::select! {
        () = tracker.wait() => {
            info!("All tasks finished");
        }
        () = tokio::time::sleep(Duration::from_secs(30)) => {
            warn!("Shutdown timed out, some tasks did not finish");
        }
    }

    info!("Shut down");
    Ok(())
}
