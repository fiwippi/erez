use std::time::Duration;

use clap::{Parser, Subcommand};
use snafu::{Report, ResultExt, Snafu};

use erezd::{
    bgp,
    bpf::{self},
    config::{self, DecapConfig, EncapConfig},
    interface::{self, Interface},
    reconciler, telemetry,
};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

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
    Reconciler {
        #[snafu(backtrace)]
        source: reconciler::Error,
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

            let mut speaker = bgp::Speaker::new(config.bgp, token.clone());
            let iface = Interface::lookup(&config.ebpf.interface).whatever_context::<_, Error>(
                format!("Failed to lookup interface: {}", config.ebpf.interface),
            )?;
            bpf::attach_erez_encap(&iface, &config.telemetry.level)
                .whatever_context::<_, Error>("Failed to attach erez_encap")?;
            let reconciler = reconciler::Reconciler::new(speaker.subscribe(), token.clone())
                .whatever_context::<_, Error>("Failed to create Reconciler")?;

            let mut join_set: JoinSet<Result<()>> = JoinSet::new();
            join_set.spawn(async move { speaker.run().await.map_err(Error::from) });
            join_set.spawn(async move { reconciler.run().await.map_err(Error::from) });
            join_set.spawn_blocking({
                let token = token.clone();
                move || bpf::tail_erez_encap_logs(&token).map_err(Error::from)
            });

            graceful_shutdown(&iface, join_set, token).await?;
        }
        Commands::Decap { config } => {
            let config = DecapConfig::load(&config).await?;
            telemetry::init(&config.telemetry.level)?;
            info!(?config, "Loaded config");

            let token = CancellationToken::new();

            let iface = Interface::lookup(&config.ebpf.interface).whatever_context::<_, Error>(
                format!("Failed to lookup interface: {}", config.ebpf.interface),
            )?;
            bpf::attach_erez_decap(&iface, &config.telemetry.level)
                .whatever_context::<_, Error>("Failed to attach erez_decap")?;

            let mut join_set: JoinSet<Result<()>> = JoinSet::new();
            join_set.spawn_blocking({
                let token = token.clone();
                move || bpf::tail_erez_decap_logs(&token).map_err(Error::from)
            });

            graceful_shutdown(&iface, join_set, token).await?;
        }
    }

    Ok(())
}

async fn graceful_shutdown(
    iface: &Interface,
    mut join_set: JoinSet<Result<()>>,
    token: CancellationToken,
) -> Result<()> {
    tokio::select! {
        _ = erez_lib::signal::shutdown_signal() => {
            info!("Received signal, shutting down");
        }
        Some(result) = join_set.join_next() => {
            if let Ok(Err(e)) = result {
                error!(error = %Report::from_error(&e), "Task failed, shutting down");
            }
        }
    }

    bpf::detach(iface).whatever_context::<_, Error>("Failed to detach Erez programs")?;
    info!("Detached Erez programs");

    token.cancel();
    info!("Draining tasks");
    tokio::select! {
        _ = join_set.join_all() => {
            info!("All tasks finished");
        }
        () = tokio::time::sleep(Duration::from_secs(30)) => {
            warn!("Shutdown timed out, some tasks did not finish");
        }
    }

    info!("Shut down");
    Ok(())
}
