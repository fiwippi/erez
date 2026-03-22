use std::net::{Ipv4Addr, Ipv6Addr};

use serde::{Deserialize, Serialize};
use snafu::{ResultExt, Snafu};
use tokio::fs;

#[derive(Debug, Snafu)]
#[snafu(whatever, display("{message}"))]
pub struct Error {
    message: String,
    #[snafu(source(from(anyhow::Error, Some)))]
    source: Option<anyhow::Error>,
    backtrace: snafu::Backtrace,
}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Deserialize, Serialize)]
pub struct EncapConfig {
    pub bgp: BgpConfig,
    pub ebpf: EbpfConfig,
    pub telemetry: TelemetryConfig,
}

impl EncapConfig {
    pub async fn load(path: &str) -> Result<Self> {
        let str = fs::read_to_string(path)
            .await
            .whatever_context(format!("Failed to read config file: {path}"))?;
        let config = toml::from_str(&str)
            .whatever_context(format!("Failed to deserialise config from file: {path}"))?;

        Ok(config)
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub struct DecapConfig {
    pub ebpf: EbpfConfig,
    pub telemetry: TelemetryConfig,
}

impl DecapConfig {
    pub async fn load(path: &str) -> Result<Self> {
        let str = fs::read_to_string(path)
            .await
            .whatever_context(format!("Failed to read config file: {path}"))?;
        let config = toml::from_str(&str)
            .whatever_context(format!("Failed to deserialise config from file: {path}"))?;

        Ok(config)
    }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct BgpConfig {
    /// ASN of the AS that we're running in.
    pub asn: u32,

    /// Our BGP ID.
    pub bgp_id: Ipv4Addr,

    /// IPv6 addresses of the peers that
    /// we establish BGP sessions with.
    pub peer_ips: Vec<Ipv6Addr>,

    /// Network interface name for link-local peer scoping.
    pub interface: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct EbpfConfig {
    /// Name of the network interface the eBPF
    /// program will bind to.
    #[serde(default = "default_iface_name")]
    pub interface: String,
}

impl Default for EbpfConfig {
    fn default() -> Self {
        Self {
            interface: default_iface_name(),
        }
    }
}

fn default_iface_name() -> String {
    "erez0".into()
}

#[derive(Debug, Deserialize, Serialize)]
pub struct TelemetryConfig {
    /// One of ["OFF", "ERROR", "WARN", "INFO", "DEBUG", "TRACE"].
    pub level: String,
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        Self {
            level: default_log_level(),
        }
    }
}

fn default_log_level() -> String {
    "INFO".into()
}
