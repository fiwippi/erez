use clap::Parser;
use erez_test::{
    ns::{self, NsChild},
    repl,
    topology::{self, Edge, Metal, Router, Transit},
};
use erezd::config::{BgpConfig, DecapConfig, EbpfConfig, EncapConfig, TelemetryConfig};
use tokio::net::TcpListener;

const EREZD_BIN: &str = concat!(env!("CARGO_TARGET_DIR"), "/debug/erezd");
const EREZD_BGP_PORT: u16 = 1179; // Can't be 179 which is already in use.

#[derive(Debug, Parser)]
#[command(about, long_about = None)]
struct Args {
    /// Log level for erezd processes.
    #[arg(long, env = "EREZD_LOG", default_value = "INFO")]
    erezd_log_level: String,

    /// Run without an interactive REPL, waiting for a signal to exit.
    #[arg(long, env = "NO_REPL")]
    no_repl: bool,
}

fn main() -> anyhow::Result<()> {
    if !nix::unistd::Uid::effective().is_root() {
        eprintln!("Lab must be run as root");
        std::process::exit(1);
    }

    let args = Args::parse();
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async {
        ns::cleanup_netns().await?;

        if !args.no_repl {
            ns::set_stderr_suppressed(true);
            println!("Loading lab...");
        }

        run(&args).await?;

        if !args.no_repl {
            println!("Exited REPL!");
        }

        Ok(())
    })
}

// ┌───────────┐                               ┌───────────┐
// │           │                               │ Transit A │
// │  Metal 1  │────┐                     ┌────│           │────┐
// │           │    │    ┌───────────┐    │    │ ASN 64512 │    │    ┌───────────┐    ┌───────────┐
// └───────────┘    │    │   Edge    │    │    └───────────┘    │    │  Origin   │    │           │
//                  ├────│           │────┤                     ├────│           │────│   Metal   │
// ┌───────────┐    │    │ ASN 4181  │    │    ┌───────────┐    │    │ ASN 64514 │    │           │
// │           │    │    └───────────┘    │    │ Transit B │    │    └───────────┘    └───────────┘
// │  Metal 2  │────┘          │          └────│           │────┘          │
// │           │                               │ ASN 64513 │
// └───────────┘          172.16.0.0/24        └───────────┘          10.41.0.0/24
//                      3ffff:172:16::/64                           3ffff:10:41::/64
async fn run(args: &Args) -> anyhow::Result<()> {
    let mut edge = Router::<Edge>::new(
        "edge",
        4181,
        "172.16.0.0/24".parse()?,
        "3fff:172:16::/64".parse()?,
        &[("erezd", EREZD_BGP_PORT)],
    )
    .await?;
    let edge_metal_1 = edge.add_metal("edge_metal_1").await?;
    let edge_metal_2 = edge.add_metal("edge_metal_2").await?;

    let mut origin_edge = Router::<Edge>::new(
        "origin_edge",
        64514,
        "10.41.0.0/24".parse()?,
        "3fff:10:41::/64".parse()?,
        &[],
    )
    .await?;
    let origin_metal = origin_edge.add_metal("origin_metal").await?;

    let mut transit_a = Router::<Transit>::new("transit_a", 64512).await?;
    let mut transit_b = Router::<Transit>::new("transit_b", 64513).await?;
    for mut transit in [&mut transit_a, &mut transit_b] {
        topology::peer(&mut edge, &mut transit).await?;
        topology::peer(&mut transit, &mut origin_edge).await?;
    }

    let _edge_metal_1_encap = run_erez_encap(&edge_metal_1, &edge, &args.erezd_log_level).await?;
    let _edge_metal_2_encap = run_erez_encap(&edge_metal_2, &edge, &args.erezd_log_level).await?;
    let _edge_decap = run_erez_decap(&edge, &args.erezd_log_level).await?;

    // Echo server.
    origin_metal
        .ns
        .spawn({
            let sitelocal = origin_metal.sitelocal_v4.addr();
            async move {
                let listener = TcpListener::bind(format!("{sitelocal}:80")).await?;
                tokio::spawn(async move {
                    while let Ok((mut stream, _)) = listener.accept().await {
                        let (mut reader, mut writer) = stream.split();
                        let _ = tokio::io::copy(&mut reader, &mut writer).await;
                    }
                });
                Ok::<_, anyhow::Error>(())
            }
        })
        .await??;

    if args.no_repl {
        erez_lib::signal::shutdown_signal().await;
    } else {
        repl::run(&[
            &edge.bird.ns,
            &edge_metal_1.ns,
            &edge_metal_1.bird.ns,
            &edge_metal_2.ns,
            &edge_metal_2.bird.ns,
            &origin_edge.bird.ns,
            &origin_metal.ns,
            &origin_metal.bird.ns,
            &transit_a.bird.ns,
            &transit_b.bird.ns,
        ])?;
    }

    Ok(())
}

async fn run_erez_encap(
    metal: &Metal,
    edge: &Router<Edge>,
    log_level: &str,
) -> anyhow::Result<NsChild> {
    let config = EncapConfig {
        bgp: BgpConfig {
            asn: edge.bird.asn,
            bgp_id: metal.sitelocal_v4.addr(),
            peer_ips: vec![edge.kind.interface.bridge.link_local],
            port: EREZD_BGP_PORT,
            interface: Some(metal.uplink.clone()),
        },
        ebpf: EbpfConfig {
            interface: metal.uplink.clone(),
        },
        telemetry: TelemetryConfig {
            level: log_level.to_string(),
        },
    };
    let encap_toml = toml::to_string(&config)?;
    metal
        .ns
        .spawn(async { tokio::fs::write("/tmp/encap.toml", encap_toml).await })
        .await??;
    let encap = metal
        .ns
        .spawn_process(EREZD_BIN, &["encap", "--config", "/tmp/encap.toml"])
        .await?;
    Ok(encap)
}

async fn run_erez_decap(edge: &Router<Edge>, log_level: &str) -> anyhow::Result<NsChild> {
    let config = DecapConfig {
        ebpf: EbpfConfig {
            interface: edge.kind.interface.bridge.name.clone(),
        },
        telemetry: TelemetryConfig {
            level: log_level.to_string(),
        },
    };
    let decap_toml = toml::to_string(&config)?;
    edge.ns
        .spawn(async { tokio::fs::write("/tmp/decap.toml", decap_toml).await })
        .await??;
    let decap = edge
        .ns
        .spawn_process(EREZD_BIN, &["decap", "--config", "/tmp/decap.toml"])
        .await?;
    Ok(decap)
}
