use std::{collections::HashMap, fmt::Debug};

use snafu::Snafu;
use tokio::sync::mpsc::Receiver;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::{
    bgp::{self, Nexthop, Nlri, PathId, Route},
    bpf,
    c_data::{CFibEntry, CNlri},
};

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
    #[snafu(whatever, display("{message}"))]
    Whatever {
        message: String,
        #[snafu(source(from(anyhow::Error, Some)))]
        source: Option<anyhow::Error>,
        backtrace: snafu::Backtrace,
    },
}

pub type Result<T> = std::result::Result<T, Error>;

pub struct Reconciler {
    /// Reconciler receives BGP updates from a BGP speaker on
    /// this channel, it populates the eBPF map using these
    /// updates.
    updates_rx: Receiver<bgp::Update>,

    /// Cancellation token for graceful shutdown.
    token: CancellationToken,
}

impl Reconciler {
    pub fn new(updates_rx: Receiver<bgp::Update>, token: CancellationToken) -> Result<Self> {
        Ok(Self { updates_rx, token })
    }

    pub async fn run(mut self) -> Result<()> {
        let fib = bpf::Fib::open()?;
        let mut rib = Rib::default();

        loop {
            tokio::select! {
                () = self.token.cancelled() => break,
                update = self.updates_rx.recv() => {
                    let Some(update) = update else {
                        info!("BGP channel closed, shutting down");
                        break;
                    };

                    // Update the RIB with the routes we learnt from the update.
                    for announcement in &update.announcements {
                        for route in &announcement.routes {
                            rib.insert(route, &announcement.nexthop);
                        }
                    }
                    for route in &update.withdrawals {
                        rib.remove(route);
                    }

                    if let Err(e) = fib.reconcile(rib.to_fib_state()) {
                        warn!(error = %e, "Failed reconciling FIB with RIB");
                    }
                }
            }
        }

        info!("Reconciler finished running");
        Ok(())
    }
}

struct Rib {
    table: HashMap<Nlri, Vec<(PathId, Nexthop)>>,
}

impl Default for Rib {
    fn default() -> Rib {
        Rib {
            table: HashMap::new(),
        }
    }
}

impl Rib {
    pub fn insert(&mut self, route: &Route, nexthop: &Nexthop) {
        let entries = self.table.entry(route.nlri).or_default();
        entries.retain(|&(path_id, _)| path_id != route.path_id);
        entries.push((route.path_id, *nexthop));
    }

    pub fn remove(&mut self, route: &Route) {
        let Some(entries) = self.table.get_mut(&route.nlri) else {
            return;
        };
        entries.retain(|&(path_id, _)| route.path_id != path_id);
        if entries.is_empty() {
            self.table.remove(&route.nlri);
        }
    }

    pub fn to_fib_state(&self) -> bpf::FibState {
        self.table
            .iter()
            .map(|(nlri, entries)| {
                let nexthops: Vec<&Nexthop> = entries.iter().map(|(_, nh)| nh).collect();
                (CNlri::from(*nlri), CFibEntry::new(&nexthops))
            })
            .collect()
    }
}
