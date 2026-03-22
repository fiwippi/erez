use std::{collections::HashMap, fmt::Debug};

use snafu::{ResultExt, Snafu};
use tokio::sync::mpsc::Receiver;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::{
    bgp::{self, Nexthop, Nlri, PathId, Route, Update},
    bpf,
    c_data::{CFibEntry, CNlri},
    interface::Interface,
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

pub struct Director {
    /// Director receives BGP updates from a BGP speaker on
    /// this channel, it populates the eBPF map using these
    /// updates.
    updates_rx: Receiver<bgp::Update>,

    /// Interface that erez_encap is running on.
    iface: Interface,

    /// The RIB maps NLRIs to nexthops.
    rib: Rib,

    /// Cancellation token for graceful shutdown.
    token: CancellationToken,
}

impl Director {
    pub fn new(
        updates_rx: Receiver<bgp::Update>,
        iface: Interface,
        token: CancellationToken,
    ) -> Result<Self> {
        Ok(Self {
            updates_rx,
            iface,
            rib: Rib::new(),
            token,
        })
    }

    pub async fn run(mut self) -> Result<()> {
        loop {
            tokio::select! {
                () = self.token.cancelled() => break,
                update = self.updates_rx.recv() => {
                    let Some(update) = update else { continue };
                    if let Err(e) = self.handle_update(&update) {
                        warn!(error = %e, "Failed handling update");
                    }
                }
            }
        }

        info!("Director finished running");
        Ok(())
    }

    fn handle_update(&mut self, update: &Update) -> Result<()> {
        for announcement in &update.announcements {
            for route in &announcement.routes {
                let (c_nlri, c_fib_entry) = self.rib.insert(route, &announcement.nexthop);
                bpf::update_fib_entry(&self.iface, c_nlri, c_fib_entry)
                    .whatever_context::<_, Error>("Failed handling announcement")?;
            }
        }

        for route in &update.withdrawals {
            let result = match self.rib.remove(route) {
                Some((c_nlri, Some(c_fib_entry))) => {
                    bpf::update_fib_entry(&self.iface, c_nlri, c_fib_entry)
                }
                Some((c_nlri, None)) => bpf::delete_fib_entry(&self.iface, c_nlri),
                None => continue,
            };
            result.whatever_context::<_, Error>("Failed handling withdrawal")?;
        }

        Ok(())
    }
}

struct Rib {
    table: HashMap<Nlri, Vec<(PathId, Nexthop)>>,
}

impl Rib {
    fn new() -> Self {
        Self {
            table: HashMap::new(),
        }
    }

    fn insert(&mut self, route: &Route, nexthop: &Nexthop) -> (CNlri, CFibEntry) {
        let entries = self.table.entry(route.nlri).or_default();
        entries.push((route.path_id, *nexthop));
        entries.dedup_by(|a, b| a.0 == b.0);

        let key = CNlri::from(route.nlri);
        let value = {
            // Currently a FIB entry only accepts at most four nexthops;
            // it doesn't really matter which nexthops we provide until
            // we start sorting them for loadbalancing purposes.
            //
            // We will want to log/emit a metric to understand how often
            // this might be happening!
            let nexthops: Vec<&Nexthop> = entries.iter().map(|(_, nexthop)| nexthop).collect();
            CFibEntry::new(&nexthops[..])
        };
        (key, value)
    }

    fn remove(&mut self, route: &Route) -> Option<(CNlri, Option<CFibEntry>)> {
        let entries = self.table.get_mut(&route.nlri)?;
        entries.retain(|&(path_id, _)| route.path_id != path_id);

        let key = CNlri::from(route.nlri);
        if entries.is_empty() {
            self.table.remove(&route.nlri);
            return Some((key, None));
        }

        let value = {
            let nexthops: Vec<&Nexthop> = entries.iter().map(|(_, nexthop)| nexthop).collect();
            CFibEntry::new(&nexthops[..])
        };
        Some((key, Some(value)))
    }
}
