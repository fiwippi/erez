use std::net::{IpAddr, Ipv6Addr, SocketAddr, SocketAddrV6};

use ipnet::IpNet;
use netgauze_bgp_pkt::{
    capabilities::{
        AddPathAddressFamily, AddPathCapability, BgpCapability, MultiProtocolExtensionsCapability,
    },
    nlri::{Ipv4UnicastAddress, Ipv6UnicastAddress},
    path_attribute::{MpReach, MpUnreach, PathAttributeValue},
    update::BgpUpdateMessage,
};
use netgauze_bgp_speaker::{
    connection::TcpActiveConnect,
    events::{BgpEvent, UpdateTreatment},
    fsm::{FsmState, FsmStateError},
    listener::BgpListener,
    peer::{EchoCapabilitiesPolicy, PeerConfigBuilder, PeerProperties},
    supervisor::PeersSupervisor,
};
use netgauze_iana::address_family::AddressType;
use snafu::{OptionExt, ResultExt, Snafu};
use tokio::{
    net::TcpStream,
    sync::mpsc::{self, UnboundedReceiver},
};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

use crate::{
    config::BgpConfig,
    interface::{self, Interface},
};

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("BGP update missing nexthop"))]
    UpdateMissingNexthop,
    #[snafu(transparent)]
    Interface {
        #[snafu(backtrace)]
        source: interface::Error,
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

/// This is a thin wrapper over `netgauze-bgp-speaker`, ideally
/// we'll be able to use a better maintained library in the
/// future.
pub struct Speaker {
    config: BgpConfig,

    /// Send updates about NLRIs via this channel.
    update_tx: mpsc::Sender<Update>,

    /// Manages the state of all known peers (including our own).
    supervisor: PeersSupervisor<IpAddr, SocketAddr, TcpStream>,

    /// Listener solely handles incoming BGP connections
    /// and hands these off to the supervisor to manage.
    listener: BgpListener<SocketAddr, TcpStream>,

    /// Cancellation token for graceful shutdown.
    token: CancellationToken,
}

impl Speaker {
    pub fn new(
        config: BgpConfig,
        token: CancellationToken,
    ) -> Result<(Self, mpsc::Receiver<Update>)> {
        let (update_tx, update_rx) = mpsc::channel::<Update>(32);

        let peer_ips = config.peer_ips.clone();
        let port = config.port;
        let iface = config.interface.clone();
        let mut speaker = Speaker {
            supervisor: PeersSupervisor::new(config.asn, config.bgp_id),
            config,
            update_tx,
            listener: BgpListener::new(
                vec![SocketAddr::V6(SocketAddrV6::new(
                    Ipv6Addr::UNSPECIFIED,
                    port,
                    0,
                    0,
                ))],
                false,
            ),
            token,
        };
        let scope_id = if let Some(iface) = iface {
            Interface::lookup(&iface)?.index.cast_unsigned().get()
        } else {
            0
        };
        for ip in peer_ips {
            speaker.add_peer(SocketAddr::V6(SocketAddrV6::new(ip, port, 0, scope_id)))?;
        }

        Ok((speaker, update_rx))
    }

    fn add_peer(&mut self, addr: SocketAddr) -> Result<()> {
        let config = PeerConfigBuilder::new()
            .open_delay_timer_duration(5)
            .build();
        // We are parroting the default config value which
        // is itself stored as u16, so no truncation is
        // possible.
        let hold_timer_duration = config.hold_timer_duration_large_value().as_secs() as u16;
        let policy = EchoCapabilitiesPolicy::new(
            self.config.asn,
            true,
            self.config.bgp_id,
            hold_timer_duration,
            vec![
                BgpCapability::AddPath(AddPathCapability::new(vec![
                    AddPathAddressFamily::new(AddressType::Ipv4Unicast, false, true),
                    AddPathAddressFamily::new(AddressType::Ipv6Unicast, false, true),
                ])),
                BgpCapability::MultiProtocolExtensions(MultiProtocolExtensionsCapability::new(
                    AddressType::Ipv4Unicast,
                )),
                BgpCapability::MultiProtocolExtensions(MultiProtocolExtensionsCapability::new(
                    AddressType::Ipv6Unicast,
                )),
            ],
            vec![],
        );
        let properties = PeerProperties::new(
            self.config.asn,
            self.config.asn,
            self.config.bgp_id,
            addr,
            true,
        );

        // A bunch of the netgauze errors don't actually implement
        // std::error::Error, so we manually create the Whatever
        // variant.
        let (peer_states_rx, peer_handle) = self
            .supervisor
            .create_peer(addr.ip(), properties, config, TcpActiveConnect, policy)
            .map_err(|e| Error::Whatever {
                message: format!("Failed to create peer: {}", addr.ip()),
                source: Some(anyhow::anyhow!("{e:?}")),
                backtrace: snafu::Backtrace::capture(),
            })?;
        peer_handle
            .start()
            .whatever_context::<_, Error>(format!("Failed to start peer: {}", addr.ip()))?;
        self.listener.reg_peer(addr.ip(), peer_handle);

        tokio::spawn({
            let update_tx = self.update_tx.clone();
            async move { process_bgp_updates(addr.ip(), peer_states_rx, update_tx).await }
        });

        Ok(())
    }

    pub async fn run(mut self) -> Result<()> {
        tokio::select! {
            () = self.token.cancelled() => {}
            result = self.listener.run(&mut self.supervisor) => {
                result.whatever_context::<_, Error>("Failed to run BGP listener")?;
            }
        }
        info!("BGP speaker finished running");
        Ok(())
    }
}

pub type Nexthop = IpAddr;

pub type Nlri = IpNet;

pub type PathId = Option<u32>;

#[derive(Debug)]
pub struct Route {
    pub path_id: PathId,
    pub nlri: Nlri,
}

impl From<&Ipv4UnicastAddress> for Route {
    fn from(nlri: &Ipv4UnicastAddress) -> Self {
        Self {
            path_id: nlri.path_id(),
            nlri: IpNet::V4(nlri.network().address()),
        }
    }
}

impl From<&Ipv6UnicastAddress> for Route {
    fn from(nlri: &Ipv6UnicastAddress) -> Self {
        Self {
            path_id: nlri.path_id(),
            nlri: IpNet::V6(nlri.network().address()),
        }
    }
}

#[derive(Debug)]
pub struct Announcement {
    pub routes: Vec<Route>,
    pub nexthop: Nexthop,
}

#[derive(Debug)]
pub struct Update {
    // We may have multiple NLRIs announced for different
    // nexthops (due to MP-BGP), but this isn't the case
    // for withdrawals, so we don't need a "nested" vec.
    pub announcements: Vec<Announcement>,
    pub withdrawals: Vec<Route>,
}

impl TryFrom<BgpUpdateMessage> for Update {
    type Error = Error;

    fn try_from(msg: BgpUpdateMessage) -> std::result::Result<Self, Self::Error> {
        let mut announcements: Vec<Announcement> = vec![];
        let mut withdrawals: Vec<Route> = vec![];

        // For MP-BGP, we prefer local nexthops in cases
        // where we are peering over link-locals.

        // IPv4 advertised using "legacy" BGP.
        if !msg.nlri().is_empty() {
            let nexthop = msg
                .path_attributes()
                .iter()
                .find_map(|attr| match attr.value() {
                    PathAttributeValue::NextHop(nh) => Some(IpAddr::V4(nh.next_hop())),
                    _ => None,
                })
                .context(UpdateMissingNexthopSnafu {})?;
            announcements.push(Announcement {
                routes: msg.nlri().iter().map(Route::from).collect(),
                nexthop,
            });
        }

        // IPv4 withdrawn using "legacy" BGP.
        if !msg.withdraw_routes().is_empty() {
            withdrawals.extend(msg.withdraw_routes().iter().map(Route::from));
        }

        // IPv4 advertised using MP-BGP.
        if let Some(MpReach::Ipv4Unicast {
            next_hop,
            next_hop_local,
            nlri,
            ..
        }) = msg
            .path_attributes()
            .iter()
            .find_map(|attr| match attr.value() {
                PathAttributeValue::MpReach(reach) => Some(reach),
                _ => None,
            })
        {
            announcements.push(Announcement {
                routes: nlri.iter().map(Route::from).collect(),
                nexthop: next_hop_local.map(IpAddr::V6).unwrap_or(*next_hop),
            });
        }

        // IPv4 withdrawn using MP-BGP.
        if let Some(MpUnreach::Ipv4Unicast { nlri }) =
            msg.path_attributes()
                .iter()
                .find_map(|attr| match attr.value() {
                    PathAttributeValue::MpUnreach(unreach) => Some(unreach),
                    _ => None,
                })
        {
            withdrawals.extend(nlri.iter().map(Route::from));
        }

        // IPv6 advertised using MP-BGP.
        if let Some(MpReach::Ipv6Unicast {
            next_hop_global,
            next_hop_local,
            nlri,
            ..
        }) = msg
            .path_attributes()
            .iter()
            .find_map(|attr| match attr.value() {
                PathAttributeValue::MpReach(reach) => Some(reach),
                _ => None,
            })
        {
            announcements.push(Announcement {
                routes: nlri.iter().map(Route::from).collect(),
                nexthop: IpAddr::V6(next_hop_local.unwrap_or(*next_hop_global)),
            });
        }

        // IPv6 withdrawn using MP-BGP.
        if let Some(MpUnreach::Ipv6Unicast { nlri }) =
            msg.path_attributes()
                .iter()
                .find_map(|attr| match attr.value() {
                    PathAttributeValue::MpUnreach(unreach) => Some(unreach),
                    _ => None,
                })
        {
            withdrawals.extend(nlri.iter().map(Route::from));
        }

        Ok(Self {
            announcements,
            withdrawals,
        })
    }
}

// Filter out BGP updates for a specific peer and emit
// them from the speaker via an update channel.
#[allow(clippy::type_complexity)]
#[tracing::instrument(skip_all, fields(peer = %peer_address))]
async fn process_bgp_updates(
    peer_address: IpAddr,
    mut fsm_state_rx: UnboundedReceiver<
        std::result::Result<(FsmState, BgpEvent<SocketAddr>), FsmStateError<SocketAddr>>,
    >,
    update_tx: mpsc::Sender<Update>,
) {
    use netgauze_bgp_speaker::events::BgpEvent as E;
    use netgauze_bgp_speaker::fsm::FsmState as S;

    while let Some(event) = fsm_state_rx.recv().await {
        match event {
            Ok((S::Established, E::UpdateMsg(msg, treatment))) => {
                if treatment != UpdateTreatment::Normal {
                    warn!(?treatment, "Skipping update message, invalid treatment");
                    continue;
                }

                let update = match Update::try_from(msg) {
                    Ok(update) => update,
                    Err(e) => {
                        warn!(error = %e, "Failed parsing BGP update message");
                        continue;
                    }
                };
                debug!(?update, "BGP update");
                let _ = update_tx.send(update).await;
            }
            Ok(event) => {
                debug!(?event, "BGP event");
            }
            Err(e) => {
                drop(update_tx);
                error!(error = %e, "FSM failed, handling stopped");
                return;
            }
        }
    }
}
