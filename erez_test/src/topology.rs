use std::fmt;
use std::net::Ipv6Addr;
use std::sync::atomic::{AtomicU32, Ordering};

use ipnet::{IpNet, Ipv4AddrRange, Ipv4Net, Ipv6AddrRange, Ipv6Net};
use rand::Rng;

use crate::bird::config::Peer;
use crate::bird::daemon::Bird;
use crate::netlink::Netlink;
use crate::ns::Ns;

static NEXT_ROUTER_ID: AtomicU32 = AtomicU32::new(1);

fn next_router_id() -> u32 {
    NEXT_ROUTER_ID.fetch_add(1, Ordering::Relaxed)
}

/// A Linux bridge device inside a namespace.
#[derive(Debug, Clone)]
pub struct Bridge {
    /// Namespace the bridge lives in.
    pub ns: Ns,

    /// Interface name, (e.g. "br04a1").
    pub name: String,

    /// IPv6 link-local address assigned to the bridge.
    pub link_local: Ipv6Addr,
}

impl Bridge {
    pub async fn new(ns: Ns) -> anyhow::Result<Bridge> {
        let device = {
            let id: u16 = rand::rng().random();
            format!("br{id:04x}")
        };
        let address = ns
            .spawn({
                let name = device.clone();
                async move {
                    let nl = Netlink::connect()?;
                    let idx = nl.bridge_create(&name).await?;
                    nl.link_set_up(idx).await?;
                    let address = nl.link_get_link_local(&name).await?;
                    Ok::<_, anyhow::Error>(address)
                }
            })
            .await??;
        Ok(Bridge {
            ns,
            name: device,
            link_local: address,
        })
    }
}

/// Where to place one end of a veth pair and how to configure it.
pub enum VethPlacement {
    /// Move into the namespace and assign the given CIDR.
    Addr(Ns, IpNet),

    /// Move into the namespace with no address assigned.
    /// The end still receives an IPv6 link-local address.
    Bare(Ns),

    /// Attach as a port on the given bridge.
    BridgePort(Bridge),
}

impl VethPlacement {
    /// The namespace this end will be moved into.
    pub fn ns(&self) -> &Ns {
        match self {
            VethPlacement::Addr(ns, _) | VethPlacement::Bare(ns) => ns,
            VethPlacement::BridgePort(bridge) => &bridge.ns,
        }
    }
}

/// One end of a veth pair.
#[derive(Debug)]
pub struct VethEnd {
    /// Namespace this end was moved into.
    pub ns: Ns,

    /// Interface name, (e.g. "veth04a1" or "peer04a1").
    ///
    /// When this end is a bridge port, this is the bridge's
    /// name, since bridge ports have no independent L3
    /// identity.
    pub name: String,

    /// IPv6 link-local address assigned to this end.
    ///
    /// When this end is a bridge port, this is the bridge's
    /// link-local address, since bridge ports have no
    /// independent L3 identity.
    pub link_local: Ipv6Addr,
}

/// An IPv6 link-local address with its scope interface, (i.e. RFC 4007 zone ID).
#[derive(Debug, Clone)]
pub struct ScopedAddr {
    pub addr: Ipv6Addr,
    pub interface: String,
}

impl fmt::Display for ScopedAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}%{}", self.addr, self.interface)
    }
}

/// A connected veth pair spanning two namespaces.
#[derive(Debug)]
pub struct VethPair {
    /// The first end, typically the initiating side.
    pub device: VethEnd,

    /// The second end, typically the remote side.
    pub peer: VethEnd,
}

impl VethPair {
    pub async fn new(device: VethPlacement, peer: VethPlacement) -> anyhow::Result<VethPair> {
        let (device_name, peer_name) = {
            let id: u16 = rand::rng().random();
            (format!("veth{id:04x}"), format!("peer{id:04x}"))
        };

        let nl = Netlink::connect()?;
        let (device_idx, peer_idx) = nl.veth_create_pair(&device_name, &peer_name).await?;

        // We need to bring both ends up before link-local addresses
        // are assigned to each end. Then we can query for these
        // addresses.
        VethPair::setup_end(&nl, &device, device_idx, device_name.to_string()).await?;
        VethPair::setup_end(&nl, &peer, peer_idx, peer_name.to_string()).await?;

        let query_ll = |ns: &Ns, name: String| {
            ns.spawn(async move {
                let nl = Netlink::connect()?;
                nl.link_get_link_local(&name).await
            })
        };
        let device_address = query_ll(device.ns(), device_name.clone()).await??;
        let peer_address = query_ll(peer.ns(), peer_name.clone()).await??;

        let (device_ll, device_name) = match &device {
            VethPlacement::BridgePort(b) => (b.link_local, b.name.clone()),
            _ => (device_address, device_name),
        };
        let (peer_ll, peer_name) = match &peer {
            VethPlacement::BridgePort(b) => (b.link_local, b.name.clone()),
            _ => (peer_address, peer_name),
        };

        Ok(VethPair {
            device: VethEnd {
                name: device_name,
                link_local: device_ll,
                ns: device.ns().clone(),
            },
            peer: VethEnd {
                name: peer_name,
                link_local: peer_ll,
                ns: peer.ns().clone(),
            },
        })
    }

    /// Scoped address of the peer, from the device side.
    pub fn peer_addr(&self) -> ScopedAddr {
        ScopedAddr {
            addr: self.peer.link_local,
            interface: self.device.name.clone(),
        }
    }

    /// Scoped address of the device, from the peer side.
    pub fn device_addr(&self) -> ScopedAddr {
        ScopedAddr {
            addr: self.device.link_local,
            interface: self.peer.name.clone(),
        }
    }

    async fn setup_end(
        nl: &Netlink,
        end: &VethPlacement,
        veth_idx: u32,
        veth_name: String,
    ) -> anyhow::Result<()> {
        let ns = end.ns();

        // Move the veth into the target namespace.
        nl.veth_set_ns(veth_idx, ns.pid()).await?;

        // Configure the veth end inside the target namespace.
        ns.spawn({
            let address = match end {
                VethPlacement::Addr(_, addr) => Some(*addr),
                VethPlacement::Bare(_) | VethPlacement::BridgePort(_) => None,
            };
            let br_name = match end {
                VethPlacement::Addr(_, _) | VethPlacement::Bare(_) => None,
                VethPlacement::BridgePort(bridge) => Some(bridge.name.clone()),
            };
            async move {
                let nl = Netlink::connect()?;
                let link_idx = nl.link_get_index(&veth_name).await?;
                if let Some(address) = address {
                    nl.addr_add(link_idx, address).await?;
                }
                if let Some(br_name) = br_name {
                    let bridge_idx = nl.link_get_index(&br_name).await?;
                    nl.bridge_add_port(bridge_idx, link_idx).await?;
                }
                nl.link_set_up(link_idx).await?;
                Ok::<_, anyhow::Error>(())
            }
        })
        .await??;

        Ok(())
    }
}

pub struct RouterInterface {
    /// L2 switch for packets on this interface.
    pub bridge: Bridge,

    /// Subnet used to allocate IPv4 addresses.
    pub hosts_v4: Ipv4AddrRange,

    /// Subnet used to allocate IPv6 addresses.
    pub hosts_v6: Ipv6AddrRange,
}

/// A BGP router running BIRD inside a network namespace.
pub struct Router<K> {
    /// Namespace the router runs in.
    pub ns: Ns,

    /// BIRD routing daemon instance.
    pub bird: Bird,

    /// Role-specific state.
    pub kind: K,
}

pub async fn peer<A, B>(a: &mut Router<A>, b: &mut Router<B>) -> anyhow::Result<VethPair> {
    let veth = VethPair::new(
        VethPlacement::Bare(a.ns.clone()),
        VethPlacement::Bare(b.ns.clone()),
    )
    .await?;

    let peer_a = Peer::new(b.ns.display_name(), veth.peer_addr().addr, b.bird.asn)
        .interface(veth.peer_addr().interface)
        .connect_delay_seconds(1);
    let peer_b = Peer::new(a.ns.display_name(), veth.device_addr().addr, a.bird.asn)
        .interface(veth.device_addr().interface)
        .connect_delay_seconds(1);

    a.bird.add_peer(peer_a).await?;
    b.bird.add_peer(peer_b).await?;

    Ok(veth)
}

/// A transit router in an external AS.
pub struct Transit;

impl Router<Transit> {
    pub async fn new(name: &str, asn: u32) -> anyhow::Result<Router<Transit>> {
        let ns = Ns::net(name).await?;
        set_ip_forwarding(&ns, true).await?;

        let id = next_router_id();
        let bird = Bird::new(id, asn, ns.net_ns().clone()).await?;

        Ok(Router {
            ns,
            bird,
            kind: Transit,
        })
    }
}

/// A bare-metal server.
pub struct Metal {
    /// Namespace the metal runs in.
    pub ns: Ns,

    /// IPv4 address on the loopback, used as the preferred
    /// source address for outgoing IPv4 traffic.
    pub sitelocal_v4: Ipv4Net,

    /// IPv6 address on the loopback, used as the preferred
    /// source address for outgoing IPv6 traffic.
    pub sitelocal_v6: Ipv6Net,

    /// BIRD routing daemon instance announcing sitelocals
    /// to the edge.
    pub bird: Bird,

    /// Interface name for the metal's uplink to the edge router.
    pub uplink: String,
}

/// An edge router that bridges metals and provides them
/// with upstream connectivity via BGP.
pub struct Edge {
    /// Network segment where metals are connected.
    pub interface: RouterInterface,
}

impl Router<Edge> {
    pub async fn new(
        name: &str,
        asn: u32,
        v4_subnet: Ipv4Net,
        v6_subnet: Ipv6Net,
    ) -> anyhow::Result<Router<Edge>> {
        let ns = Ns::net(name).await?;
        let bridge = Bridge::new(ns.clone()).await?;
        set_ip_forwarding(&ns, true).await?;

        let id = next_router_id();
        let mut bird = Bird::new(id, asn, ns.net_ns().clone()).await?;

        // Accept any BGP peers from link-local addresses on the bridge.
        bird.add_peer(
            Peer::new("metal", "fe80::/10".parse::<IpNet>().unwrap(), asn)
                .interface(bridge.name.clone())
                .add_paths_tx(true),
        )
        .await?;

        // Skip the first IPv6 host, so that the numbering
        // begins at 1, making it consistent with IPv4.
        let mut hosts_v6 = v6_subnet.hosts();
        hosts_v6.next();

        Ok(Router {
            ns,
            bird,
            kind: Edge {
                interface: RouterInterface {
                    bridge,
                    hosts_v4: v4_subnet.hosts(),
                    hosts_v6,
                },
            },
        })
    }

    pub async fn add_metal(&mut self, name: &str) -> anyhow::Result<Metal> {
        let ns = Ns::net(name).await?;
        let interface = &mut self.kind.interface;

        // Connect metal to the edge's bridge.
        let link = VethPair::new(
            VethPlacement::Bare(ns.clone()),
            VethPlacement::BridgePort(interface.bridge.clone()),
        )
        .await?;

        // Allocate the next IPs from the edge's subnet
        // and assign it to the metal's loopback.
        let sitelocal_v4 = {
            let addr = interface
                .hosts_v4
                .next()
                .ok_or(anyhow::anyhow!("IPv4 metal subnet exhausted"))?;
            Ipv4Net::new(addr, 32)?
        };
        let sitelocal_v6 = {
            let addr = interface
                .hosts_v6
                .next()
                .ok_or(anyhow::anyhow!("IPv6 metal subnet exhausted"))?;
            Ipv6Net::new(addr, 128)?
        };
        ns.spawn(async move {
            let nl = Netlink::connect()?;
            let lo_idx = nl.link_get_index("lo").await?;
            nl.addr_add(lo_idx, sitelocal_v4).await?;
            nl.addr_add(lo_idx, sitelocal_v6).await?;
            Ok::<_, anyhow::Error>(())
        })
        .await??;

        // Set default routes on the metal to point to the router's bridge.
        ns.spawn({
            let device_name = link.device.name.clone();
            let bridge_address = interface.bridge.link_local;
            async move {
                let nl = Netlink::connect()?;
                nl.route_add_default_via_v6(
                    bridge_address,
                    &device_name,
                    sitelocal_v4.addr(),
                    sitelocal_v6.addr(),
                )
                .await?;
                Ok::<_, anyhow::Error>(())
            }
        })
        .await??;

        // Configure BIRD on the metal to peer with the edge.
        let id = next_router_id();
        let mut bird = Bird::new(id, self.bird.asn, ns.net_ns().clone()).await?;
        bird.add_peer(
            Peer::new("edge", link.peer_addr().addr, self.bird.asn)
                .interface(link.peer_addr().interface),
        )
        .await?;

        Ok(Metal {
            ns,
            bird,
            sitelocal_v4,
            sitelocal_v6,
            uplink: link.device.name,
        })
    }
}

pub async fn set_ip_forwarding(ns: &Ns, forward: bool) -> anyhow::Result<()> {
    let v = if forward { "1" } else { "0" };
    ns.spawn(async move {
        tokio::fs::write("/proc/sys/net/ipv4/ip_forward", v).await?;
        tokio::fs::write("/proc/sys/net/ipv6/conf/all/forwarding", v).await?;
        Ok::<_, anyhow::Error>(())
    })
    .await??;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn direct_connectivity() {
        let ns_a = Ns::net("a").await.unwrap();
        let ns_b = Ns::net("b").await.unwrap();
        let link = VethPair::new(
            VethPlacement::Bare(ns_a.clone()),
            VethPlacement::Bare(ns_b.clone()),
        )
        .await
        .unwrap();

        let b_addr = link.peer_addr();
        let out = ns_a
            .exec("ping", &["-6", "-c", "1", "-W", "3", &b_addr.to_string()])
            .await
            .unwrap();
        assert!(
            out.status.success(),
            "A should reach B via link-local: {}",
            out.status,
        );

        let a_addr = link.device_addr();
        let out = ns_b
            .exec("ping", &["-6", "-c", "1", "-W", "1", &a_addr.to_string()])
            .await
            .unwrap();
        assert!(
            out.status.success(),
            "B should reach A via link-local: {}",
            out.status
        );
    }

    #[tokio::test]
    async fn star_connectivity() {
        // Create hub namespace with a bridge.
        let hub = Ns::net("hub").await.unwrap();
        let bridge = Bridge::new(hub.clone()).await.unwrap();

        // Create three spokes, each linked to the hub's bridge.
        let mut spokes = Vec::new();
        for i in 0..3 {
            let ns = Ns::net(&format!("s{i}")).await.unwrap();
            let link = VethPair::new(
                VethPlacement::Bare(ns.clone()),
                VethPlacement::BridgePort(bridge.clone()),
            )
            .await
            .unwrap();
            spokes.push((ns, link));
        }

        // Verify spoke-to-spoke connectivity through the bridge.
        for (i, (ns_from, link_from)) in spokes.iter().enumerate() {
            for (j, (_, link_to)) in spokes.iter().enumerate() {
                if i == j {
                    continue;
                }

                let target = format!("{}%{}", link_to.device.link_local, link_from.device.name);
                let out = ns_from
                    .exec("ping", &["-6", "-c", "1", "-W", "1", &target])
                    .await
                    .unwrap();
                assert!(
                    out.status.success(),
                    "spoke {i} should reach spoke {j} at {target}"
                );
            }
        }
    }
}
