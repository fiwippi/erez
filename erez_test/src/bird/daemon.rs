use std::str::FromStr;

use ipnet::IpNet;
use tokio::time::Duration;

use crate::ns::{NetNs, Ns, NsChild};

use super::config::{Peer, Render, Route};

/// This is the default BIRD config path.
const PATH_CONFIG: &str = "/etc/bird/bird.conf";

pub struct Bird {
    /// Namespace this BIRD instance runs in.
    pub ns: Ns,
    /// Unique 32-bit router identifier.
    pub id: u32,
    /// Local autonomous system number.
    pub asn: u32,
    /// IPv4 static routes announced to BGP peers.
    routes_v4: Vec<Route>,
    /// IPv6 static routes announced to BGP peers.
    routes_v6: Vec<Route>,
    /// BGP peer sessions.
    peers: Vec<Peer>,
    /// Held to keep the BIRD process alive.
    _child: NsChild,
}

impl Bird {
    /// Start a BIRD routing daemon inside the given namespace.
    pub async fn new(id: u32, asn: u32, net_ns: NetNs) -> anyhow::Result<Bird> {
        let ns = Ns::builder(net_ns)
            .mount("bird", &["/run/bird", "/etc/bird"])
            .build()
            .await?;

        let render = Render {
            id,
            asn,
            routes_v4: &[],
            routes_v6: &[],
            peers: &[],
        }
        .to_string();
        ns.spawn(async { tokio::fs::write(PATH_CONFIG, render).await })
            .await??;

        let child = ns.spawn_process("bird", &["-d"]).await?;
        let bird = Bird {
            ns,
            id,
            asn,
            routes_v4: Vec::new(),
            routes_v6: Vec::new(),
            peers: Vec::new(),
            _child: child,
        };

        // Wait for BIRD's control socket to be initialised before
        // returning, otherwise birdc calls may error.
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if bird.birdc(&["show", "status"]).await.is_ok() {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        })
        .await?;

        Ok(bird)
    }

    pub async fn all_peers_established(&self) -> anyhow::Result<bool> {
        let protocols = self.protocols().await?;
        let all_established = self.peers.iter().all(|peer| {
            protocols
                .iter()
                .any(|p| p.name == peer.name && p.proto == "BGP" && p.state == "Established")
        });
        Ok(all_established)
    }

    pub async fn add_peer(&mut self, peer: Peer) -> anyhow::Result<()> {
        self.peers.push(peer);
        self.reconfigure().await
    }

    pub async fn announce_route(&mut self, route: Route) -> anyhow::Result<()> {
        match route.prefix {
            IpNet::V4(_) => self.routes_v4.push(route),
            IpNet::V6(_) => self.routes_v6.push(route),
        }
        self.reconfigure().await
    }

    pub async fn announce_routes(
        &mut self,
        routes: impl IntoIterator<Item = Route>,
    ) -> anyhow::Result<()> {
        for route in routes {
            match route.prefix {
                IpNet::V4(_) => self.routes_v4.push(route),
                IpNet::V6(_) => self.routes_v6.push(route),
            }
        }
        self.reconfigure().await
    }

    pub async fn withdraw_route(&mut self, route: impl Into<IpNet>) -> anyhow::Result<()> {
        let route = route.into();
        match route {
            IpNet::V4(_) => self.routes_v4.retain(|r| r.prefix != route),
            IpNet::V6(_) => self.routes_v6.retain(|r| r.prefix != route),
        }
        self.reconfigure().await
    }

    async fn birdc(&self, args: &[&str]) -> anyhow::Result<String> {
        let output = self.ns.exec_checked("birdc", args).await?;
        Ok(String::from_utf8_lossy(&output).into_owned())
    }

    async fn protocols(&self) -> anyhow::Result<Vec<ProtocolEntry>> {
        let s = self.birdc(&["show", "protocols"]).await?;
        parse_protocols(&s)
    }

    // Currently only used during tests to verify that BIRD
    // is exchanging routes between peers correctly.
    #[cfg(test)]
    async fn routes(&self) -> anyhow::Result<Vec<RouteEntry>> {
        let s = self.birdc(&["show", "route"]).await?;
        parse_routes(&s)
    }

    async fn reconfigure(&self) -> anyhow::Result<()> {
        let config = Render {
            id: self.id,
            asn: self.asn,
            routes_v4: &self.routes_v4,
            routes_v6: &self.routes_v6,
            peers: &self.peers,
        }
        .to_string();
        self.ns
            .spawn(async { tokio::fs::write(PATH_CONFIG, config).await })
            .await??;
        self.birdc(&["configure"]).await?;
        Ok(())
    }
}

#[derive(Debug, Clone)]
struct ProtocolEntry {
    pub name: String,
    pub proto: String,
    pub state: String,
}

fn parse_protocols(s: &str) -> anyhow::Result<Vec<ProtocolEntry>> {
    let mut lines = s.lines();

    // Header line anchors column positions.
    let header = lines
        .find(|l| l.starts_with("Name"))
        .ok_or_else(|| anyhow::anyhow!("Missing header in protocols output"))?;

    let proto_col = header
        .find("Proto")
        .ok_or_else(|| anyhow::anyhow!("Missing Proto column"))?;
    let info_col = header
        .find("Info")
        .ok_or_else(|| anyhow::anyhow!("Missing Info column"))?;

    let entries = lines
        .filter(|l| !l.is_empty())
        .map(|line| {
            let name = line[..proto_col].trim().to_string();
            let proto = line[proto_col..]
                .split_whitespace()
                .next()
                .unwrap_or("")
                .to_string();
            let state = if line.len() > info_col {
                line[info_col..].trim().to_string()
            } else {
                String::new()
            };
            ProtocolEntry { name, proto, state }
        })
        .collect();
    Ok(entries)
}

#[derive(Debug, Clone, PartialEq)]
struct RouteEntry {
    pub prefix: IpNet,
    pub peer: String,
}

impl FromStr for RouteEntry {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let prefix: IpNet = s
            .split_whitespace()
            .next()
            .ok_or_else(|| anyhow::anyhow!("Empty route line"))?
            .parse()?;

        let bracket = s
            .find('[')
            .ok_or_else(|| anyhow::anyhow!("Missing '[' in route line"))?
            + 1;
        let rest = &s[bracket..];
        let end = rest
            .find(|c: char| c.is_whitespace() || c == ']')
            .ok_or_else(|| anyhow::anyhow!("Malformed peer name"))?;
        let peer = rest[..end].to_string();

        Ok(RouteEntry { prefix, peer })
    }
}

// Currently only used during tests to verify that BIRD
// is exchanging routes between peers correctly.
#[cfg(test)]
fn parse_routes(s: &str) -> anyhow::Result<Vec<RouteEntry>> {
    let entries = s
        .lines()
        .filter(|l| {
            !l.is_empty()
                && !l.starts_with(char::is_whitespace)
                && !l.starts_with("BIRD")
                && !l.starts_with("Table")
        })
        .filter_map(|l| l.parse::<RouteEntry>().ok())
        .collect();
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        assert_eventually,
        bird::config::Peer,
        netlink::Netlink,
        topology::{VethPair, VethPlacement},
    };

    /// Two BIRD instances connected by a veth pair with an
    /// established BGP session, ready for route exchange.
    async fn bird_pair() -> (Bird, Bird) {
        let ns_a = Ns::net("a").await.unwrap();
        let ns_b = Ns::net("b").await.unwrap();
        let link = VethPair::new(
            VethPlacement::Bare(ns_a.clone()),
            VethPlacement::Bare(ns_b.clone()),
        )
        .await
        .unwrap();

        const ASN: u32 = 64512;
        let (mut a, mut b) = tokio::try_join!(
            Bird::new(1, ASN, ns_a.net_ns().clone()),
            Bird::new(2, ASN, ns_b.net_ns().clone()),
        )
        .unwrap();

        a.add_peer(
            Peer::new("peer_b", link.peer_addr().addr, ASN)
                .interface(link.peer_addr().interface)
                .connect_delay_seconds(1),
        )
        .await
        .unwrap();
        b.add_peer(
            Peer::new("peer_a", link.device_addr().addr, ASN)
                .interface(link.device_addr().interface)
                .connect_delay_seconds(1),
        )
        .await
        .unwrap();

        assert_eventually!(
            assert!(b.all_peers_established().await.unwrap()),
            Duration::from_secs(5),
        );

        (a, b)
    }

    #[tokio::test]
    async fn export_loopback_routes() {
        let (a, b) = bird_pair().await;

        let prefix_v4: IpNet = "172.16.0.1/32".parse().unwrap();
        let prefix_v6: IpNet = "3fff::1/128".parse().unwrap();

        // Assign addresses to A's loopback.
        a.ns.spawn(async move {
            let nl = Netlink::connect()?;
            nl.addr_add("lo", prefix_v4).await?;
            nl.addr_add("lo", prefix_v6).await?;
            Ok::<_, anyhow::Error>(())
        })
        .await
        .unwrap()
        .unwrap();

        // Both routes should propagate to B via BGP.
        assert_eventually!(
            {
                let routes = b.routes().await.unwrap();
                assert!(
                    routes.iter().any(|r| r.prefix == prefix_v4),
                    "IPv4 loopback route not received by peer, got: {routes:?}"
                );
                assert!(
                    routes.iter().any(|r| r.prefix == prefix_v6),
                    "IPv6 loopback route not received by peer, got: {routes:?}"
                );
            },
            Duration::from_secs(5),
        );
    }

    #[tokio::test]
    async fn peer_link_local() {
        let ns_a = Ns::net("a").await.unwrap();
        let ns_b = Ns::net("b").await.unwrap();
        let link = VethPair::new(
            VethPlacement::Bare(ns_a.clone()),
            VethPlacement::Bare(ns_b.clone()),
        )
        .await
        .unwrap();

        const ASN: u32 = 64512;

        let cases: Vec<Peer> = vec![
            // Explicit link-local address.
            Peer::new("peer_b", link.peer_addr().addr, ASN)
                .interface(link.peer_addr().interface)
                .connect_delay_seconds(1),
            // Link-local range (fe80::/10).
            Peer::new("peer_b", "fe80::/10".parse::<IpNet>().unwrap(), ASN)
                .interface(link.peer_addr().interface)
                .connect_delay_seconds(1),
        ];

        for peer_a in cases {
            let (mut bird_a, mut bird_b) = tokio::try_join!(
                Bird::new(1, ASN, ns_a.net_ns().clone()),
                Bird::new(2, ASN, ns_b.net_ns().clone()),
            )
            .unwrap();

            bird_a.add_peer(peer_a).await.unwrap();
            bird_b
                .add_peer(
                    Peer::new("peer_a", link.device_addr().addr, ASN)
                        .interface(link.device_addr().interface)
                        .connect_delay_seconds(1),
                )
                .await
                .unwrap();

            assert_eventually!(
                assert!(
                    bird_b.all_peers_established().await.unwrap(),
                    "BGP session not established"
                ),
                Duration::from_secs(5),
            );
        }
    }

    #[tokio::test]
    async fn route_lifecycle() {
        let (mut a, b) = bird_pair().await;

        let routes = b.routes().await.unwrap();
        assert_eq!(routes.len(), 0, "no routes should exist initially");

        let route: IpNet = "172.0.0.0/24".parse().unwrap();

        a.announce_route(Route::blackhole(route)).await.unwrap();
        assert_eventually!(
            {
                let routes = b.routes().await.unwrap();
                assert_eq!(routes.len(), 1);
                assert_eq!(
                    routes[0],
                    RouteEntry {
                        prefix: route,
                        peer: "peer_a".to_string(),
                    },
                    "announced route not picked up by peer"
                );
            },
            Duration::from_secs(5),
        );

        a.withdraw_route(route).await.unwrap();
        assert_eventually!(
            {
                let routes = b.routes().await.unwrap();
                assert!(routes.is_empty(), "withdrawn route not picked up by peer");
            },
            Duration::from_secs(5)
        );
    }
}
