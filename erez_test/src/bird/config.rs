use std::{
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use askama::Template;
use ipnet::{IpNet, Ipv4Net, Ipv6Net};

#[derive(Template)]
#[template(path = "bird.conf", escape = "none")]
pub(super) struct Render<'a> {
    pub id: u32,
    pub asn: u32,
    pub routes_v4: &'a [Route],
    pub routes_v6: &'a [Route],
    pub peers: &'a [Peer],
}

#[derive(Debug, Clone)]
pub struct Route {
    pub prefix: IpNet,
    kind: RouteKind,
}

impl Route {
    pub fn blackhole(prefix: impl Into<IpNet>) -> Self {
        Self {
            prefix: prefix.into(),
            kind: RouteKind::Blackhole,
        }
    }
}

impl fmt::Display for Route {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.prefix, self.kind)
    }
}

#[derive(Debug, Clone)]
enum RouteKind {
    Blackhole,
}

impl fmt::Display for RouteKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RouteKind::Blackhole => write!(f, "blackhole"),
        }
    }
}

pub struct Peer {
    pub name: String,
    pub port: u16,
    pub neighbour: Neighbour,
    pub interface: Option<String>,
    pub remote_as: u32,
    pub connect_delay_seconds: Option<u32>,
    pub add_paths_tx: bool,
}

impl Peer {
    pub fn new(name: impl Into<String>, neighbour: impl Into<Neighbour>, remote_as: u32) -> Peer {
        Peer {
            name: name.into(),
            port: 179,
            neighbour: neighbour.into(),
            remote_as,
            interface: None,
            connect_delay_seconds: None,
            add_paths_tx: false,
        }
    }

    #[must_use]
    pub fn add_paths_tx(mut self, enabled: bool) -> Self {
        self.add_paths_tx = enabled;
        self
    }

    #[must_use]
    pub fn connect_delay_seconds(mut self, delay: u32) -> Self {
        self.connect_delay_seconds = Some(delay);
        self
    }

    #[must_use]
    pub fn interface(mut self, interface: String) -> Self {
        self.interface = Some(interface);
        self
    }

    #[must_use]
    pub fn port(mut self, port: u16) -> Self {
        self.port = port;
        self
    }
}

#[derive(Debug, Clone)]
pub enum Neighbour {
    Ip(IpAddr),
    Range(IpNet),
}

impl From<IpAddr> for Neighbour {
    fn from(addr: IpAddr) -> Self {
        Self::Ip(addr)
    }
}

impl From<Ipv6Addr> for Neighbour {
    fn from(addr: Ipv6Addr) -> Self {
        Self::Ip(addr.into())
    }
}

impl From<Ipv4Addr> for Neighbour {
    fn from(addr: Ipv4Addr) -> Self {
        Self::Ip(addr.into())
    }
}

impl From<IpNet> for Neighbour {
    fn from(net: IpNet) -> Self {
        Self::Range(net)
    }
}

impl From<Ipv4Net> for Neighbour {
    fn from(net: Ipv4Net) -> Self {
        Self::Range(net.into())
    }
}

impl From<Ipv6Net> for Neighbour {
    fn from(net: Ipv6Net) -> Self {
        Self::Range(net.into())
    }
}
