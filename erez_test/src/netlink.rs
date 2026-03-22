use std::net::Ipv4Addr;
use std::net::{IpAddr, Ipv6Addr};

use futures::TryStreamExt;
use ipnet::IpNet;
use netlink_packet_route::address::AddressAttribute;
use nix::unistd::Pid;
use rtnetlink::{LinkBridge, LinkUnspec, LinkVeth, RouteMessageBuilder};

pub struct Netlink {
    handle: rtnetlink::Handle,
}

impl Netlink {
    pub fn connect() -> anyhow::Result<Self> {
        let (connection, handle, _) = rtnetlink::new_connection()?;
        tokio::spawn(connection);
        Ok(Self { handle })
    }

    pub async fn addr_add(&self, name: &str, cidr: impl Into<IpNet>) -> anyhow::Result<()> {
        let cidr = cidr.into();
        let idx = self.link_get_index(name).await?;
        self.handle
            .address()
            .add(idx, cidr.addr(), cidr.prefix_len())
            .execute()
            .await?;
        Ok(())
    }

    pub async fn bridge_add_port(&self, bridge_name: &str, port_name: &str) -> anyhow::Result<()> {
        let bridge_idx = self.link_get_index(bridge_name).await?;
        self.handle
            .link()
            .change(
                LinkUnspec::new_with_name(port_name)
                    .controller(bridge_idx)
                    .build(),
            )
            .execute()
            .await?;
        Ok(())
    }

    pub async fn bridge_create(&self, name: &str) -> anyhow::Result<()> {
        self.handle
            .link()
            .add(LinkBridge::new(name).build())
            .execute()
            .await?;
        Ok(())
    }

    async fn link_get_index(&self, name: &str) -> anyhow::Result<u32> {
        let mut links = self
            .handle
            .link()
            .get()
            .match_name(name.to_string())
            .execute();
        let link_msg = links
            .try_next()
            .await?
            .ok_or(anyhow::anyhow!("Link not found: {name}"))?;
        Ok(link_msg.header.index)
    }

    pub async fn link_get_link_local(&self, name: &str) -> anyhow::Result<Ipv6Addr> {
        let idx = self.link_get_index(name).await?;
        let mut addrs = self
            .handle
            .address()
            .get()
            .set_link_index_filter(idx)
            .execute();
        while let Some(msg) = addrs.try_next().await? {
            for attr in &msg.attributes {
                if let AddressAttribute::Address(IpAddr::V6(v6)) = attr {
                    // Extract the top 10 bits.
                    if (v6.segments()[0] & 0xffc0) == 0xfe80 {
                        return Ok(*v6);
                    }
                }
            }
        }
        Err(anyhow::anyhow!("No link-local address found on {name}"))
    }

    pub async fn link_set_up(&self, name: &str) -> anyhow::Result<()> {
        self.handle
            .link()
            .change(LinkUnspec::new_with_name(name).up().build())
            .execute()
            .await?;
        Ok(())
    }

    pub async fn route_add_default_via_v6(
        &self,
        gateway: Ipv6Addr,
        device: &str,
        src_v4: impl Into<Option<Ipv4Addr>>,
        src_v6: impl Into<Option<Ipv6Addr>>,
    ) -> anyhow::Result<()> {
        let dev_idx = self.link_get_index(device).await?;

        if let Some(src) = src_v6.into() {
            let route = RouteMessageBuilder::<Ipv6Addr>::new()
                .destination_prefix(Ipv6Addr::UNSPECIFIED, 0)
                .gateway(gateway)
                .output_interface(dev_idx)
                .pref_source(src)
                .build();
            self.handle.route().add(route).execute().await?;
        }

        if let Some(src) = src_v4.into() {
            let route = RouteMessageBuilder::<Ipv4Addr>::new()
                .destination_prefix(Ipv4Addr::UNSPECIFIED, 0)
                .via(gateway)
                .output_interface(dev_idx)
                .pref_source(src)
                .build();
            self.handle.route().add(route).execute().await?;
        }

        Ok(())
    }

    pub async fn veth_create_pair(&self, device_name: &str, peer_name: &str) -> anyhow::Result<()> {
        self.handle
            .link()
            .add(LinkVeth::new(device_name, peer_name).build())
            .execute()
            .await?;
        Ok(())
    }

    pub async fn veth_set_ns(&self, name: &str, ns_pid: Pid) -> anyhow::Result<()> {
        self.handle
            .link()
            .change(
                LinkUnspec::new_with_name(name)
                    .setns_by_pid(ns_pid.as_raw() as u32)
                    .build(),
            )
            .execute()
            .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ns::Ns;

    #[tokio::test]
    async fn addr_add_succeeds() {
        let ns = Ns::net("test").await.unwrap();
        ns.spawn(async {
            let nl = Netlink::connect().unwrap();
            nl.veth_create_pair("a", "b").await.unwrap();
            nl.addr_add("a", "10.0.0.1/24".parse::<IpNet>().unwrap())
                .await
        })
        .await
        .unwrap()
        .unwrap();
    }

    #[tokio::test]
    async fn bridge_add_port_succeeds() {
        let ns = Ns::net("test").await.unwrap();
        ns.spawn(async {
            let nl = Netlink::connect().unwrap();
            nl.bridge_create("br0").await.unwrap();
            nl.veth_create_pair("a", "b").await.unwrap();
            nl.bridge_add_port("br0", "a").await
        })
        .await
        .unwrap()
        .unwrap();
    }

    #[tokio::test]
    async fn bridge_create_duplicate_errors() {
        let ns = Ns::net("test").await.unwrap();
        let result = ns
            .spawn(async {
                let nl = Netlink::connect().unwrap();
                nl.bridge_create("br0").await.unwrap();
                nl.bridge_create("br0").await
            })
            .await
            .unwrap();
        assert!(result.is_err(), "duplicate bridge creation should fail");
    }

    #[tokio::test]
    async fn link_get_index_loopback() {
        let ns = Ns::net("test").await.unwrap();
        let idx = ns
            .spawn(async {
                let nl = Netlink::connect().unwrap();
                nl.link_get_index("lo").await.unwrap()
            })
            .await
            .unwrap();
        assert!(idx > 0, "loopback must have a valid index");
    }

    #[tokio::test]
    async fn link_get_index_not_found() {
        let ns = Ns::net("test").await.unwrap();
        let err = ns
            .spawn(async {
                let nl = Netlink::connect().unwrap();
                nl.link_get_index("non-existent").await
            })
            .await
            .unwrap()
            .unwrap_err();
        let is_enodev = err.downcast_ref::<rtnetlink::Error>().is_some_and(
            |e| matches!(e, rtnetlink::Error::NetlinkError(msg) if msg.raw_code() == -19),
        );
        assert!(is_enodev, "no device should exist");
    }

    #[tokio::test]
    async fn veth_create_pair_duplicate_errors() {
        let ns = Ns::net("test").await.unwrap();
        let err = ns
            .spawn(async {
                let nl = Netlink::connect().unwrap();
                nl.veth_create_pair("a", "b").await.unwrap();
                nl.veth_create_pair("a", "b").await
            })
            .await
            .unwrap()
            .unwrap_err();
        let is_eexist = err.downcast_ref::<rtnetlink::Error>().is_some_and(
            |e| matches!(e, rtnetlink::Error::NetlinkError(msg) if msg.raw_code() == -17),
        );
        assert!(is_eexist, "device should exist");
    }

    #[tokio::test]
    async fn veth_create_pair_returns_distinct_indices() {
        let ns = Ns::net("test").await.unwrap();
        let (a, b) = ns
            .spawn(async {
                let nl = Netlink::connect().unwrap();
                nl.veth_create_pair("a", "b").await.unwrap();
                let idx_a = nl.link_get_index("a").await.unwrap();
                let idx_b = nl.link_get_index("b").await.unwrap();
                (idx_a, idx_b)
            })
            .await
            .unwrap();
        assert_ne!(a, b, "veth pair must have distinct indices");
    }

    #[tokio::test]
    async fn veth_set_ns_moves_link_out() {
        let ns_src = Ns::net("src").await.unwrap();
        let ns_dst = Ns::net("dst").await.unwrap();

        let dst_pid = ns_dst.pid();
        ns_src
            .spawn(async move {
                let nl = Netlink::connect().unwrap();
                nl.veth_create_pair("a", "b").await.unwrap();
                nl.veth_set_ns("a", dst_pid).await.unwrap();
                let err = nl.link_get_index("a").await;
                assert!(err.is_err(), "moved link must not be found in source ns");
                Ok::<_, anyhow::Error>(())
            })
            .await
            .unwrap()
            .unwrap();

        ns_dst
            .spawn(async move {
                let nl = Netlink::connect().unwrap();
                let idx = nl.link_get_index("a").await.unwrap();
                assert!(idx > 0, "moved link must be found in destination ns");
                Ok::<_, anyhow::Error>(())
            })
            .await
            .unwrap()
            .unwrap();
    }
}
