# Erez

eBPF-based per-packet multipath routing.

## FAQ

**Q: How does routing work?**

`erezd` is a daemon that runs on metals in *encap* mode, and on edge
routers in *decap* mode.

- On metals, the daemon peers with BGP routers to collect all nexthops for
  each prefix. On every outbound packet it picks a nexthop at random and
  encapsulates the packet in IPv6/GRE toward it
- On edge routers, the daemon receives these encapsulated packets, strips
  the IPv6/GRE header, and forwards the inner packet through the nexthop

*Currently nexthop selection is random (**!**), but support is planned for
balancing based on capacity and health, in addition to other metrics.*

**Q: Is this production-ready?**

Not yet!
