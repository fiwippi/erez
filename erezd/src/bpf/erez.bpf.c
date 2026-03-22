#include "erez.bpf.h"
#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

// A ring buffer to send logs to user space.
struct e_logs {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 256 * 1024);
} e_logs SEC(".maps");

// Off-stack scratch space for log message formatting.
struct e_log_buf {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __type(key, u32);
  __type(value, struct log_event);
  __uint(max_entries, 1);
} e_log_buf SEC(".maps");

// An eBPF map of a single element that stores options of an attached
// erez_encap program.
struct e_encap_opts {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, struct opts);
	__uint(max_entries, 1);
} e_encap_opts SEC(".maps");

// An eBPF map of a single element that stores options of an attached
// erez_decap program.
struct e_decap_opts {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, struct opts);
	__uint(max_entries, 1);
} e_decap_opts SEC(".maps");

#define should_log(opts, lvl) ((lvl) >= (opts)->log_level)

// A convenient wrapper around `bpf_snprintf`.
#define snprintf(buf, fmt, args...)                                         \
  ({                                                                        \
	  static const char ___fmt[] = fmt;                                       \
	  unsigned long long ___params[___bpf_narg(args)];                        \
	  _Pragma("GCC diagnostic push")                                          \
    _Pragma("GCC diagnostic ignored \"-Wint-conversion\"")                  \
      ___bpf_fill(___params, args);                                         \
    _Pragma("GCC diagnostic pop")                                           \
      bpf_snprintf(buf, sizeof(buf), ___fmt, ___params, sizeof(___params)); \
	})

// Produces a log event at a given log level after recording the current
// source code line and formatting a message.
#define logf(opts, lvl, fmt, args...)                                                \
  ({                                                                                 \
    if (should_log(opts, lvl)) {                                                     \
      u32 ___key = 0;                                                                \
      struct log_event *___event =                                                   \
        bpf_map_lookup_percpu_elem(&e_log_buf, &___key, bpf_get_smp_processor_id()); \
      if (NULL != ___event) {                                                        \
        ___event->version = LOG_EVENT_FORMAT_VERSION;                                \
        ___event->level = lvl;                                                       \
        ___event->line = __LINE__;                                                   \
        snprintf(___event->message, fmt, args);                                      \
        bpf_ringbuf_output(&e_logs, ___event, sizeof(*___event), 0);                 \
      }                                                                              \
    }                                                                                \
  })

// Convenient logging wrappers for corresponding log levels.
#define tracef(opts, fmt, args...) logf(opts, TRACE, fmt, args)
#define debugf(opts, fmt, args...) logf(opts, DEBUG, fmt, args)
#define infof(opts, fmt, args...) logf(opts, INFO, fmt, args)
#define warnf(opts, fmt, args...) logf(opts, WARN, fmt, args)
#define errorf(opts, fmt, args...) logf(opts, ERROR, fmt, args)

// Keep this in sync with the Rust structure.
struct __attribute__((__packed__)) nlri_t {
  struct bpf_lpm_trie_key_hdr hdr;
  struct in6_addr address; // May be an IPv4-mapped IPv6 address.
};

// Keep this in sync with the Rust structure.
struct __attribute__((__packed__)) fib_entry_t {
  __u8 nexthop_count; // How many valid nexthops exist in the array.
  struct in6_addr nexthops[NEXTHOP_MAX_COUNT];
};

// A eBPF trie which maps an NLRI to nexthop IDs.
struct e_fib {
  // Updates are "atomic" due to the built-in RCU, so
  // we don't need to synchronise access to this map.
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__type(key, struct nlri_t);
	__type(value, struct fib_entry_t);
  // This flag must be set: https://docs.kernel.org/bpf/map_lpm_trie.html.
  __uint(map_flags, BPF_F_NO_PREALLOC);
 	__uint(max_entries, 1024); 
} e_fib SEC(".maps") ;

static __s64 __always_inline skb_extract_l4_proto(struct __sk_buff *skb, __u32 l3_proto, __u8 *l4_proto) {
  switch (l3_proto) {
  case ETH_P_IP: {
    __u32 offset = sizeof(struct ethhdr) + offsetof(struct iphdr, protocol);
    if (bpf_skb_load_bytes(skb, offset, l4_proto, sizeof(__u8)) < 0)
			return -1;
    break;
    }
  case ETH_P_IPV6: {
    __u32 offset = sizeof(struct ethhdr) + offsetof(struct ipv6hdr, nexthdr);
    if (bpf_skb_load_bytes(skb, offset, l4_proto, sizeof(__u8)) < 0)
			return -1;
    break;
    }
  default:
    return -1;
  };

  return 0;
}

static bool __always_inline valid_encap_l3_proto(__u32 proto) {
  // We only process packets that can be IP-routed to the Internet (via BGP).
  return proto == ETH_P_IP || proto == ETH_P_IPV6;
}

static bool __always_inline valid_encap_l4_proto(__u8 proto) {
  // We only process TCP/UDP/ICMP packets.
  return proto == IPPROTO_TCP || proto == IPPROTO_UDP || proto == IPPROTO_ICMP;
}

static bool __always_inline valid_decap_l3_proto(__u16 proto) {
  // Packets should only be encapsulated in IPv6.
  return proto == ETH_P_IPV6;
}

static bool __always_inline valid_decap_l4_proto(__u8 proto) {
  // Packets should only be encapsulated in GRE.
  return proto == IPPROTO_GRE;
}

static __s64 __always_inline skb_extract_nlri(struct __sk_buff *skb, __u32 l3_proto, struct nlri_t *nlri) {
  nlri->hdr.prefixlen = 128;
  switch (l3_proto) {
  case ETH_P_IP: {
    __u32 offset = sizeof(struct ethhdr) + offsetof(struct iphdr, daddr);
    if (bpf_skb_load_bytes(skb, offset, &nlri->address.in6_u.u6_addr32[3], sizeof(__be32)) < 0)
			return -1;
    nlri->address.in6_u.u6_addr16[5] = 0xffff;
    break;
    }
  case ETH_P_IPV6: {
    __u32 offset = sizeof(struct ethhdr) + offsetof(struct ipv6hdr, daddr);
    if (bpf_skb_load_bytes(skb, offset, &nlri->address, sizeof(struct in6_addr)) < 0)
			return -1;
    break;
    }
  };

  return 0;
}

// Reference: https://git.kernel.org/pub/scm/linux/kernel/git/bpf/bpf-next.git/tree/tools/testing/selftests/bpf/progs/test_tc_tunnel.c.
static __s64 __always_inline skb_encap_ip6_gre(struct __sk_buff *skb, struct in6_addr nexthop, __u32 l3_proto, __u32 l4_proto) {
  // Before we adjust room via direct memory access
  // we need to extract the packet's source address.
  struct in6_addr saddr = {0};

  switch (l3_proto) {
  case ETH_P_IP: {
    __u32 offset = sizeof(struct ethhdr) + offsetof(struct iphdr, saddr);
    if (bpf_skb_load_bytes(skb, offset, &saddr.in6_u.u6_addr32[3], sizeof(__be32)) < 0)
      return -1;
    saddr.in6_u.u6_addr16[5] = 0xffff;
    break;
    }
  case ETH_P_IPV6: {
    __u32 offset = sizeof(struct ethhdr) + offsetof(struct ipv6hdr, saddr);
    if (bpf_skb_load_bytes(skb, offset, &saddr, sizeof(saddr)) < 0)
      return -1;
    break;
    }
  default:
    return -1;
  };
  
  // Ok, now we're ready to adjust room.
	__u64 adj_room_flags = BPF_F_ADJ_ROOM_ENCAP_L3_IPV6 | BPF_F_ADJ_ROOM_ENCAP_L4_GRE;

  // We don't want gso_size to be changed when encapsulating UDP, since
  // this will change the point at which datagrams are delineated, which
  // fragments them incorrectly.
  if (l4_proto == IPPROTO_UDP)
    adj_room_flags |= BPF_F_ADJ_ROOM_FIXED_GSO;

  __s64 ret = bpf_skb_adjust_room(skb, ENCAP_LEN, BPF_ADJ_ROOM_MAC, adj_room_flags);
  if (ret < 0)
    return -1;

  void *head = (void*)(__u64)skb->data;
  void *tail = (void*)(__u64)skb->data_end;
  if (head + sizeof(struct ethhdr) + ENCAP_LEN > tail)
     return -1;

  struct ethhdr *eth = (struct ethhdr *)(head);
  eth->h_proto = bpf_htons(ETH_P_IPV6);

  struct ipv6hdr *ip6 = (struct ipv6hdr *)(head + sizeof(struct ethhdr));
  ip6->version = 6;
  ip6->hop_limit = 255;
	ip6->nexthdr = IPPROTO_GRE;
	ip6->saddr = saddr;
	ip6->daddr = nexthop;
	ip6->payload_len = bpf_htons(skb->len - sizeof(struct ethhdr) - sizeof(struct ipv6hdr));

  struct gre_base_hdr *gre = (struct gre_base_hdr *)(head + sizeof(struct ethhdr) + sizeof(struct ipv6hdr));
  gre->flags = 0;
  gre->protocol = bpf_htons(l3_proto);

  return 0;
}

static __s64 __always_inline xdp_decap_ip6_gre(struct xdp_md *ctx, __u16 gre_proto) {
  void *head = (void*)(__u64)ctx->data;
  void *tail = (void*)(__u64)ctx->data_end;
  if (head + sizeof(struct ethhdr) + ENCAP_LEN > tail)
    return -1;

  struct ethhdr *eth = (struct ethhdr *)(head);
  eth->h_proto = bpf_htons(gre_proto);

  __builtin_memmove(head + ENCAP_LEN, head, sizeof(struct ethhdr));
  return bpf_xdp_adjust_head(ctx, ENCAP_LEN);
}

static __s64 __always_inline xdp_decrement_ttl(struct xdp_md *ctx, __u16 gre_proto) {
  switch (gre_proto) {
  case ETH_P_IP: {
    void *head = (void*)(__u64)ctx->data;
    void *tail = (void*)(__u64)ctx->data_end;
    if (head + sizeof(struct ethhdr) + sizeof(struct iphdr) > tail)
      return -1;

    struct iphdr *ip = (struct iphdr *)(head + sizeof(struct ethhdr));
    if (ip->ttl <= 1)
      return -1;

    // Matches the kernel's ip_decrease_ttl implementation.
    ip->ttl -= 1;
    __u32 sum = (__u32)ip->check + bpf_htons(0x0100);
    ip->check = (__u16)(sum + (sum >= 0xFFFF));
     
    break;
    }
  case ETH_P_IPV6: {
    void *head = (void*)(__u64)ctx->data;
    void *tail = (void*)(__u64)ctx->data_end;
    if (head + sizeof(struct ethhdr) + sizeof(struct ipv6hdr) > tail)
      return -1;

    struct ipv6hdr *ip6 = (struct ipv6hdr *)(head + sizeof(struct ethhdr));
    if (ip6->hop_limit <= 1)
      return -1;
    ip6->hop_limit -= 1;

    break;
    }
  default:
    return -1;
  };

  return 0;
}

static __always_inline bool ipv6_is_mapped_ipv4(struct in6_addr *addr) {
	return addr->in6_u.u6_addr32[0] == 0 &&
	       addr->in6_u.u6_addr32[1] == 0 &&
	       addr->in6_u.u6_addr16[4] == 0 &&
	       addr->in6_u.u6_addr16[5] == 0xffff;
}

static __s64 __always_inline xdp_forward_packet(struct opts *opts, struct xdp_md *ctx, __u16 gre_proto, struct in6_addr nexthop) {
  // Since we do a direct FIB lookup which solely
  // depends on the destination IP, we don't need
  // to supply any source address in the lookup.
  struct bpf_fib_lookup fib_params = {
    .ifindex = ctx->ingress_ifindex,
  };
  if (ipv6_is_mapped_ipv4(&nexthop)) {
    fib_params.family = AF_INET;
    fib_params.ipv4_dst = nexthop.in6_u.u6_addr32[3];
  } else {
    fib_params.family = AF_INET6;
    __builtin_memcpy(fib_params.ipv6_dst, &nexthop, sizeof(nexthop));
  }

  // All our routes are installed by BIRD into the default
  // routing table, so, we can just skip any FIB rules which
  // may cause us to evaluate routes from a different table,
  // making this call more performant.
  __u32 fib_lookup_flags = BPF_FIB_LOOKUP_DIRECT; 
  __u64 ret = bpf_fib_lookup(ctx, &fib_params, sizeof(struct bpf_fib_lookup), fib_lookup_flags);
  if (ret != BPF_FIB_LKUP_RET_SUCCESS)
    return XDP_PASS;

  // Now that we want to forward the packet, let's decrement its TTL.
  __s64 ttl_ret = xdp_decrement_ttl(ctx, gre_proto);
  if (ttl_ret < 0) {
      errorf(opts, "reached: Failed to decrement TTL");
      return XDP_PASS;
  }

  // Rewrite the Ethernet headers, so that the
  // packets are switched to the correct remote
  // interface.
  void *head = (void*)(__u64)ctx->data;
  void *tail = (void*)(__u64)ctx->data_end;
  if (head + sizeof(struct ethhdr) > tail)
     return XDP_PASS;
  struct ethhdr *eth = (struct ethhdr *)(head);
  __builtin_memcpy(eth->h_dest, fib_params.dmac, ETH_ALEN);
	__builtin_memcpy(eth->h_source, fib_params.smac, ETH_ALEN);

	// This should never happen, unless a peer is
	// messing with us, as these types of packets
	// should only originate from inside our
	// network.
  if (fib_params.ifindex == ctx->ingress_ifindex) {
    return XDP_TX;
  }
  // XDP version of this function accepts no flags.
  return bpf_redirect(fib_params.ifindex, 0);
}

SEC("tc")
int erez_encap(struct __sk_buff *skb) {
  __u32 key = 0;
	struct opts *opts = bpf_map_lookup_elem(&e_encap_opts, &key);
	if (opts == NULL) {
	  return TC_ACT_OK;
	}

  // Extract prerequisite data.
  __u32 l3_proto = bpf_ntohs(skb->protocol);
  if (!valid_encap_l3_proto(l3_proto)) {
    tracef(opts, "reached: L3 protocol not supported: %u", l3_proto);
    return TC_ACT_OK;
  }
  __u8 l4_proto;
  if (skb_extract_l4_proto(skb, l3_proto, &l4_proto) < 0)
    return TC_ACT_OK;
  if (!valid_encap_l4_proto(l4_proto)) {
    tracef(opts, "reached: L4 protocol not supported: %u", l4_proto);
    return TC_ACT_OK;
  }
  struct nlri_t nlri = {0};
  if (skb_extract_nlri(skb, l3_proto, &nlri) < 0)
      return TC_ACT_OK;

  // Look up nexthops for the NLRI.
  struct fib_entry_t *entry = bpf_map_lookup_elem(&e_fib, &nlri);
  if (entry == NULL) {
    tracef(opts, "reached: No FIB entry found for %pI6", &nlri.address);
    return TC_ACT_OK;
  }
  if (entry->nexthop_count == 0) {
    errorf(opts, "reached: No nexthops in FIB entry for %pI6", &nlri.address);
    return TC_ACT_OK;
  }

  // Choose a nexthop at random.
  __u32 nexthop_idx = bpf_get_prandom_u32() % entry->nexthop_count;
  if (nexthop_idx >= NEXTHOP_MAX_COUNT) {
    errorf(opts, "reached: Invalid nexthop index %u for %pI6", nexthop_idx, &nlri.address);
    return TC_ACT_OK;
  }
  struct in6_addr nexthop = entry->nexthops[nexthop_idx];
  tracef(opts, "Found nexthop %pI6 for address %pI6", &nexthop, &nlri.address);

  if (skb_encap_ip6_gre(skb, nexthop, l3_proto, l4_proto) < 0) {
    errorf(opts, "reached: Failed to encapsulate packet");
    // We may have modified the packet when attempting encap,
    // meaning it's not valid to continue sending through the
    // networking stack, so we drop it.
    return TC_ACT_SHOT;
  }

  return TC_ACT_OK;
}

SEC("xdp")
int erez_decap(struct xdp_md *ctx) {
  __u32 key = 0;
	struct opts *opts = bpf_map_lookup_elem(&e_decap_opts, &key);
	if (opts == NULL) {
	  return XDP_PASS;
	}

  void *head = (void*)(__u64)ctx->data;
  void *tail = (void*)(__u64)ctx->data_end;
  if (head + sizeof(struct ethhdr) + sizeof(struct ipv6hdr) + sizeof(struct gre_base_hdr) > tail)
     return XDP_PASS;

  struct ethhdr *eth = (struct ethhdr *)(head);
  __u16 l3_proto = bpf_ntohs(eth->h_proto);
  if (!valid_decap_l3_proto(l3_proto)) {
      warnf(opts, "reached: L3 protocol not supported: %u", l3_proto);
      return XDP_PASS;
  }
  struct ipv6hdr *ip6 = (struct ipv6hdr *)(head + sizeof(struct ethhdr));
  __u8 l4_proto = ip6->nexthdr;
  if (!valid_decap_l4_proto(l4_proto)) {
      warnf(opts, "reached: L4 protocol not supported: %u", l4_proto);
      return XDP_PASS;
  }
  struct gre_base_hdr *gre = (struct gre_base_hdr *)(head + sizeof(struct ethhdr) + sizeof(struct ipv6hdr));
  __u16 gre_proto = bpf_ntohs(gre->protocol);
  if (!valid_encap_l3_proto(gre_proto)) {
      warnf(opts, "reached: GRE protocol not supported: %u", gre_proto);
      return XDP_PASS;
  }

  // Extract nexthop we're supposed to forward to.
  struct in6_addr nexthop = ip6->daddr;

  // Always decap the header, so that if we aren't able
  // to process the packet at a later point, we let it
  // be handled normally by the kernel.
  __s64 ret = xdp_decap_ip6_gre(ctx, gre_proto);
  if (ret < 0) {
      // If the packet can't be decapsulated, it can't
      // be handled by the kernel, so we must drop it.
      errorf(opts, "reached: Failed to decapsulate packet");
      return XDP_DROP;
  }
  return xdp_forward_packet(opts, ctx, gre_proto, nexthop);
}

char LICENSE[] SEC("license") = "GPL v2";
