#ifndef __ROUTER_BPF_H__
#define __ROUTER_BPF_H__

#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

// vmlinux.h only includes BTF data, meaning, it
// won't contain define directives for certain
// constants, e.g. TC_ACT_OK, we need to define
// these manually.

// #include <linux/pkt_cls.h>
enum {
	TC_ACT_UNSPEC     = -1,
	TC_ACT_OK         = 0,
	TC_ACT_RECLASSIFY = 1,
	TC_ACT_SHOT       = 2,
	TC_ACT_PIPE       = 3,
	TC_ACT_STOLEN     = 4,
	TC_ACT_QUEUED     = 5,
	TC_ACT_REPEAT     = 6,
	TC_ACT_REDIRECT   = 7,
	TC_ACT_TRAP       = 8,
	TC_ACT_VALUE_MAX  = TC_ACT_TRAP,
};

// #include <linux/if_ether.h>
enum {
	ETH_P_IP   = 0x0800,
	ETH_P_IPV6 = 0x86DD,
};

// #include <linux/if_ether.h>
enum {
	ETH_ALEN = 6, // Octets in one Ethernet address.
};

// #include <linux/socket.h>
enum {
	AF_INET  = 2,
	AF_INET6 = 10,
};

// The current format version of log events shipped to the userspace.
#define LOG_EVENT_FORMAT_VERSION 1

// Maximum size of a log message in bytes. It must be kept in sync
// with the Rust const.
#define LOG_MESSAGE_MAX_SIZE 256

// Log levels that are exchanged between kernel and user space
// via an eBPF map. It must be kept in sync with the Rust enum.
enum log_level {
	TRACE = 1,
	DEBUG = 2,
	INFO  = 3,
	WARN  = 4,
	ERROR = 5,
};

// Log events that are exchanged between kernel and user space via
// an eBPF map. The size of an encoded message in bytes should be
// a multiple of 64. It must be kept in sync with the Rust struct.
struct __attribute__((__packed__)) log_event {
	u8 version;
	u8 level;
	u16 line;
	char message[LOG_MESSAGE_MAX_SIZE];
};

// Keep this in sync with the Rust structure.
struct opts {
	// Minimum log level for messages that are allowed to be sent to
	// userspace via the ring buffer.
	u8 log_level;
};

// How many nexthops may be configured per NLRI in the FIB. It must
// be kept in sync with the Rust const.
#define NEXTHOP_MAX_COUNT 4

// The combined size of the IPv6 and GRE headers
// that we prepend when encapsulating a packet.
#define ENCAP_LEN (sizeof(struct ipv6hdr) + sizeof(struct gre_base_hdr))
_Static_assert(ENCAP_LEN == 44, "ENCAP_LEN must be 44");
 
#endif
