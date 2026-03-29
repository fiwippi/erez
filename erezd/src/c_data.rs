use std::{mem, net::IpAddr, str::FromStr};

use ipnet::IpNet;
use plain::Plain;
use snafu::Snafu;
use tracing::{debug, error, info, trace, warn};

use crate::bgp::Nexthop;

#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum Error {
    #[snafu(display("Invalid log level: {level}"))]
    InvalidLevel { level: String },
}

/// The current format version of log events shipped to the userspace.
const LOG_EVENT_FORMAT_VERSION: u8 = 1;

/// Log levels that are exchanged between kernel and user space
/// via an eBPF map. It must be kept in sync with the C enum.
#[repr(u8)]
#[derive(Debug, Clone, Copy)]
pub enum CLogLevel {
    Trace = 1,
    Debug = 2,
    Info = 3,
    Warn = 4,
    Error = 5,
}

impl FromStr for CLogLevel {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "TRACE" => Ok(CLogLevel::Trace),
            "DEBUG" => Ok(CLogLevel::Debug),
            "INFO" => Ok(CLogLevel::Info),
            "WARN" => Ok(CLogLevel::Warn),
            "ERROR" => Ok(CLogLevel::Error),
            _ => InvalidLevelSnafu { level: s }.fail(),
        }
    }
}

impl From<u8> for CLogLevel {
    fn from(value: u8) -> Self {
        match value {
            x if x == CLogLevel::Trace as u8 => CLogLevel::Trace,
            x if x == CLogLevel::Debug as u8 => CLogLevel::Debug,
            x if x == CLogLevel::Info as u8 => CLogLevel::Info,
            x if x == CLogLevel::Warn as u8 => CLogLevel::Warn,
            x if x == CLogLevel::Error as u8 => CLogLevel::Error,
            _ => CLogLevel::Error,
        }
    }
}

/// Maximum size of a log message in bytes. It
/// must be kept in sync with the C const.
const LOG_MESSAGE_MAX_SIZE: usize = 256;

/// Log events that are exchanged between kernel and user space via
/// an eBPF map. The size of encoded messages in bytes should be a
/// multiple of 64. It must be kept in sync with the C structure.
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct CLogEvent {
    /// Log event format version.
    version: u8,
    /// Encoded log level.
    level: u8,
    /// Line number the log message was produced on.
    line: u16,
    /// Message string as a byte array.
    message: [u8; LOG_MESSAGE_MAX_SIZE],
}

impl CLogEvent {
    /// Decode an event from bytes.
    pub fn copy_from_bytes(bytes: &[u8]) -> Self {
        let mut e = Self::default();
        e.copy_from_bytes(bytes)
            .expect("not enough bytes to deserialize a log event");
        e
    }

    /// Log the event message with the decoded level.
    pub fn log(&self, program: &str) {
        if self.version != LOG_EVENT_FORMAT_VERSION {
            error!(version = self.version, "Unexpected eBPF log event version");
            return;
        }

        let line = self.line;
        let message_len = self
            .message
            .iter()
            .position(|&c| c == b'\0')
            .unwrap_or(self.message.len());
        let message = String::from_utf8_lossy(&self.message[..message_len]);
        let location = format!("erez.bpf.c:{line}");

        match CLogLevel::from(self.level) {
            CLogLevel::Trace => trace!(program, location, %message),
            CLogLevel::Debug => debug!(program, location, %message),
            CLogLevel::Info => info!(program, location, %message),
            CLogLevel::Warn => warn!(program, location, %message),
            CLogLevel::Error => error!(program, location, %message),
        }
    }
}

impl Default for CLogEvent {
    fn default() -> Self {
        Self {
            version: u8::default(),
            level: u8::default(),
            line: u16::default(),
            message: [0; LOG_MESSAGE_MAX_SIZE],
        }
    }
}

unsafe impl Plain for CLogEvent {}

// Keep this in sync with its C counterpart.
#[repr(C)]
pub struct COpts {
    /// Minimum log level for messages that are allowed
    /// to be sent to userspace via the ring buffer.
    pub log_level: CLogLevel,
}

impl COpts {
    /// Size in bytes of an encoded COpts instance.
    pub const SIZE: usize = mem::size_of::<COpts>();
}

impl From<&COpts> for [u8; COpts::SIZE] {
    /// Encode an COpts instance to bytes.
    fn from(value: &COpts) -> Self {
        unsafe { mem::transmute_copy(value) }
    }
}

unsafe impl Plain for COpts {}

/// Size of IPv6 address in bytes.
const IPV6_ADDR_SIZE: usize = 16;

#[repr(C)]
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct CIpv6Addr {
    octets: [u8; IPV6_ADDR_SIZE],
}

impl CIpv6Addr {
    pub const SIZE: usize = mem::size_of::<CIpv6Addr>();

    pub const UNSPECIFIED: Self = CIpv6Addr {
        octets: [0; IPV6_ADDR_SIZE],
    };

    pub fn new(addr: IpAddr) -> CIpv6Addr {
        match addr {
            IpAddr::V4(addr) => {
                // https://datatracker.ietf.org/doc/html/rfc4291#section-2.5.5.2
                // |                80 bits               | 16 |      32 bits        |
                // +--------------------------------------+--------------------------+
                // |0000..............................0000|FFFF|    IPv4 address     |
                // +--------------------------------------+----+---------------------+
                let mut v6 = [0; IPV6_ADDR_SIZE];
                v6[10] = 0xFF;
                v6[11] = 0xFF;
                v6[12..].copy_from_slice(&addr.octets());
                Self { octets: v6 }
            }
            IpAddr::V6(addr) => Self {
                octets: addr.octets(),
            },
        }
    }
}

impl From<CIpv6Addr> for [u8; CIpv6Addr::SIZE] {
    fn from(value: CIpv6Addr) -> [u8; CIpv6Addr::SIZE] {
        unsafe { mem::transmute_copy(&value) }
    }
}

unsafe impl Plain for CIpv6Addr {}

// Keep this in sync with its C counterpart.
#[repr(C)]
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct CNlri {
    prefix_len: u32,
    address: CIpv6Addr,
}

impl CNlri {
    pub const SIZE: usize = mem::size_of::<CNlri>();

    pub fn new(addr: IpAddr, prefix_len: u32) -> Self {
        let address = CIpv6Addr::new(addr);
        let prefix_len = match addr {
            IpAddr::V4(_) => prefix_len + 96,
            IpAddr::V6(_) => prefix_len,
        };
        Self {
            prefix_len,
            address,
        }
    }
}

impl From<IpNet> for CNlri {
    fn from(prefix: IpNet) -> Self {
        CNlri::new(prefix.addr(), prefix.prefix_len() as u32)
    }
}

impl From<CNlri> for [u8; CNlri::SIZE] {
    fn from(value: CNlri) -> [u8; CNlri::SIZE] {
        unsafe { mem::transmute_copy(&value) }
    }
}

unsafe impl Plain for CNlri {}

// How many nexthops may be configured per NLRI in the FIB. It must
// be kept in sync with the C const.
const NEXTHOP_MAX_COUNT: usize = 4;

// Keep this in sync with its C counterpart.
#[repr(C)]
#[derive(Clone, Eq, Hash, PartialEq)]
pub struct CFibEntry {
    nexthop_count: u8,
    nexthops: [CIpv6Addr; NEXTHOP_MAX_COUNT],
}

impl CFibEntry {
    pub const SIZE: usize = mem::size_of::<CFibEntry>();

    pub fn new(nexthops: &[&Nexthop]) -> Self {
        // Currently a FIB entry only accepts at most four nexthops;
        // it doesn't really matter which nexthops we provide until
        // we start sorting them for loadbalancing purposes.
        //
        // We will want to log/emit a metric to understand how often
        // this might be happening!
        let nexthop_count = nexthops.len().min(NEXTHOP_MAX_COUNT);
        let nexthops = {
            let mut array: [CIpv6Addr; NEXTHOP_MAX_COUNT] =
                [CIpv6Addr::UNSPECIFIED; NEXTHOP_MAX_COUNT];
            for i in 0..nexthop_count {
                array[i] = CIpv6Addr::new(*nexthops[i]);
            }
            array
        };

        Self {
            nexthop_count: nexthop_count as u8,
            nexthops,
        }
    }
}

impl From<CFibEntry> for [u8; CFibEntry::SIZE] {
    fn from(value: CFibEntry) -> [u8; CFibEntry::SIZE] {
        unsafe { mem::transmute_copy(&value) }
    }
}

unsafe impl Plain for CFibEntry {}
