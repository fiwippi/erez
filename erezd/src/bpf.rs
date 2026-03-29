use std::{
    collections::HashMap, mem::MaybeUninit, os::fd::AsFd, path::Path, str::FromStr, sync::LazyLock,
    time::Duration,
};

use libbpf_rs::{
    MapCore, MapFlags, MapHandle, OpenObject, PrintLevel, RingBufferBuilder, TC_EGRESS,
    TcHookBuilder, Xdp, XdpFlags,
    libbpf_sys::{self},
    skel::{OpenSkel, SkelBuilder},
};
use nix::errno::Errno;
use snafu::{OptionExt, ResultExt, Snafu};
use tokio_util::sync::CancellationToken;
use tracing::{info, trace, warn};

#[rustfmt::skip]
mod erez_bpf {
    #![allow(warnings)]
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bpf/erez.skel.rs"));
}

use crate::{
    c_data::{self, CFibEntry, CLogEvent, CLogLevel, CNlri, COpts},
    interface::{self, Interface},
};
use erez_bpf::*;
use tokio::sync::mpsc::{error::TryRecvError, unbounded_channel};

/// eBPF TC handle number for Erez programs.
const TC_HANDLE: u32 = 1;
/// eBPF TC priority value for Erez programs.
const TC_PRIORITY: u32 = 1;

/// Name of the erez_encap eBPF program.
pub const PROG_EREZ_ENCAP: &str = "erez_encap";
/// Name of the erez_decap eBPF program.
pub const PROG_EREZ_DECAP: &str = "erez_decap";

/// Root path in the BPF filesystem where Erez maps are pinned.
pub const PIN_ROOT: &str = "/sys/fs/bpf/erez";
/// Pin path in the BPF filesystem for the e_fib map which maps
/// NLRIs to nexthop IDs sent through by the router.
pub static PIN_MAP_E_FIB: LazyLock<String> = LazyLock::new(|| format!("{PIN_ROOT}/e_fib"));

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("Not attached to: {iface}"))]
    NotAttached { iface: String },
    #[snafu(transparent)]
    CData {
        #[snafu(backtrace)]
        source: c_data::Error,
    },
    #[snafu(transparent)]
    Interface {
        #[snafu(backtrace)]
        source: interface::Error,
    },
    #[snafu(display("{message}"))]
    Libbpf {
        message: String,
        source: libbpf_rs::Error,
    },
    #[snafu(display("{message}: {inner:?}"))]
    Plain {
        message: String,
        inner: plain::Error,
    },
    #[snafu(whatever, display("{message}"))]
    Whatever {
        message: String,
        #[snafu(source(from(anyhow::Error, Some)))]
        source: Option<anyhow::Error>,
        backtrace: snafu::Backtrace,
    },
}

impl Error {
    fn from_c_int(op: &str, ret: i32) -> Self {
        let err = ret.abs();
        Error::Libbpf {
            message: op.into(),
            source: libbpf_rs::Error::from_raw_os_error(err),
        }
    }

    fn from_c_int_for_iface(op: &str, iface: &Interface, err: i32) -> Self {
        let err = err.abs();
        match Errno::from_raw(err) {
            // For TC/XDP:
            //   - If the parent qdisc doesn't exist => -EINVAL
            //   - If the parent exists but the hook
            //     is not found in the filter chain  => -ENOENT
            Errno::EINVAL | Errno::ENOENT => Error::NotAttached {
                iface: iface.name.to_string(),
            },
            _ => Error::from_c_int(op, err),
        }
    }
}

pub type Result<T> = core::result::Result<T, Error>;

pub fn set_libbpf_logger() {
    // We request the most detailed log level on the
    // eBPF side, and userspace is responsible for
    // not logging incorrect log levels.
    let _ = libbpf_rs::set_print(Some((PrintLevel::Debug, print_callback)));
}

/// Noise produced by libbpf when querying and attaching eBPF
/// programs/maps. These messages are logged at debug level.
const NOISY_LIBBPF_MESSAGES: [&str; 1] =
    // We often see this when trying to detach a TC program
    // that doesn't exist; once we move to TCX this shouldn't
    // happen anymore.
    ["libbpf: Kernel error message: Parent Qdisc doesn't exists"];

#[allow(clippy::needless_pass_by_value)]
fn print_callback(level: PrintLevel, message: String) {
    let message = message.trim();
    if NOISY_LIBBPF_MESSAGES.contains(&message) {
        trace!("{message}");
        return;
    }

    match level {
        // These are really verbose, even at debug
        // level so we're going to trace-log them.
        PrintLevel::Debug => trace!("{message}"),
        PrintLevel::Info => info!("{message}"),
        PrintLevel::Warn => warn!("{message}"),
    }
}

fn load_skel(open_object: &mut MaybeUninit<OpenObject>) -> Result<ErezSkel> {
    let skel_builder = ErezSkelBuilder::default();
    let open_skel = skel_builder.open(open_object).context(LibbpfSnafu {
        message: "Failed to open eBPF skeleton",
    })?;
    let skel = open_skel.load().context(LibbpfSnafu {
        message: "Failed to load eBPF skeleton",
    })?;
    Ok(skel)
}

fn attach(prog: &str, iface: &Interface, log_level: &str) -> Result<()> {
    // Initialise the skeleton.
    let mut open_object = MaybeUninit::uninit();
    let mut skel = load_skel(&mut open_object)?;

    // Compute program options.
    let log_level = CLogLevel::from_str(log_level)?;
    let opts = COpts { log_level };
    let opts_bytes: [u8; COpts::SIZE] = (&opts).into();

    // Attach programs.
    match prog {
        PROG_EREZ_ENCAP => {
            // Attach the program to the network interface on egress.
            let mut tc_builder = TcHookBuilder::new(skel.progs.erez_encap.as_fd());
            let mut egress_hook = tc_builder
                .ifindex(iface.index.get())
                .replace(true)
                .handle(TC_HANDLE)
                .priority(TC_PRIORITY)
                .hook(TC_EGRESS);
            egress_hook.create().context(LibbpfSnafu {
                message: format!("Failed to create TC hook for interface {}", iface.name),
            })?;
            egress_hook.attach().context(LibbpfSnafu {
                message: format!("Failed to attach TC hook to interface {}", iface.name),
            })?;
            skel.maps
                .e_encap_opts
                .update(&0u32.to_le_bytes(), &opts_bytes, MapFlags::empty())
                .whatever_context::<_, Error>("Failed to set erez_encap program options")?;

            // We need to ensure the root directory
            // exists before we pin to it.
            std::fs::create_dir_all(PIN_ROOT)
                .whatever_context::<_, Error>("Failed to create BPF_PIN_ROOT directory")?;
            if !Path::new(&*PIN_MAP_E_FIB).exists() {
                skel.maps
                    .e_fib
                    .pin(&*PIN_MAP_E_FIB)
                    .with_context(|_| LibbpfSnafu {
                        message: "Failed to pin e_fib map",
                    })?;
            }
        }
        PROG_EREZ_DECAP => {
            // Attach the program to the network interface on ingress.
            let xdp = Xdp::new(skel.progs.erez_decap.as_fd());
            xdp.attach(iface.index.get(), XdpFlags::empty())
                .context(LibbpfSnafu {
                    message: format!("Failed to attach XDP program to interface {}", iface.name),
                })?;
            skel.maps
                .e_decap_opts
                .update(&0u32.to_le_bytes(), &opts_bytes, MapFlags::empty())
                .whatever_context::<_, Error>("Failed to set erez_decap program options")?;
        }
        _ => snafu::whatever!("Invalid program: {prog}"),
    }

    Ok(())
}

pub fn attach_erez_encap(iface: &Interface, log_level: &str) -> Result<()> {
    attach(PROG_EREZ_ENCAP, iface, log_level)?;
    Ok(())
}

pub fn attach_erez_decap(iface: &Interface, log_level: &str) -> Result<()> {
    attach(PROG_EREZ_DECAP, iface, log_level)?;
    Ok(())
}

/// Recreates a TC hook using libbpf constructs, this is useful for
/// cases where we don't have prior access to a libbpf_rs::TcHook,
/// but we still want to perform some action on it, e.g. detaching
/// the eBPF program from a specific interface.
fn reconstruct_tc_hook(iface: &Interface) -> (libbpf_sys::bpf_tc_hook, libbpf_sys::bpf_tc_opts) {
    let hook = libbpf_sys::bpf_tc_hook {
        sz: size_of::<libbpf_sys::bpf_tc_hook>() as libbpf_sys::size_t,
        ifindex: iface.index.get(),
        attach_point: TC_EGRESS,
        ..libbpf_sys::bpf_tc_hook::default()
    };
    // If flags, prog_id, or prog_fd are non-zero, the kernel
    // errors (when detaching), so we don't specify them.
    let opts = libbpf_sys::bpf_tc_opts {
        sz: size_of::<libbpf_sys::bpf_tc_opts>() as libbpf_sys::size_t,
        handle: TC_HANDLE,
        priority: TC_PRIORITY,
        ..libbpf_sys::bpf_tc_opts::default()
    };

    (hook, opts)
}

pub fn detach(iface: &Interface) -> Result<()> {
    let tc_result = detach_tc(iface);
    let xdp_result = detach_xdp(iface);

    // We only process results after trying to detach,
    // so that failure to detach one program type
    // does not affect others.
    tc_result?;
    xdp_result?;

    Ok(())
}

fn detach_tc(iface: &Interface) -> Result<()> {
    let (tc_hook, tc_opts) = reconstruct_tc_hook(iface);
    let ret: i32 = unsafe { libbpf_sys::bpf_tc_detach(&raw const tc_hook, &raw const tc_opts) };
    if ret != 0 {
        match Error::from_c_int_for_iface("bpf_tc_detach", iface, ret) {
            Error::NotAttached { .. } => Ok(()),
            e => Err(e).whatever_context::<_, Error>(format!(
                "Failed to detach TC program from interface {}",
                iface.name
            )),
        }
    } else {
        Ok(())
    }
}

fn detach_xdp(iface: &Interface) -> Result<()> {
    let xdp_flags = XdpFlags::empty().bits();
    let xdp_attach_opts = libbpf_sys::bpf_xdp_attach_opts {
        sz: size_of::<libbpf_sys::bpf_xdp_attach_opts>() as libbpf_sys::size_t,
        ..libbpf_sys::bpf_xdp_attach_opts::default()
    };
    let ret: i32 = unsafe {
        libbpf_sys::bpf_xdp_detach(iface.index.get(), xdp_flags, &raw const xdp_attach_opts)
    };
    if ret != 0 {
        match Error::from_c_int_for_iface("bpf_xdp_detach", iface, ret) {
            Error::NotAttached { .. } => Ok(()),
            e => Err(e).whatever_context::<_, Error>(format!(
                "Failed to detach XDP program from interface {}",
                iface.name
            )),
        }
    } else {
        Ok(())
    }
}

pub fn tail_erez_encap_logs(token: &CancellationToken) -> Result<()> {
    tail_logs(PROG_EREZ_ENCAP, token)
}

pub fn tail_erez_decap_logs(token: &CancellationToken) -> Result<()> {
    tail_logs(PROG_EREZ_DECAP, token)
}

/// Consume log events from a libbpf_rs::RingBuffer that are produced
/// by Erez programs in the current network namespace.
fn tail_logs(prog_name: &str, token: &CancellationToken) -> Result<()> {
    // Initialise the skeleton.
    let mut open_object = MaybeUninit::uninit();
    let skel = load_skel(&mut open_object)?;
    let map = &skel.maps.e_logs;

    // This channel is used to funnel logs from the eBPF side.
    let (tx, mut rx) = unbounded_channel::<CLogEvent>();
    let callback = move |data: &[u8]| -> i32 {
        let event = CLogEvent::copy_from_bytes(data);
        if let Err(e) = tx.send(event) {
            warn!(error = %e , event = ?event, "Failed to send event to the channel");
        }
        0
    };

    // Create a RingBuffer instance that sends
    // eBPF logs to the channel created above.
    let mut rb_builder = RingBufferBuilder::new();
    rb_builder
        .add(map, callback)
        .whatever_context::<_, Error>("Failed to add map and callback to ring buffer builder")?;
    let logs = rb_builder
        .build()
        .whatever_context::<_, Error>("Failed to build ring buffer")?;

    // Receive logs from the channel in a loop.
    loop {
        if token.is_cancelled() {
            break;
        }
        match rx.try_recv() {
            Ok(event) => {
                event.log(prog_name);
                continue;
            }
            Err(TryRecvError::Empty) => (),
            Err(TryRecvError::Disconnected) => snafu::whatever!("The channel is disconnected"),
        }
        // Sleep and try consuming again.
        logs.poll(Duration::from_millis(100))
            .whatever_context::<_, Error>("Failed to poll ring buffer")?;
    }

    // Drain remaining log events. This is safe because eBPF programs
    // are detached before the token is cancelled, so no new events
    // will arrive in the ring buffer.
    while let Ok(event) = rx.try_recv() {
        event.log(prog_name);
    }

    Ok(())
}

pub type FibState = HashMap<CNlri, CFibEntry>;

pub struct Fib(MapHandle);

impl Fib {
    pub fn open() -> Result<Fib> {
        MapHandle::from_pinned_path(&*PIN_MAP_E_FIB)
            .map(Fib)
            .with_context(|_| LibbpfSnafu {
                message: "Failed to open pinned e_fib map",
            })
    }

    pub fn reconcile(&self, desired: FibState) -> Result<()> {
        let actual = self.read()?;
        for (nlri, entry) in &desired {
            if actual.get(nlri) != Some(entry) {
                self.insert(*nlri, entry.clone())?;
            }
        }
        for nlri in actual.keys() {
            if !desired.contains_key(nlri) {
                self.delete(*nlri)?;
            }
        }
        Ok(())
    }

    fn read(&self) -> Result<FibState> {
        self.0
            .keys()
            .map(|key_bytes| {
                let nlri = plain::from_bytes::<CNlri>(&key_bytes).map_err(|e| Error::Plain {
                    message: "Failed to deserialise CNlri".into(),
                    inner: e,
                })?;
                let value_bytes = self
                    .0
                    .lookup(&key_bytes, MapFlags::empty())
                    .with_context(|_| LibbpfSnafu {
                        message: "Failed to lookup e_fib entry",
                    })?
                    .whatever_context::<_, Error>("Failed to find e_fib entry")?;
                let fib_entry =
                    plain::from_bytes::<CFibEntry>(&value_bytes).map_err(|e| Error::Plain {
                        message: "Failed to deserialise CFibEntry".into(),
                        inner: e,
                    })?;
                Ok((*nlri, fib_entry.clone()))
            })
            .collect()
    }

    fn insert(&self, nlri: CNlri, fib_entry: CFibEntry) -> Result<()> {
        let nlri_bytes: [u8; CNlri::SIZE] = nlri.into();
        let fib_entry_bytes: [u8; CFibEntry::SIZE] = fib_entry.into();
        self.0
            .update(&nlri_bytes, &fib_entry_bytes, MapFlags::empty())
            .context(LibbpfSnafu {
                message: "Failed to update e_fib",
            })
    }

    fn delete(&self, nlri: CNlri) -> Result<()> {
        let nlri_bytes: [u8; CNlri::SIZE] = nlri.into();
        self.0.delete(&nlri_bytes).context(LibbpfSnafu {
            message: "Failed to delete from e_fib",
        })
    }
}
