use std::{
    ffi::c_void,
    mem::MaybeUninit,
    os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd},
    str::FromStr,
    time::Duration,
};

use libbpf_rs::{
    MapCore, MapFlags, MapHandle, PrintLevel, RingBufferBuilder, TC_EGRESS, TcHookBuilder, Xdp,
    XdpFlags,
    libbpf_sys::{self},
    skel::{OpenSkel, SkelBuilder},
};
use nix::errno::Errno;
use snafu::{OptionExt, ResultExt, Snafu};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, trace, warn};

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

/// Name of a mapping from NLRIs to nexthop
/// IDs sent through by the router.
const MAP_E_FIB: &str = "e_fib";
/// Name of a map holding erez_encap program
/// options.
const MAP_E_ENCAP_OPTS: &str = "e_encap_opts";
/// Name of a map holding erez_decap program
/// options.
const MAP_E_DECAP_OPTS: &str = "e_decap_opts";
/// Name of a mapping that is used for sending
/// logs from Erez eBPF programs to user space.
const MAP_E_LOGS: &str = "e_logs";

/// Name of the erez_encap eBPF program.
pub const PROG_EREZ_ENCAP: &str = "erez_encap";
/// Name of the erez_decap eBPF program.
pub const PROG_EREZ_DECAP: &str = "erez_decap";

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
        debug!("{message}");
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

#[derive(Debug, Copy, Clone)]
pub enum ProgramType {
    Xdp,
    Tc,
}

fn attach(prog: &str, iface: &Interface, log_level: &str) -> Result<COpts> {
    let skel_builder = ErezSkelBuilder::default();
    let mut open_object = MaybeUninit::uninit();
    let open_skel = skel_builder.open(&mut open_object).context(LibbpfSnafu {
        message: "Failed to open eBPF object",
    })?;
    let skel = open_skel.load().context(LibbpfSnafu {
        message: "Failed to load eBPF object",
    })?;

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
        }
        PROG_EREZ_DECAP => {
            // Attach the program to the network interface on ingress.
            let xdp = Xdp::new(skel.progs.erez_decap.as_fd());
            xdp.attach(iface.index.get(), XdpFlags::empty())
                .context(LibbpfSnafu {
                    message: format!("Failed to attach XDP program to interface {}", iface.name),
                })?;
        }
        _ => snafu::whatever!("Invalid program: {prog}"),
    }

    // Set program options.
    let log_level = CLogLevel::from_str(log_level)?;
    let opts = COpts { log_level };
    Ok(opts)
}

pub fn attach_erez_encap(iface: &Interface, log_level: &str) -> Result<()> {
    let opts = attach(PROG_EREZ_ENCAP, iface, log_level)?;
    let opts_bytes: [u8; COpts::SIZE] = (&opts).into();

    let maps = query_maps(iface, ProgramType::Tc)?;
    let map = find_map_handle(&maps, MAP_E_ENCAP_OPTS)?;
    map.update(&0u32.to_le_bytes(), &opts_bytes, MapFlags::empty())
        .whatever_context::<_, Error>("Failed to set erez_encap program options")?;
    Ok(())
}

pub fn attach_erez_decap(iface: &Interface, log_level: &str) -> Result<()> {
    let opts = attach(PROG_EREZ_DECAP, iface, log_level)?;
    let opts_bytes: [u8; COpts::SIZE] = (&opts).into();

    let maps = query_maps(iface, ProgramType::Xdp)?;
    let map = find_map_handle(&maps, MAP_E_DECAP_OPTS)?;
    map.update(&0u32.to_le_bytes(), &opts_bytes, MapFlags::empty())
        .whatever_context::<_, Error>("Failed to set erez_decap program options")?;
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

pub fn tail_erez_encap_logs(iface: &Interface, token: &CancellationToken) -> Result<()> {
    tail_logs(iface, ProgramType::Tc, PROG_EREZ_ENCAP, token)
}

pub fn tail_erez_decap_logs(iface: &Interface, token: &CancellationToken) -> Result<()> {
    tail_logs(iface, ProgramType::Xdp, PROG_EREZ_DECAP, token)
}

/// Consume log events from a libbpf_rs::RingBuffer that are produced
/// by Erez programs in the current network namespace.
fn tail_logs(
    iface: &Interface,
    prog_type: ProgramType,
    prog_name: &str,
    token: &CancellationToken,
) -> Result<()> {
    let maps = query_maps(iface, prog_type)?;
    let map = find_map_handle(&maps, MAP_E_LOGS)?;

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

fn query_prog_id(iface: &Interface, prog_type: ProgramType) -> Result<u32> {
    match prog_type {
        ProgramType::Tc => {
            // We can't use libbpf_rs::ProgInfoIter because it doesn't
            // return a valid interface index, so we can't filter on
            // the correct interface, instead we use a TC helper.
            let (hook, mut opts) = reconstruct_tc_hook(iface);
            let ret = unsafe { libbpf_sys::bpf_tc_query(&raw const hook, &raw mut opts) };
            if ret != 0 {
                return Err(Error::from_c_int_for_iface("bpf_tc_query", iface, ret));
            }
            Ok(opts.prog_id)
        }
        ProgramType::Xdp => {
            let flags = XdpFlags::empty().bits() as i32;
            let mut opts = libbpf_sys::bpf_xdp_query_opts {
                sz: size_of::<libbpf_sys::bpf_xdp_query_opts>() as libbpf_sys::size_t,
                ..libbpf_sys::bpf_xdp_query_opts::default()
            };
            let ret: i32 =
                unsafe { libbpf_sys::bpf_xdp_query(iface.index.get(), flags, &raw mut opts) };
            if ret != 0 {
                return Err(Error::from_c_int_for_iface("bpf_xdp_query", iface, ret));
            }
            Ok(opts.prog_id)
        }
    }
}

fn get_prog_fd(id: u32) -> Result<OwnedFd> {
    match libbpf_rs::Program::fd_from_id(id) {
        Ok(fd) => Ok(fd),
        Err(e) => Err(Error::Libbpf {
            message: format!("Failed to get an FD for program with ID {id}"),
            source: e,
        }),
    }
}

fn get_prog_map_ids(fd: BorrowedFd<'_>) -> Result<Vec<u32>> {
    // To query the map IDs, we need to know how many exist so
    // that we can resize our map ID vec to this amount.
    let mut item = libbpf_sys::bpf_prog_info::default();
    let item_ptr: *mut libbpf_sys::bpf_prog_info = &raw mut item;
    let mut len = size_of_val(&item) as u32;

    let ret = unsafe {
        libbpf_sys::bpf_obj_get_info_by_fd(fd.as_raw_fd(), item_ptr.cast::<c_void>(), &raw mut len)
    };
    if ret != 0 {
        return Err(Error::from_c_int("bpf_obj_get_info_by_id", ret));
    }

    // Now we perform the query again, this time, libbpf will take
    // care to fill in our vec with the map IDs associated with the
    // program. We take care to zero the rest of the fields so we
    // don't return info for data we don't care about.
    let mut map_ids: Vec<u32> = vec![0; item.nr_map_ids as usize];
    item.map_ids = map_ids.as_mut_ptr().cast::<c_void>() as u64;

    item.xlated_prog_len = 0;
    item.jited_prog_len = 0;
    item.nr_line_info = 0;
    item.nr_func_info = 0;
    item.nr_jited_line_info = 0;
    item.nr_jited_func_lens = 0;
    item.nr_prog_tags = 0;
    item.nr_jited_ksyms = 0;

    let ret = unsafe {
        libbpf_sys::bpf_obj_get_info_by_fd(fd.as_raw_fd(), item_ptr.cast::<c_void>(), &raw mut len)
    };
    if ret != 0 {
        return Err(Error::from_c_int("bpf_obj_get_info_by_id", ret));
    }

    Ok(map_ids)
}

pub fn query_maps(iface: &Interface, prog_type: ProgramType) -> Result<Vec<MapHandle>> {
    let prog_id = query_prog_id(iface, prog_type)?;
    let prog_fd = get_prog_fd(prog_id)?;
    let map_ids = get_prog_map_ids(prog_fd.as_fd())?;

    let mut handles = Vec::new();
    for id in map_ids {
        let handle = MapHandle::from_map_id(id).whatever_context::<_, Error>(format!(
            "Failed to create map handle from map ID {id}"
        ))?;
        handles.push(handle);
    }

    Ok(handles)
}

fn get_map_handle<'a>(maps: &'a [MapHandle], name: &str) -> Option<&'a MapHandle> {
    maps.iter().find(|m| m.name() == name)
}

fn find_map_handle<'a>(maps: &'a [MapHandle], name: &str) -> Result<&'a MapHandle> {
    get_map_handle(maps, name).with_whatever_context(|| format!("Map {name} not found"))
}

pub fn update_fib_entry(iface: &Interface, nlri: CNlri, fib_entry: CFibEntry) -> Result<()> {
    let maps = query_maps(iface, ProgramType::Tc)?;
    let map = find_map_handle(&maps, MAP_E_FIB)?;

    let nlri_bytes: [u8; CNlri::SIZE] = nlri.into();
    let fib_entry_bytes: [u8; CFibEntry::SIZE] = fib_entry.into();
    map.update(&nlri_bytes, &fib_entry_bytes, MapFlags::empty())
        .with_context(|_| LibbpfSnafu {
            message: "Failed to update e_fib",
        })
}

pub fn delete_fib_entry(iface: &Interface, nlri: CNlri) -> Result<()> {
    let maps = query_maps(iface, ProgramType::Tc)?;
    let map = find_map_handle(&maps, MAP_E_FIB)?;

    let nlri_bytes: [u8; CNlri::SIZE] = nlri.into();
    map.delete(&nlri_bytes).with_context(|_| LibbpfSnafu {
        message: "Failed to delete from e_fib",
    })
}
