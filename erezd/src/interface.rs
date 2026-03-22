use std::num::NonZeroI32;

use network_interface::{NetworkInterface, NetworkInterfaceConfig};
use snafu::{OptionExt, ResultExt, Snafu};

#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum Error {
    #[snafu(display("Failed listing interfaces"))]
    ListInterfaces { source: network_interface::Error },
    #[snafu(display("Interface not found: {name}"))]
    InterfaceNotFound { name: String },
    #[snafu(display("Failed parsing interface index: {index}"))]
    ParseInterfaceIndex { index: u32 },
    #[snafu(display("Interface {name} has index zero"))]
    ZeroIndex { name: String },
}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Clone)]
pub struct Interface {
    pub name: String,
    pub index: NonZeroI32,
}

impl Interface {
    pub fn lookup(name: &str) -> Result<Self> {
        let ifaces = NetworkInterface::show().context(ListInterfacesSnafu)?;
        let iface = ifaces
            .into_iter()
            .find(|iface| iface.name == name)
            .context(InterfaceNotFoundSnafu {
                name: name.to_string(),
            })?;

        // We parse to i32 because the libbpf function calls we
        // execute require the index as this type, it's easier
        // to force this failure here so we don't have to deal
        // with it later.
        let index = i32::try_from(iface.index)
            .map_err(|_| Error::ParseInterfaceIndex { index: iface.index })?;
        let index = NonZeroI32::new(index).context(ZeroIndexSnafu {
            name: name.to_string(),
        })?;
        Ok(Interface {
            name: iface.name,
            index,
        })
    }
}
