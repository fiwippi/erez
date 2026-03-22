use std::{io, str::FromStr};

use snafu::Snafu;
use time::macros::format_description;
use tracing::level_filters::LevelFilter;
use tracing_subscriber::{
    filter::Targets, fmt::time::UtcTime, layer::SubscriberExt, util::SubscriberInitExt,
};

use crate::bpf;

#[derive(Debug, Snafu)]
#[non_exhaustive]
pub enum Error {
    #[snafu(display("Invalid log level: {level}"))]
    InvalidLevel { level: String },
}

pub type Result<T> = std::result::Result<T, Error>;

pub fn init(level: &str) -> Result<()> {
    let level = LevelFilter::from_str(level).map_err(|_| Error::InvalidLevel {
        level: level.to_owned(),
    })?;

    tracing_subscriber::registry()
        .with(
            Targets::new()
                .with_target("erezd", level)
                .with_default(LevelFilter::OFF),
        )
        .with(
            tracing_subscriber::fmt::layer()
                .compact()
                .with_writer(io::stderr)
                .with_timer(UtcTime::new(format_description!(
                    "[year]-[month]-[day] [hour]:[minute]:[second].[subsecond digits:3]"
                ))),
        )
        .init();

    bpf::set_libbpf_logger();

    Ok(())
}
