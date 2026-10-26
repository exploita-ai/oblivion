use reqwest::dns::{Name, Resolve, Resolving};
use std::io;

pub(crate) struct NoDns;

impl Resolve for NoDns {
    fn resolve(&self, _name: Name) -> Resolving {
        Box::pin(async { Err(io::Error::other("local_dns_denied").into()) })
    }
}
