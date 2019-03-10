#![feature(proc_macro_hygiene, decl_macro)]

#[cfg(test)]
#[macro_use]
extern crate rocket;
mod error;
mod header;

pub use error::HawkError;
pub use header::{AuthorizationHeader, ServerAuthorizationHeader};
