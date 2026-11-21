//! Runs Session Router under supervision: start it, restart it with back-off if it
//! crashes, stop after a crash loop, and always put routes and DNS back.

pub mod config;
pub mod guard;
pub mod policy;
pub mod process;
pub mod runner;
pub mod supervisor;
pub mod sweep;
#[cfg(windows)]
pub mod winsvc;
