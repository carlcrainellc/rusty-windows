//! In-memory route table and DNS settings, for tests and dry runs.

use crate::{DnsSettings, Ipv6Bindings, Route, RouteTable};
use std::collections::BTreeMap;
use std::io;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone, Default, PartialEq)]
pub struct MemRoutes {
    pub table: Vec<Route>,
    /// Makes every add fail, to test error paths.
    pub refuse_adds: bool,
    /// Interface metrics; interfaces not listed have 0.
    pub if_metrics: BTreeMap<u32, u32>,
    /// Interfaces that are tunnel adapters.
    pub tunnels: Vec<u32>,
    /// Adapter names to interface indexes.
    pub names: BTreeMap<String, u32>,
}

impl MemRoutes {
    pub fn with(table: Vec<Route>) -> Self {
        MemRoutes {
            table,
            ..Default::default()
        }
    }
}

impl RouteTable for MemRoutes {
    fn routes(&self) -> io::Result<Vec<Route>> {
        Ok(self.table.clone())
    }
    fn add(&mut self, r: &Route) -> io::Result<()> {
        if self.refuse_adds {
            return Err(io::Error::new(io::ErrorKind::PermissionDenied, "refused"));
        }
        if self
            .table
            .iter()
            .any(|x| x.dest == r.dest && x.next_hop == r.next_hop && x.if_index == r.if_index)
        {
            return Err(io::Error::new(io::ErrorKind::AlreadyExists, "route exists"));
        }
        self.table.push(r.clone());
        Ok(())
    }
    fn delete(&mut self, r: &Route) -> io::Result<()> {
        self.table.retain(|x| {
            !(x.dest == r.dest && x.next_hop == r.next_hop && x.if_index == r.if_index)
        });
        Ok(())
    }
    fn interface_metric(&self, if_index: u32) -> io::Result<u32> {
        Ok(self.if_metrics.get(&if_index).copied().unwrap_or(0))
    }
    fn is_tunnel(&self, if_index: u32) -> bool {
        self.tunnels.contains(&if_index)
    }
    fn index_of(&self, name: &str) -> io::Result<Option<u32>> {
        Ok(self.names.get(name).copied())
    }
    fn name_of(&self, if_index: u32) -> Option<String> {
        self.names
            .iter()
            .find(|(_, &i)| i == if_index)
            .map(|(n, _)| n.clone())
    }
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct MemDns {
    pub by_if: BTreeMap<u32, Vec<IpAddr>>,
}

impl MemDns {
    pub fn add_interface(&mut self, if_index: u32, servers: Vec<IpAddr>) {
        self.by_if.insert(if_index, servers);
    }

    pub fn remove_interface(&mut self, if_index: u32) {
        self.by_if.remove(&if_index);
    }
}

impl DnsSettings for MemDns {
    fn servers(&self, if_index: u32) -> io::Result<Vec<IpAddr>> {
        self.by_if
            .get(&if_index)
            .cloned()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no such interface"))
    }
    fn set_servers(&mut self, if_index: u32, servers: &[IpAddr]) -> io::Result<()> {
        match self.by_if.get_mut(&if_index) {
            Some(v) => {
                *v = servers.to_vec();
                Ok(())
            }
            None => Err(io::Error::new(io::ErrorKind::NotFound, "no such interface")),
        }
    }
}

/// Shared so a test can flip adapters while a guard holds its own handle.
#[derive(Debug, Clone, Default)]
pub struct MemIpv6(Arc<Mutex<BTreeMap<String, bool>>>);

impl MemIpv6 {
    pub fn with(adapters: &[(&str, bool)]) -> Self {
        MemIpv6(Arc::new(Mutex::new(
            adapters
                .iter()
                .map(|(n, on)| (n.to_string(), *on))
                .collect(),
        )))
    }
    pub fn set(&self, adapter: &str, on: bool) {
        self.0.lock().unwrap().insert(adapter.to_string(), on);
    }
    /// The adapter is unplugged or renamed.
    pub fn remove(&self, adapter: &str) {
        self.0.lock().unwrap().remove(adapter);
    }
    pub fn is_on(&self, adapter: &str) -> bool {
        self.0
            .lock()
            .unwrap()
            .get(adapter)
            .copied()
            .unwrap_or(false)
    }
}

impl Ipv6Bindings for MemIpv6 {
    fn enabled(&self) -> io::Result<Vec<String>> {
        Ok(self
            .0
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, on)| **on)
            .map(|(n, _)| n.clone())
            .collect())
    }
    fn enable(&mut self, adapter: &str) -> io::Result<()> {
        match self.0.lock().unwrap().get_mut(adapter) {
            Some(on) => {
                *on = true;
                Ok(())
            }
            None => Err(io::Error::new(io::ErrorKind::NotFound, "no such adapter")),
        }
    }
}
