use serde::{Deserialize, Serialize};
use std::fmt;
use std::net::Ipv4Addr;
use std::str::FromStr;

/// An IPv4 network such as `10.0.0.0/8`. The address is always stored masked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Ipv4Net {
    pub addr: Ipv4Addr,
    pub prefix: u8,
}

impl Ipv4Net {
    pub fn new(addr: Ipv4Addr, prefix: u8) -> Option<Self> {
        if prefix > 32 {
            return None;
        }
        Some(Ipv4Net {
            addr: Ipv4Addr::from(u32::from(addr) & mask(prefix)),
            prefix,
        })
    }

    pub fn host(addr: Ipv4Addr) -> Self {
        Ipv4Net { addr, prefix: 32 }
    }

    pub const DEFAULT: Ipv4Net = Ipv4Net {
        addr: Ipv4Addr::UNSPECIFIED,
        prefix: 0,
    };

    pub fn is_default(&self) -> bool {
        self.prefix == 0
    }

    pub fn contains(&self, ip: Ipv4Addr) -> bool {
        u32::from(ip) & mask(self.prefix) == u32::from(self.addr)
    }

    pub fn netmask(&self) -> Ipv4Addr {
        Ipv4Addr::from(mask(self.prefix))
    }
}

fn mask(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix as u32)
    }
}

impl fmt::Display for Ipv4Net {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.addr, self.prefix)
    }
}

impl FromStr for Ipv4Net {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (a, p) = match s.split_once('/') {
            Some((a, p)) => (
                a,
                p.parse::<u8>().map_err(|_| format!("bad prefix in {s}"))?,
            ),
            None => (s, 32),
        };
        let addr: Ipv4Addr = a.parse().map_err(|_| format!("bad address in {s}"))?;
        Ipv4Net::new(addr, p).ok_or_else(|| format!("prefix over 32 in {s}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_and_contains() {
        let n: Ipv4Net = "10.1.2.3/8".parse().unwrap();
        assert_eq!(n.to_string(), "10.0.0.0/8");
        assert!(n.contains("10.255.0.1".parse().unwrap()));
        assert!(!n.contains("11.0.0.1".parse().unwrap()));
        assert_eq!(n.netmask(), Ipv4Addr::new(255, 0, 0, 0));
        let d: Ipv4Net = "0.0.0.0/0".parse().unwrap();
        assert!(d.is_default() && d.contains(Ipv4Addr::new(8, 8, 8, 8)));
        let h: Ipv4Net = "1.2.3.4".parse().unwrap();
        assert_eq!(h.prefix, 32);
        assert!("1.2.3.4/33".parse::<Ipv4Net>().is_err());
        assert!("nope/8".parse::<Ipv4Net>().is_err());
    }
}
