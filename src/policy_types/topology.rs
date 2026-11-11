use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::policy::v1;
use crate::policy_types::attr_exp::AttrExp;
use crate::policy_types::error::PolicyTypeError;
use crate::write_to::WriteTo;

/// Shadows the cap'n proto `Peering` struct.
#[derive(Debug, PartialEq)]
pub struct Peering {
    pub link_id: String,
    pub node_a: IpAddr, // by convention we are using ZPR address
    /// Substrate address of node A. `None` means policy gives none: the node
    /// reports its own when it authenticates (policy.capnp `Peering`).
    pub substrate_a: Option<NetAddr>,
    pub node_b: IpAddr, // by convention we are using ZPR address
    /// Substrate address of node B; `None` as for `substrate_a`.
    pub substrate_b: Option<NetAddr>,
    pub attributes: Vec<AttrExp>,
}

/// Either a host name or an IP address.
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub enum NetworkHost {
    Ip(IpAddr),
    Hostname(String),
}

/// Maps to a Cap'n Proto `NetAddr`
#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct NetAddr {
    pub host: NetworkHost,
    pub port: u16,
}

impl NetAddr {
    /// If the passed `ip_or_host` parses as a valid IP address, it is treated as an IP.
    /// Otherwise, it is treated as a hostname.
    pub fn new_for_ip_or_host(ip_or_host: &str, port: u16) -> Self {
        if let Ok(ip) = ip_or_host.parse::<IpAddr>() {
            NetAddr {
                host: NetworkHost::Ip(ip),
                port,
            }
        } else {
            NetAddr {
                host: NetworkHost::Hostname(ip_or_host.to_string()),
                port,
            }
        }
    }
}

impl fmt::Display for NetworkHost {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NetworkHost::Ip(ip) => write!(f, "{}", ip),
            NetworkHost::Hostname(hostname) => write!(f, "{}", hostname),
        }
    }
}

impl TryFrom<v1::net_addr::Reader<'_>> for NetAddr {
    type Error = PolicyTypeError;

    fn try_from(reader: v1::net_addr::Reader<'_>) -> Result<Self, Self::Error> {
        let port = reader.get_port();
        match reader.which()? {
            v1::net_addr::IpAddr(ip) => {
                let ip = ip?;
                if ip.len() == 4 {
                    let octets: [u8; 4] = ip.try_into().expect("IP length checked above");
                    let ipv4_addr = Ipv4Addr::from(octets);
                    return Ok(NetAddr {
                        host: NetworkHost::Ip(IpAddr::V4(ipv4_addr)),
                        port,
                    });
                } else if ip.len() == 16 {
                    let octets: [u8; 16] = ip.try_into().expect("IP length checked above");
                    let ipv6_addr = Ipv6Addr::from(octets);
                    return Ok(NetAddr {
                        host: NetworkHost::Ip(IpAddr::V6(ipv6_addr)),
                        port,
                    });
                } else {
                    return Err(PolicyTypeError::DeserializationError("Invalid IP length"));
                }
            }
            v1::net_addr::Hostname(hostname) => {
                let hostname_str = hostname?.to_string()?;
                Ok(NetAddr {
                    host: NetworkHost::Hostname(hostname_str),
                    port,
                })
            }
        }
    }
}

impl TryFrom<v1::peering::Reader<'_>> for Peering {
    type Error = PolicyTypeError;

    fn try_from(reader: v1::peering::Reader<'_>) -> Result<Self, Self::Error> {
        let link_id = reader.get_link_id()?.to_string()?;

        // NOTE: In Capn Proto the node identifiers are strings. For time being we are using the
        // node ZPR address.
        let node_a: IpAddr = reader.get_node_a()?.to_string()?.parse()?;
        // An unset NetAddr would otherwise read as hostname "" port 0, so check
        // has_*() first: unset means the node reports its own substrate address.
        let substrate_a = if reader.has_node_a_substrate() {
            Some(reader.get_node_a_substrate()?.try_into()?)
        } else {
            None
        };

        let node_b: IpAddr = reader.get_node_b()?.to_string()?.parse()?;
        let substrate_b = if reader.has_node_b_substrate() {
            Some(reader.get_node_b_substrate()?.try_into()?)
        } else {
            None
        };

        let mut attributes = Vec::new();
        for attr in reader.get_attrs()?.iter() {
            attributes.push(attr.try_into()?);
        }

        Ok(Self {
            link_id,
            node_a,
            substrate_a,
            node_b,
            substrate_b,
            attributes,
        })
    }
}

/// Writes into a freshly initialised builder, like every `WriteTo` in this crate
/// (`init_root`, or an element of a freshly `init_*`ed list). A `None` substrate
/// is written by not touching the field, which leaves it unset only on a fresh
/// builder: the generated capnp builder has no call that clears a struct field.
impl WriteTo<v1::peering::Builder<'_>> for Peering {
    fn write_to(&self, bldr: &mut v1::peering::Builder) {
        bldr.set_link_id(&self.link_id);
        bldr.set_node_a(&self.node_a.to_string());
        // None leaves the field unset on the wire (see the Peering doc comment).
        if let Some(a) = &self.substrate_a {
            a.write_to(&mut bldr.reborrow().init_node_a_substrate());
        }
        bldr.set_node_b(&self.node_b.to_string());
        if let Some(b) = &self.substrate_b {
            b.write_to(&mut bldr.reborrow().init_node_b_substrate());
        }

        let mut attr_list = bldr.reborrow().init_attrs(self.attributes.len() as u32);
        for (i, attr) in self.attributes.iter().enumerate() {
            attr.write_to(&mut attr_list.reborrow().get(i as u32));
        }
    }
}

impl WriteTo<v1::net_addr::Builder<'_>> for NetAddr {
    fn write_to(&self, bldr: &mut v1::net_addr::Builder) {
        bldr.set_port(self.port);
        match &self.host {
            NetworkHost::Ip(ip) => {
                let ip_bytes = match ip {
                    IpAddr::V4(ipv4) => ipv4.octets().to_vec(),
                    IpAddr::V6(ipv6) => ipv6.octets().to_vec(),
                };
                bldr.set_ip_addr(&ip_bytes);
            }
            NetworkHost::Hostname(hostname) => {
                bldr.set_hostname(hostname);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::v1;
    use crate::policy_types::attr_exp::{AttrExp, AttrOp};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    fn make_net_addr_ip(
        ip_bytes: &[u8],
        port: u16,
    ) -> capnp::message::Builder<capnp::message::HeapAllocator> {
        let mut msg = capnp::message::Builder::new_default();
        {
            let mut root: v1::net_addr::Builder<'_> = msg.init_root();
            root.set_ip_addr(ip_bytes);
            root.set_port(port);
        }
        msg
    }

    fn make_net_addr_hostname(
        hostname: &str,
        port: u16,
    ) -> capnp::message::Builder<capnp::message::HeapAllocator> {
        let mut msg = capnp::message::Builder::new_default();
        {
            let mut root: v1::net_addr::Builder<'_> = msg.init_root();
            root.set_hostname(hostname);
            root.set_port(port);
        }
        msg
    }

    fn read_substrate(
        msg: &capnp::message::Builder<capnp::message::HeapAllocator>,
    ) -> Result<NetAddr, PolicyTypeError> {
        let reader: v1::net_addr::Reader<'_> = msg.get_root_as_reader().unwrap();
        NetAddr::try_from(reader)
    }

    // --- NetAddr deserialization ---

    #[test]
    fn test_substrate_ipv4() {
        // IPv4 address (4 bytes) deserializes to the correct IpAddr::V4
        let msg = make_net_addr_ip(&[192, 168, 1, 1], 8080);
        let addr = read_substrate(&msg).unwrap();
        assert_eq!(
            addr.host,
            NetworkHost::Ip(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)))
        );
        assert_eq!(addr.port, 8080);
    }

    #[test]
    fn test_substrate_ipv6() {
        // IPv6 address (16 bytes) deserializes to the correct IpAddr::V6
        let bytes = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1u8];
        let msg = make_net_addr_ip(&bytes, 9000);
        let addr = read_substrate(&msg).unwrap();
        assert_eq!(
            addr.host,
            NetworkHost::Ip(IpAddr::V6(Ipv6Addr::from(bytes)))
        );
        assert_eq!(addr.port, 9000);
    }

    #[test]
    fn test_substrate_hostname() {
        // Hostname variant deserializes correctly with port
        let msg = make_net_addr_hostname("node.example.com", 443);
        let addr = read_substrate(&msg).unwrap();
        assert_eq!(
            addr.host,
            NetworkHost::Hostname("node.example.com".to_string())
        );
        assert_eq!(addr.port, 443);
    }

    #[test]
    fn test_substrate_invalid_ip_3_bytes() {
        // IP data with 3 bytes (neither 4 nor 16) returns an error
        let msg = make_net_addr_ip(&[1, 2, 3], 80);
        assert!(read_substrate(&msg).is_err());
    }

    #[test]
    fn test_substrate_invalid_ip_5_bytes() {
        // IP data with 5 bytes returns an error
        let msg = make_net_addr_ip(&[1, 2, 3, 4, 5], 80);
        assert!(read_substrate(&msg).is_err());
    }

    #[test]
    fn test_substrate_invalid_ip_empty() {
        // Empty IP data returns an error
        let msg = make_net_addr_ip(&[], 80);
        assert!(read_substrate(&msg).is_err());
    }

    // --- NetAddr roundtrip (WriteTo + TryFrom) ---

    #[test]
    fn test_substrate_roundtrip_ipv4() {
        // write_to then TryFrom preserves an IPv4 NetAddr
        let original = NetAddr {
            host: NetworkHost::Ip(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))),
            port: 7000,
        };
        let mut msg = capnp::message::Builder::new_default();
        {
            let mut root: v1::net_addr::Builder<'_> = msg.init_root();
            original.write_to(&mut root);
        }
        let reader: v1::net_addr::Reader<'_> = msg.get_root_as_reader().unwrap();
        let result = NetAddr::try_from(reader).unwrap();
        assert_eq!(result, original);
    }

    #[test]
    fn test_substrate_roundtrip_ipv6() {
        // write_to then TryFrom preserves an IPv6 NetAddr
        let bytes = [0u8; 16]; // ::0
        let original = NetAddr {
            host: NetworkHost::Ip(IpAddr::V6(Ipv6Addr::from(bytes))),
            port: 6000,
        };
        let mut msg = capnp::message::Builder::new_default();
        {
            let mut root: v1::net_addr::Builder<'_> = msg.init_root();
            original.write_to(&mut root);
        }
        let reader: v1::net_addr::Reader<'_> = msg.get_root_as_reader().unwrap();
        let result = NetAddr::try_from(reader).unwrap();
        assert_eq!(result, original);
    }

    #[test]
    fn test_substrate_roundtrip_hostname() {
        // write_to then TryFrom preserves a hostname NetAddr
        let original = NetAddr {
            host: NetworkHost::Hostname("gw.internal".to_string()),
            port: 1234,
        };
        let mut msg = capnp::message::Builder::new_default();
        {
            let mut root: v1::net_addr::Builder<'_> = msg.init_root();
            original.write_to(&mut root);
        }
        let reader: v1::net_addr::Reader<'_> = msg.get_root_as_reader().unwrap();
        let result = NetAddr::try_from(reader).unwrap();
        assert_eq!(result, original);
    }

    // --- Peering roundtrip (WriteTo + TryFrom) ---

    #[test]
    fn test_peering_roundtrip_no_attrs() {
        // Peering with no link attributes roundtrips correctly
        let original = Peering {
            link_id: "link-001".to_string(),
            node_a: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            substrate_a: Some(NetAddr {
                host: NetworkHost::Ip(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))),
                port: 5000,
            }),
            node_b: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            substrate_b: Some(NetAddr {
                host: NetworkHost::Hostname("host-b.net".to_string()),
                port: 5001,
            }),
            attributes: vec![],
        };
        let mut msg = capnp::message::Builder::new_default();
        {
            let mut root: v1::peering::Builder<'_> = msg.init_root();
            original.write_to(&mut root);
        }
        let reader: v1::peering::Reader<'_> = msg.get_root_as_reader().unwrap();
        let result = Peering::try_from(reader).unwrap();
        assert_eq!(result.link_id, "link-001");
        assert_eq!(result.node_a, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(result.node_b, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)));
        assert!(result.attributes.is_empty());
        assert_eq!(result, original);
    }

    #[test]
    fn test_peering_roundtrip_with_attrs() {
        // Peering with link attributes roundtrips correctly including attr fields
        let original = Peering {
            link_id: "link-002".to_string(),
            node_a: IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1)),
            substrate_a: Some(NetAddr {
                host: NetworkHost::Ip(IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1))),
                port: 4000,
            }),
            node_b: IpAddr::V4(Ipv4Addr::new(10, 0, 1, 2)),
            substrate_b: Some(NetAddr {
                host: NetworkHost::Ip(IpAddr::V4(Ipv4Addr::new(172, 16, 0, 2))),
                port: 4001,
            }),
            attributes: vec![AttrExp {
                key: "link.class".to_string(),
                op: AttrOp::Eq,
                value: vec!["trusted".to_string()],
            }],
        };
        let mut msg = capnp::message::Builder::new_default();
        {
            let mut root: v1::peering::Builder<'_> = msg.init_root();
            original.write_to(&mut root);
        }
        let reader: v1::peering::Reader<'_> = msg.get_root_as_reader().unwrap();
        let result = Peering::try_from(reader).unwrap();
        assert_eq!(result.link_id, "link-002");
        assert_eq!(result.attributes.len(), 1);
        assert_eq!(result.attributes[0].key, "link.class");
        assert_eq!(result.attributes[0].op, AttrOp::Eq);
        assert_eq!(result.attributes[0].value, vec!["trusted"]);
    }

    // --- Peering with no substrate address (policy.capnp: unset = node reports its own) ---

    /// Builds a Peering message that sets each substrate field only when given.
    fn make_peering_msg(
        substrate_a: Option<&NetAddr>,
        substrate_b: Option<&NetAddr>,
    ) -> capnp::message::Builder<capnp::message::HeapAllocator> {
        let mut msg = capnp::message::Builder::new_default();
        {
            let mut root: v1::peering::Builder<'_> = msg.init_root();
            root.set_link_id("link-zodes");
            root.set_node_a("fd5a:5052::1");
            root.set_node_b("fd5a:5052::2");
            if let Some(a) = substrate_a {
                a.write_to(&mut root.reborrow().init_node_a_substrate());
            }
            if let Some(b) = substrate_b {
                b.write_to(&mut root.reborrow().init_node_b_substrate());
            }
        }
        msg
    }

    fn relay_substrate() -> NetAddr {
        NetAddr {
            host: NetworkHost::Ip(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10))),
            port: 5000,
        }
    }

    // Both ends unset (a direct link between two endpoint Zodes) decodes to None/None.
    // Before this change it decoded "successfully" to Hostname("") port 0.
    #[test]
    fn test_peering_both_substrates_unset_decode_to_none() {
        let msg = make_peering_msg(None, None);
        let reader: v1::peering::Reader<'_> = msg.get_root_as_reader().unwrap();
        let p = Peering::try_from(reader).unwrap();
        assert_eq!(p.substrate_a, None);
        assert_eq!(p.substrate_b, None);
    }

    // One end set (the relay), one unset (an endpoint): each decodes on its own.
    #[test]
    fn test_peering_one_substrate_unset() {
        let relay = relay_substrate();
        let msg = make_peering_msg(Some(&relay), None);
        let reader: v1::peering::Reader<'_> = msg.get_root_as_reader().unwrap();
        let p = Peering::try_from(reader).unwrap();
        assert_eq!(p.substrate_a, Some(relay));
        assert_eq!(p.substrate_b, None);
    }

    // Writing None must leave the field unset on the wire, not write an empty
    // NetAddr that a reader could take for a real address.
    #[test]
    fn test_peering_none_substrate_stays_unset_on_wire() {
        let original = Peering {
            link_id: "link-none".to_string(),
            node_a: "fd5a:5052::1".parse().unwrap(),
            substrate_a: None,
            node_b: "fd5a:5052::2".parse().unwrap(),
            substrate_b: Some(relay_substrate()),
            attributes: vec![],
        };
        let mut msg = capnp::message::Builder::new_default();
        {
            let mut root: v1::peering::Builder<'_> = msg.init_root();
            original.write_to(&mut root);
        }
        let reader: v1::peering::Reader<'_> = msg.get_root_as_reader().unwrap();
        assert!(!reader.has_node_a_substrate());
        assert!(reader.has_node_b_substrate());
        assert_eq!(Peering::try_from(reader).unwrap(), original);
    }
}
