use crate::vsapi::v1;
use crate::vsapi_types::{SockAddr, VsapiTypeError};
use std::net::IpAddr;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinkRole {
    Active,
    Backup,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Link {
    pub link_id: String,
    pub peer: SockAddr,
    pub role: LinkRole,
    /// ZPR address of the peer. Required: the node compares it with its own to
    /// decide who dials (ZODE_LINKS.md). The decoder rejects a link without it.
    pub zpr_addr: IpAddr,
    /// CN the peer's CA-signed link certificate must carry. Required and non-empty:
    /// the decoder rejects a link without it.
    pub peer_cn: String,
}

/// State of one link as a node reports it (vs.capnp `LinkState`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkState {
    /// Established, and the peer's certificate verified with the expected CN.
    /// Reported by both ends.
    Up,
    /// Was up, and is now lost or closed. Reported by both ends.
    Down,
    /// Reported only by the link's owner, after the link-up window passed without
    /// the link coming up. The non-owner never reports it.
    Failed,
}

/// One entry of a node's link-state snapshot (vs.capnp `LinkStateReport`), sent
/// with `VSHandle.reportLinkStates`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkStateReport {
    /// The peer's link-certificate CN, as in `Link::peer_cn`.
    pub peer_cn: String,
    pub state: LinkState,
}

impl From<v1::LinkRole> for LinkRole {
    fn from(r: v1::LinkRole) -> Self {
        match r {
            v1::LinkRole::Active => LinkRole::Active,
            v1::LinkRole::Backup => LinkRole::Backup,
        }
    }
}

impl From<v1::LinkState> for LinkState {
    fn from(s: v1::LinkState) -> Self {
        match s {
            v1::LinkState::Up => LinkState::Up,
            v1::LinkState::Down => LinkState::Down,
            v1::LinkState::Failed => LinkState::Failed,
        }
    }
}

impl From<LinkState> for v1::LinkState {
    fn from(s: LinkState) -> Self {
        match s {
            LinkState::Up => v1::LinkState::Up,
            LinkState::Down => v1::LinkState::Down,
            LinkState::Failed => v1::LinkState::Failed,
        }
    }
}

impl TryFrom<v1::link_state_report::Reader<'_>> for LinkStateReport {
    type Error = VsapiTypeError;

    fn try_from(reader: v1::link_state_report::Reader<'_>) -> Result<Self, Self::Error> {
        Ok(LinkStateReport {
            peer_cn: reader.get_peer_cn()?.to_string()?,
            state: LinkState::from(reader.get_state()?),
        })
    }
}

impl TryFrom<v1::link::Reader<'_>> for Link {
    type Error = VsapiTypeError;

    fn try_from(reader: v1::link::Reader<'_>) -> Result<Self, Self::Error> {
        let link_id = reader.get_link_id()?.to_string()?;
        let peer = SockAddr::try_from(reader.get_peer()?)?;
        let role = LinkRole::from(reader.get_role()?);
        if !reader.has_zpr_addr() {
            return Err(VsapiTypeError::DeserializationError(
                "link is missing zprAddr",
            ));
        }
        let zpr_addr = IpAddr::try_from(reader.get_zpr_addr()?)?;
        // A missing peerCn reads as empty; both are rejected (required, non-empty).
        let peer_cn = reader.get_peer_cn()?.to_string()?;
        if peer_cn.is_empty() {
            return Err(VsapiTypeError::DeserializationError(
                "link is missing peerCn",
            ));
        }

        Ok(Link {
            link_id,
            peer,
            role,
            zpr_addr,
            peer_cn,
        })
    }
}

impl Link {
    pub fn is_active(&self) -> bool {
        matches!(self.role, LinkRole::Active)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vsapi::v1;
    use crate::vsapi_types::SockAddr;
    use crate::write_to::WriteTo;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    const TEST_ZPR_ADDR: &str = "fd5a:5052::42";
    const TEST_PEER_CN: &str = "peer.zpr";

    /// A wire `Link` with both required fields (`zprAddr`, `peerCn`) set.
    fn make_link_msg(
        link_id: &str,
        peer_ip: IpAddr,
        peer_port: u16,
        role: v1::LinkRole,
    ) -> capnp::message::Builder<capnp::message::HeapAllocator> {
        make_link_msg_with(
            link_id,
            peer_ip,
            peer_port,
            role,
            Some(TEST_ZPR_ADDR),
            Some(TEST_PEER_CN),
        )
    }

    /// A wire `Link`; `zpr_addr` and `peer_cn` are left unset when `None`, to build
    /// the messages the decoder must reject.
    fn make_link_msg_with(
        link_id: &str,
        peer_ip: IpAddr,
        peer_port: u16,
        role: v1::LinkRole,
        zpr_addr: Option<&str>,
        peer_cn: Option<&str>,
    ) -> capnp::message::Builder<capnp::message::HeapAllocator> {
        let mut msg = capnp::message::Builder::new_default();
        {
            let mut root: v1::link::Builder<'_> = msg.init_root();
            root.set_link_id(link_id);
            root.set_role(role);
            if let Some(cn) = peer_cn {
                root.set_peer_cn(cn);
            }
            if let Some(zpr) = zpr_addr {
                let ip: IpAddr = zpr.parse().unwrap();
                let mut zpr_bldr = root.reborrow().init_zpr_addr();
                match ip {
                    IpAddr::V4(ipv4) => {
                        let buf = zpr_bldr.reborrow().init_v4(4);
                        buf.copy_from_slice(&ipv4.octets());
                    }
                    IpAddr::V6(ipv6) => {
                        let buf = zpr_bldr.reborrow().init_v6(16);
                        buf.copy_from_slice(&ipv6.octets());
                    }
                }
            }
            let mut peer = root.reborrow().init_peer();
            peer.set_port(peer_port);
            let mut addr_bldr = peer.reborrow().init_addr();
            match peer_ip {
                IpAddr::V4(ipv4) => {
                    let buf = addr_bldr.reborrow().init_v4(4);
                    buf.copy_from_slice(&ipv4.octets());
                }
                IpAddr::V6(ipv6) => {
                    let buf = addr_bldr.reborrow().init_v6(16);
                    buf.copy_from_slice(&ipv6.octets());
                }
            }
        }
        msg
    }

    fn roundtrip_link(link: &Link) -> Link {
        let mut msg = capnp::message::Builder::new_default();
        {
            let mut root: v1::link::Builder<'_> = msg.init_root();
            link.write_to(&mut root);
        }
        let reader: v1::link::Reader<'_> = msg.get_root_as_reader().unwrap();
        Link::try_from(reader).unwrap()
    }

    fn roundtrip_sock_addr(sa: &SockAddr) -> SockAddr {
        let mut msg = capnp::message::Builder::new_default();
        {
            let mut root: v1::sock_addr::Builder<'_> = msg.init_root();
            sa.write_to(&mut root);
        }
        let reader: v1::sock_addr::Reader<'_> = msg.get_root_as_reader().unwrap();
        SockAddr::try_from(reader).unwrap()
    }

    #[test]
    fn test_link_role_active() {
        let role = LinkRole::try_from(v1::LinkRole::Active).unwrap();
        assert_eq!(role, LinkRole::Active);
    }

    #[test]
    fn test_link_role_backup() {
        let role = LinkRole::try_from(v1::LinkRole::Backup).unwrap();
        assert_eq!(role, LinkRole::Backup);
    }

    #[test]
    fn test_link_tryfrom_active_ipv4() {
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let msg = make_link_msg("link-v4-active", ip, 4500, v1::LinkRole::Active);
        let reader: v1::link::Reader<'_> = msg.get_root_as_reader().unwrap();
        let link = Link::try_from(reader).unwrap();
        assert_eq!(link.link_id, "link-v4-active");
        assert_eq!(link.peer.addr, ip);
        assert_eq!(link.peer.port, 4500);
        assert_eq!(link.role, LinkRole::Active);
    }

    #[test]
    fn test_link_tryfrom_backup_ipv6() {
        let ip = IpAddr::V6("2001:db8::1".parse().unwrap());
        let msg = make_link_msg("link-v6-backup", ip, 6000, v1::LinkRole::Backup);
        let reader: v1::link::Reader<'_> = msg.get_root_as_reader().unwrap();
        let link = Link::try_from(reader).unwrap();
        assert_eq!(link.link_id, "link-v6-backup");
        assert_eq!(link.peer.addr, ip);
        assert_eq!(link.peer.port, 6000);
        assert_eq!(link.role, LinkRole::Backup);
    }

    #[test]
    fn test_link_roundtrip_active_ipv4() {
        let original = Link {
            link_id: "rt-v4-active".to_string(),
            peer: SockAddr {
                addr: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
                port: 8080,
            },
            role: LinkRole::Active,
            zpr_addr: TEST_ZPR_ADDR.parse().unwrap(),
            peer_cn: "relay.zpr".to_string(),
        };
        let result = roundtrip_link(&original);
        assert_eq!(result, original);
    }

    #[test]
    fn test_link_roundtrip_backup_ipv6() {
        let original = Link {
            link_id: "rt-v6-backup".to_string(),
            peer: SockAddr {
                addr: IpAddr::V6(Ipv6Addr::from([
                    0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
                ])),
                port: 9000,
            },
            role: LinkRole::Backup,
            zpr_addr: IpAddr::V6("fd5a:5052::7".parse().unwrap()),
            peer_cn: "host-b.zpr".to_string(),
        };
        let result = roundtrip_link(&original);
        assert_eq!(result, original);
    }

    // The zpr_addr must carry through a capnp write/read roundtrip.
    #[test]
    fn test_link_roundtrip_zpr_addr_present() {
        let zpr_ip: IpAddr = "fd5a:5052::42".parse().unwrap();
        let original = Link {
            link_id: "rt-zpr-addr".to_string(),
            peer: SockAddr {
                addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9)),
                port: 4500,
            },
            role: LinkRole::Active,
            zpr_addr: zpr_ip,
            peer_cn: TEST_PEER_CN.to_string(),
        };
        let result = roundtrip_link(&original);
        assert_eq!(result.zpr_addr, zpr_ip);
        assert_eq!(result, original);
    }

    // A message built without zprAddr must fail to deserialize: the field is required.
    #[test]
    fn test_link_tryfrom_zpr_addr_absent() {
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let msg = make_link_msg_with(
            "link-no-zpr-addr",
            ip,
            4500,
            v1::LinkRole::Active,
            None,
            Some(TEST_PEER_CN),
        );
        let reader: v1::link::Reader<'_> = msg.get_root_as_reader().unwrap();
        assert!(Link::try_from(reader).is_err());
    }

    // peerCn must carry through a capnp write/read roundtrip.
    #[test]
    fn test_link_roundtrip_peer_cn() {
        let original = Link {
            link_id: "rt-peer-cn".to_string(),
            peer: SockAddr {
                addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 7)),
                port: 5000,
            },
            role: LinkRole::Active,
            zpr_addr: TEST_ZPR_ADDR.parse().unwrap(),
            peer_cn: "endpoint-a.zpr".to_string(),
        };
        let result = roundtrip_link(&original);
        assert_eq!(result.peer_cn, "endpoint-a.zpr");
        assert_eq!(result, original);
    }

    // peerCn is required (ZODE_LINKS.md "Kinds of link"): a link without it must fail
    // to deserialize.
    #[test]
    fn test_link_tryfrom_peer_cn_absent_is_rejected() {
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let msg = make_link_msg_with(
            "link-no-cn",
            ip,
            4500,
            v1::LinkRole::Active,
            Some(TEST_ZPR_ADDR),
            None,
        );
        let reader: v1::link::Reader<'_> = msg.get_root_as_reader().unwrap();
        assert!(Link::try_from(reader).is_err());
    }

    // An empty peerCn is the same as a missing one: rejected.
    #[test]
    fn test_link_tryfrom_peer_cn_empty_is_rejected() {
        let ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let msg = make_link_msg_with(
            "link-empty-cn",
            ip,
            4500,
            v1::LinkRole::Active,
            Some(TEST_ZPR_ADDR),
            Some(""),
        );
        let reader: v1::link::Reader<'_> = msg.get_root_as_reader().unwrap();
        assert!(Link::try_from(reader).is_err());
    }

    /// Every pairing between the capnp link state and ours, asserted as explicit
    /// pairs so two swapped variants cannot pass a roundtrip.
    const LINK_STATE_PAIRS: [(v1::LinkState, LinkState); 3] = [
        (v1::LinkState::Up, LinkState::Up),
        (v1::LinkState::Down, LinkState::Down),
        (v1::LinkState::Failed, LinkState::Failed),
    ];

    #[test]
    fn test_link_state_maps_both_ways() {
        for (wire, ours) in LINK_STATE_PAIRS {
            assert_eq!(LinkState::from(wire), ours);
            assert_eq!(v1::LinkState::from(ours), wire);
        }
    }

    fn roundtrip_link_state_report(report: &LinkStateReport) -> LinkStateReport {
        let mut msg = capnp::message::Builder::new_default();
        {
            let mut root: v1::link_state_report::Builder<'_> = msg.init_root();
            report.write_to(&mut root);
        }
        let reader: v1::link_state_report::Reader<'_> = msg.get_root_as_reader().unwrap();
        LinkStateReport::try_from(reader).unwrap()
    }

    #[test]
    fn test_link_state_report_roundtrip_each_state() {
        for (_, state) in LINK_STATE_PAIRS {
            let original = LinkStateReport {
                peer_cn: "relay.zpr".to_string(),
                state,
            };
            assert_eq!(roundtrip_link_state_report(&original), original);
        }
    }

    #[test]
    fn test_sock_addr_roundtrip_ipv4() {
        let original = SockAddr {
            addr: IpAddr::V4(Ipv4Addr::new(10, 20, 30, 40)),
            port: 1234,
        };
        let result = roundtrip_sock_addr(&original);
        assert_eq!(result.addr, original.addr);
        assert_eq!(result.port, original.port);
    }

    #[test]
    fn test_sock_addr_roundtrip_ipv6() {
        let original = SockAddr {
            addr: IpAddr::V6(Ipv6Addr::from([0u8; 16])),
            port: 5678,
        };
        let result = roundtrip_sock_addr(&original);
        assert_eq!(result.addr, original.addr);
        assert_eq!(result.port, original.port);
    }
}
