use std::io::Cursor;
use std::net::IpAddr;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::packet_info::L3Type;
use crate::vsapi::v1;
use crate::vsapi_types::KeyFormat;
use crate::vsapi_types::VsapiFiveTuple;
use crate::vsapi_types::VsapiTypeError;
use crate::vsapi_types::packet::HasFiveTuple;
use crate::vsapi_types::util::time::visa_expiration_timestamp_to_system_time;
use crate::vsapi_types::vsapi_ip_number;

/// Structure representing the Visa
// TODO figure out which of these need to stay once we switch to capnp
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Visa {
    pub issuer_id: u64,
    pub config: i64,
    pub expires: SystemTime,
    pub visa_type: VisaType,
    /// Required for type [VisaType::Full], will not be set for type [VisaType::ForwardOnly]
    pub dock_pep: Option<DockPep>,
    /// Required for type [VisaType::ForwardOnly], optional for type [VisaType::Full]
    pub fwd_pep: Option<FwdPep>,
    pub cons: Option<Constraints>,
    /// ZPR address of the node this visa's stream arrives from (vs.capnp `Visa.prevHop`).
    /// Set by the visa service on intermediary and egress visas; `None` on the ingress
    /// visa. A node accepts a StreamIdRequest for this visa only on the link whose peer's
    /// topology ZPR address equals this; `None` means it never accepts one (gap 7).
    pub prev_hop: Option<IpAddr>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VisaType {
    /// An ingress or egress visa. If ingress, might have a [FwdPep]. Will have a [DockPep].
    Full,
    /// For intermediary nodes on a path. Will have a [FwdPep], will not have a [DockPep].
    ForwardOnly,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FwdPep {
    /// Node ZPR address
    pub next_hop: IpAddr,
    pub style: FwdPepStyle,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FwdPepStyle {
    OneWay,

    /// Visa route applies in both directions
    Symmetric,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DockPep {
    pub source_addr: IpAddr,
    pub dest_addr: IpAddr,
    pub session_key: KeySet,
    pub pep: DockPepType,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DockPepType {
    TCP(TcpUdpPep),
    UDP(TcpUdpPep),
    ICMP(IcmpPep),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpUdpPep {
    pub source_port: u16,
    pub dest_port: u16,
    pub endpoint: EndpointT,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EndpointT {
    Any,
    Server,
    Client,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IcmpPep {
    /// the allowed ICMP type and code (in lower 16 bits)
    pub icmp_type: u8,
    pub icmp_code: u8,
}

#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct KeySet {
    pub format: KeyFormat,
    /// session key encrypted for ingress node to read
    pub ingress_key: Vec<u8>,
    /// session key encrypted for egress node to read
    pub egress_key: Vec<u8>,
}

#[derive(Debug)]
pub enum VisaOp {
    Grant(Visa),
    RevokeVisaId(u64),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Constraints {
    /// not set or none means no bandwidth constraint
    pub bw: bool,
    pub bw_limit_bps: i64,
    /// empty/None means no data cap
    pub data_cap_id: String,
    pub data_cap_bytes: i64,
    /// tether addr of service actor
    pub data_cap_affinity_addr: Vec<u8>,
}

impl KeySet {
    pub fn new(ingress: &[u8], egress: &[u8]) -> Self {
        KeySet {
            ingress_key: ingress.to_vec(),
            egress_key: egress.to_vec(),
            format: KeyFormat::default(),
        }
    }
}

impl Visa {
    /// Create a new "full" visa with no forwarding information.
    pub fn new(
        issuer_id: u64,
        config: i64,
        expires: SystemTime,
        source_addr: IpAddr,
        dest_addr: IpAddr,
        pep: DockPepType,
        session_key: KeySet,
        cons: Option<Constraints>,
    ) -> Self {
        let dock_pep = DockPep {
            source_addr,
            dest_addr,
            session_key,
            pep,
        };
        Self {
            issuer_id,
            config,
            expires,
            visa_type: VisaType::Full,
            dock_pep: Some(dock_pep),
            fwd_pep: None,
            cons,
            prev_hop: None,
        }
    }

    pub fn from_capnp_bytes(bytes: &[u8]) -> Result<Self, VsapiTypeError> {
        let mut cur = Cursor::new(bytes);
        let reader =
            capnp::serialize::read_message(&mut cur, capnp::message::ReaderOptions::new())?;
        let visa_reader = reader.get_root::<v1::visa::Reader>()?;
        Visa::try_from(visa_reader)
    }

    /// Get the expiration in milliseconds since UNIX epoch (which is how visa service formats it).
    pub fn get_expiration_timestamp(&self) -> u64 {
        match self.expires.duration_since(UNIX_EPOCH) {
            Ok(dur) => dur.as_millis() as u64,
            Err(_) => 0,
        }
    }

    /// Helper to get the five tuple if it exists.
    pub fn five_tuple(&self) -> Option<VsapiFiveTuple> {
        self.dock_pep
            .as_ref()
            .map(|dock_pep| dock_pep.get_five_tuple())
    }
}

impl HasFiveTuple for DockPep {
    /// Get the FiveTuple from a Visa
    fn get_five_tuple(&self) -> VsapiFiveTuple {
        let source_addr = self.source_addr;
        let dest_addr = self.dest_addr;

        let l3_protocol = if source_addr.is_ipv4() {
            L3Type::Ipv4
        } else {
            L3Type::Ipv6
        };

        let (l4_protocol, source_port, dest_port) = match &self.pep {
            DockPepType::ICMP(icmp_pep) => {
                if l3_protocol == L3Type::Ipv6 {
                    (
                        vsapi_ip_number::IPV6_ICMP,
                        icmp_pep.icmp_type as u16,
                        icmp_pep.icmp_code as u16,
                    )
                } else {
                    (
                        vsapi_ip_number::ICMP,
                        icmp_pep.icmp_type as u16,
                        icmp_pep.icmp_code as u16,
                    )
                }
            }
            DockPepType::UDP(tcp_udp_pep) => (
                vsapi_ip_number::UDP,
                tcp_udp_pep.source_port,
                tcp_udp_pep.dest_port,
            ),
            DockPepType::TCP(tcp_udp_pep) => (
                vsapi_ip_number::TCP,
                tcp_udp_pep.source_port,
                tcp_udp_pep.dest_port,
            ),
        };

        return VsapiFiveTuple {
            source_addr,
            dest_addr,
            l3_type: l3_protocol,
            l4_protocol,
            source_port,
            dest_port,
        };
    }
}

impl TcpUdpPep {
    pub fn new(source_port: u16, dest_port: u16, endpoint: EndpointT) -> Self {
        Self {
            source_port,
            dest_port,
            endpoint,
        }
    }
}

impl IcmpPep {
    pub fn new(icmp_type: u8, icmp_code: u8) -> Self {
        Self {
            icmp_type,
            icmp_code,
        }
    }
}

impl TryFrom<v1::visa::Reader<'_>> for Visa {
    type Error = VsapiTypeError;

    /// Returns err if required values are not set or if values are badly formatted
    fn try_from(reader: v1::visa::Reader) -> Result<Self, Self::Error> {
        let issuer_id = reader.get_issuer_id();
        let config = 0i64;
        let expires = visa_expiration_timestamp_to_system_time(reader.get_expiration());

        let visa_type = match reader.get_visa_type()? {
            v1::VisaType::Full => VisaType::Full,
            v1::VisaType::ForwardOnly => VisaType::ForwardOnly,
        };

        let dock_pep = if reader.has_dock_pep() {
            Some(DockPep::try_from(reader.get_dock_pep()?)?)
        } else {
            None
        };

        let fwd_pep = if reader.has_fwd_pep() {
            Some(FwdPep::try_from(reader.get_fwd_pep()?)?)
        } else {
            None
        };

        // TODO: constraints not yet implemented.
        let cons = None;

        let prev_hop = if reader.has_prev_hop() {
            Some(IpAddr::try_from(reader.get_prev_hop()?)?)
        } else {
            None
        };

        Ok(Self {
            issuer_id,
            config,
            expires,
            visa_type,
            dock_pep,
            fwd_pep,
            cons,
            prev_hop,
        })
    }
}

impl TryFrom<v1::visa_op::Reader<'_>> for VisaOp {
    type Error = VsapiTypeError;

    /// Returns err if required values are not set or if values are badly formatted
    fn try_from(reader: v1::visa_op::Reader) -> Result<Self, Self::Error> {
        match reader.which()? {
            v1::visa_op::Which::Grant(visa_result) => {
                let visa_reader = visa_result?;
                let visa = Visa::try_from(visa_reader)?;
                Ok(VisaOp::Grant(visa))
            }
            v1::visa_op::Which::RevokeVisaId(issuer_id) => Ok(VisaOp::RevokeVisaId(issuer_id)),
        }
    }
}

impl TryFrom<v1::fwd_pep::Reader<'_>> for FwdPep {
    type Error = VsapiTypeError;

    /// Returns err if required values are not set
    fn try_from(reader: v1::fwd_pep::Reader) -> Result<Self, Self::Error> {
        let next_hop = IpAddr::try_from(reader.get_next_hop()?)?;
        let symmetric = reader.get_symmetric();
        let style = if symmetric {
            FwdPepStyle::Symmetric
        } else {
            FwdPepStyle::OneWay
        };
        Ok(FwdPep { next_hop, style })
    }
}

impl TryFrom<v1::dock_pep::Reader<'_>> for DockPep {
    type Error = VsapiTypeError;

    /// Returns err if required values are not set
    fn try_from(reader: v1::dock_pep::Reader) -> Result<Self, Self::Error> {
        let source_addr = IpAddr::try_from(reader.get_source_addr()?)?;
        let dest_addr = IpAddr::try_from(reader.get_dest_addr()?)?;
        let session_key = KeySet::try_from(reader.get_session_key()?)?;

        let pep = match reader.which()? {
            v1::dock_pep::Which::Tcp(tcp_udp_pep_result) => {
                let tcp_udp_pep_reader = tcp_udp_pep_result?;
                let source_port = tcp_udp_pep_reader.get_source_port();
                let dest_port = tcp_udp_pep_reader.get_dest_port();
                let endpoint = match tcp_udp_pep_reader.get_endpoint()? {
                    v1::EndpointT::Any => EndpointT::Any,
                    v1::EndpointT::Server => EndpointT::Server,
                    v1::EndpointT::Client => EndpointT::Client,
                };
                let tcp_udp_pep = TcpUdpPep::new(source_port, dest_port, endpoint);
                DockPepType::TCP(tcp_udp_pep)
            }
            v1::dock_pep::Which::Udp(tcp_udp_pep_result) => {
                let tcp_udp_pep_reader = tcp_udp_pep_result?;
                let source_port = tcp_udp_pep_reader.get_source_port();
                let dest_port = tcp_udp_pep_reader.get_dest_port();
                let endpoint = match tcp_udp_pep_reader.get_endpoint()? {
                    v1::EndpointT::Any => EndpointT::Any,
                    v1::EndpointT::Server => EndpointT::Server,
                    v1::EndpointT::Client => EndpointT::Client,
                };
                let tcp_udp_pep = TcpUdpPep::new(source_port, dest_port, endpoint);
                DockPepType::UDP(tcp_udp_pep)
            }
            v1::dock_pep::Which::Icmp(icmp_pep_result) => {
                let icmp_pep_reader = icmp_pep_result?;
                // Packed as `type << 8 | code` by the writer; unpack both bytes.
                let type_code = icmp_pep_reader.get_icmp_type_code();
                let icmp_pep = IcmpPep::new((type_code >> 8) as u8, type_code as u8);
                DockPepType::ICMP(icmp_pep)
            }
        };
        Ok(DockPep {
            source_addr,
            dest_addr,
            session_key,
            pep,
        })
    }
}

impl TryFrom<v1::key_set::Reader<'_>> for KeySet {
    type Error = VsapiTypeError;

    /// Returns err if required values are not set
    fn try_from(reader: v1::key_set::Reader) -> Result<Self, Self::Error> {
        let format = match reader.get_format()? {
            v1::KeyFormat::ZprKF01 => KeyFormat::ZprKF01,
        };
        let ingress_key = reader.get_ingress_key()?.to_vec();
        let egress_key = reader.get_egress_key()?.to_vec();

        Ok(Self {
            format,
            ingress_key,
            egress_key,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::write_to::WriteTo;
    use std::net::{Ipv4Addr, Ipv6Addr};

    const SRC_V4: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    const DST_V4: IpAddr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));

    fn dock_pep(source_addr: IpAddr, dest_addr: IpAddr, pep: DockPepType) -> DockPep {
        DockPep {
            source_addr,
            dest_addr,
            session_key: KeySet::new(&[1, 2, 3], &[4, 5, 6]),
            pep,
        }
    }

    /// Encode a DockPep with the production writer and decode it with the
    /// production reader.
    fn round_trip(pep: &DockPep) -> DockPep {
        let mut msg = capnp::message::Builder::new_default();
        {
            let mut root: v1::dock_pep::Builder<'_> = msg.init_root();
            pep.write_to(&mut root);
        }
        let reader: v1::dock_pep::Reader<'_> = msg.get_root_as_reader().unwrap();
        DockPep::try_from(reader).expect("a written dock pep must decode")
    }

    // --- ICMP ---

    /// The wire field is a single `UInt16` packed as `type << 8 | code`, so both
    /// bytes must survive the trip.
    #[test]
    fn test_icmp_pep_round_trips_type_and_code() {
        // (type, code) pairs, with the meaning of the real ICMP ones noted.
        let cases = [
            (0u8, 0u8), // echo reply
            (8, 0),     // echo request
            (3, 1),     // destination unreachable / host unreachable
            (11, 0),    // time exceeded
            (5, 3),     // redirect
            (255, 255), // both bytes fully set
        ];

        for (icmp_type, icmp_code) in cases {
            let original = dock_pep(
                SRC_V4,
                DST_V4,
                DockPepType::ICMP(IcmpPep::new(icmp_type, icmp_code)),
            );

            let decoded = round_trip(&original);

            assert_eq!(
                decoded, original,
                "ICMP type {icmp_type} code {icmp_code} did not survive the round trip"
            );
        }
    }

    /// The ICMP type and code are what the lookup table matches on, so a decode
    /// error here mismatches traffic rather than merely displaying it wrong.
    #[test]
    fn test_icmp_five_tuple_carries_type_and_code() {
        let pep = dock_pep(SRC_V4, DST_V4, DockPepType::ICMP(IcmpPep::new(8, 0)));

        let ft = round_trip(&pep).get_five_tuple();

        assert_eq!(ft.l4_protocol, vsapi_ip_number::ICMP);
        assert_eq!(ft.source_port, 8, "ICMP type belongs in source_port");
        assert_eq!(ft.dest_port, 0, "ICMP code belongs in dest_port");
    }

    #[test]
    fn test_icmp_over_ipv6_uses_the_v6_protocol_number() {
        let src = IpAddr::V6(Ipv6Addr::new(0xfd5a, 0x5052, 0, 0, 0, 0, 0, 1));
        let dst = IpAddr::V6(Ipv6Addr::new(0xfd5a, 0x5052, 0, 0, 0, 0, 0, 2));
        let pep = dock_pep(src, dst, DockPepType::ICMP(IcmpPep::new(128, 0)));

        let decoded = round_trip(&pep);
        let ft = decoded.get_five_tuple();

        assert_eq!(decoded, pep);
        assert_eq!(ft.l4_protocol, vsapi_ip_number::IPV6_ICMP);
        assert_eq!(ft.l3_type, L3Type::Ipv6);
    }

    // --- TCP / UDP ---

    #[test]
    fn test_tcp_and_udp_peps_round_trip_every_endpoint() {
        for endpoint in [EndpointT::Any, EndpointT::Server, EndpointT::Client] {
            let tcp_pep = TcpUdpPep::new(4242, 443, endpoint.clone());
            let tcp = dock_pep(SRC_V4, DST_V4, DockPepType::TCP(tcp_pep.clone()));
            assert_eq!(round_trip(&tcp), tcp, "TCP with endpoint {endpoint:?}");

            let udp = dock_pep(SRC_V4, DST_V4, DockPepType::UDP(tcp_pep));
            assert_eq!(round_trip(&udp), udp, "UDP with endpoint {endpoint:?}");
        }
    }

    /// TCP and UDP share a wire struct but must not collapse into one another.
    #[test]
    fn test_tcp_and_udp_stay_distinct() {
        let pep = TcpUdpPep::new(1, 2, EndpointT::Any);
        let tcp = round_trip(&dock_pep(SRC_V4, DST_V4, DockPepType::TCP(pep.clone())));
        let udp = round_trip(&dock_pep(SRC_V4, DST_V4, DockPepType::UDP(pep)));

        assert!(matches!(tcp.pep, DockPepType::TCP(_)));
        assert!(matches!(udp.pep, DockPepType::UDP(_)));
        assert_eq!(tcp.get_five_tuple().l4_protocol, vsapi_ip_number::TCP);
        assert_eq!(udp.get_five_tuple().l4_protocol, vsapi_ip_number::UDP);
    }

    #[test]
    fn test_tcp_five_tuple_carries_ports_and_addrs() {
        let pep = dock_pep(
            SRC_V4,
            DST_V4,
            DockPepType::TCP(TcpUdpPep::new(4242, 443, EndpointT::Server)),
        );

        let ft = round_trip(&pep).get_five_tuple();

        assert_eq!(ft.source_addr, SRC_V4);
        assert_eq!(ft.dest_addr, DST_V4);
        assert_eq!(ft.l3_type, L3Type::Ipv4);
        assert_eq!(ft.source_port, 4242);
        assert_eq!(ft.dest_port, 443);
    }

    // --- KeySet ---

    #[test]
    fn test_session_keys_round_trip() {
        let pep = dock_pep(
            SRC_V4,
            DST_V4,
            DockPepType::TCP(TcpUdpPep::new(1, 2, EndpointT::Any)),
        );

        let decoded = round_trip(&pep);

        assert_eq!(decoded.session_key.ingress_key, vec![1, 2, 3]);
        assert_eq!(decoded.session_key.egress_key, vec![4, 5, 6]);
        assert_eq!(decoded.session_key.format, KeyFormat::ZprKF01);
    }

    #[test]
    fn test_empty_session_keys_round_trip() {
        let mut pep = dock_pep(
            SRC_V4,
            DST_V4,
            DockPepType::TCP(TcpUdpPep::new(1, 2, EndpointT::Any)),
        );
        pep.session_key = KeySet::new(&[], &[]);

        let decoded = round_trip(&pep);

        assert!(decoded.session_key.ingress_key.is_empty());
        assert!(decoded.session_key.egress_key.is_empty());
    }

    // --- prevHop (gap 7: StreamIdRequest only from the visa's previous hop) ---

    fn full_visa() -> Visa {
        // config and cons are not carried on the wire; keep them at their defaults.
        Visa::new(
            7,
            0,
            UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000),
            SRC_V4,
            DST_V4,
            DockPepType::TCP(TcpUdpPep::new(4242, 443, EndpointT::Client)),
            KeySet::new(&[1, 2, 3], &[4, 5, 6]),
            None,
        )
    }

    /// Write a visa with the production writer; return the decoded visa and whether
    /// `prevHop` was set on the wire.
    fn round_trip_visa(visa: &Visa) -> (Visa, bool) {
        let mut msg = capnp::message::Builder::new_default();
        {
            let mut root: v1::visa::Builder<'_> = msg.init_root();
            visa.write_to(&mut root);
        }
        let reader: v1::visa::Reader<'_> = msg.get_root_as_reader().unwrap();
        let on_wire = reader.has_prev_hop();
        (
            Visa::try_from(reader).expect("a written visa must decode"),
            on_wire,
        )
    }

    #[test]
    fn test_visa_new_has_no_prev_hop() {
        // Visa::new builds an ingress-shaped visa, which never has a previous hop.
        assert_eq!(full_visa().prev_hop, None);
    }

    #[test]
    fn test_prev_hop_round_trips_v4_and_v6() {
        let v6 = IpAddr::V6(Ipv6Addr::new(0xfd5a, 0x5052, 0, 0, 0, 0, 0, 9));
        for hop in [IpAddr::V4(Ipv4Addr::new(10, 9, 9, 9)), v6] {
            let mut visa = full_visa();
            visa.prev_hop = Some(hop);

            let (decoded, on_wire) = round_trip_visa(&visa);

            assert!(on_wire, "prevHop must be written when set");
            assert_eq!(
                decoded, visa,
                "prevHop {hop} did not survive the round trip"
            );
        }
    }

    #[test]
    fn test_unset_prev_hop_stays_unset() {
        let visa = full_visa();

        let (decoded, on_wire) = round_trip_visa(&visa);

        assert!(!on_wire, "None must leave prevHop unset on the wire");
        assert_eq!(decoded.prev_hop, None);
        assert_eq!(decoded, visa);
    }

    #[test]
    fn test_forward_only_visa_carries_prev_hop_beside_fwd_pep() {
        let visa = Visa {
            visa_type: VisaType::ForwardOnly,
            dock_pep: None,
            fwd_pep: Some(FwdPep {
                next_hop: DST_V4,
                style: FwdPepStyle::OneWay,
            }),
            prev_hop: Some(SRC_V4),
            ..full_visa()
        };

        let (decoded, on_wire) = round_trip_visa(&visa);

        assert!(on_wire);
        assert_eq!(decoded, visa);
    }
}
