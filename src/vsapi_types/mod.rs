//! Our internal visa types. These are shared by ph, libnode2, and several visa service
//! crates.
//!

mod auth;
mod common;
mod error;
mod packet;
mod param;
mod request;
mod response;
mod services;
mod topo;
mod util;
mod visa;
mod vsnet;
mod writer;

// PUBLIC API EXPORTS
pub use auth::{AuthBlob, AuthCodeBlob, ChallengeAlg, OidcBlob, SelfSignedBlob};
pub use common::KeyFormat;
pub use error::{ApiResponseError, ErrorCode, VsapiTypeError};
pub use packet::{
    CommFlag, HasFiveTuple, PacketDesc, VsapiFiveTuple, VsapiIpProtocol, vsapi_ip_number,
};
pub use param::{Param, ParamValue, pname};
pub use request::{
    Claim, ConnectRequest, ConnectType, PublicKey, ReauthRequest, VSConnectRequest, VisaRequest,
};
pub use response::{
    Connection, Denied, DenyCode, DisconnectNotice, DisconnectReason, LoginNonce, VisaDecision,
    VisaResponse,
};
pub use services::{AuthServicesList, OidcClientConfig, ServiceDescriptor, ServiceT};
pub use topo::{Link, LinkRole, LinkState, LinkStateReport};
pub use util::ip::ip_addr_from_vec;
pub use util::time::visa_expiration_timestamp_to_system_time;
pub use visa::{
    Constraints, DockPep, DockPepType, EndpointT, FwdPep, FwdPepStyle, IcmpPep, KeySet, TcpUdpPep,
    Visa, VisaOp, VisaType,
};
pub use vsnet::SockAddr;

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    // Helper function to create a test ServiceDescriptor
    fn create_test_service_descriptor() -> ServiceDescriptor {
        ServiceDescriptor {
            stype: ServiceT::ActorAuthentication,
            service_id: "test-service-123".to_string(),
            service_uri: "https://auth.example.com:8443/auth".to_string(),
            zpr_addr: IpAddr::from([192, 168, 1, 100]),
            oidc: None,
        }
    }

    // Helper function to create a test ServiceDescriptor with IPv6
    fn create_test_service_descriptor_v6() -> ServiceDescriptor {
        let ipv6_addr: Ipv6Addr = "2001:db8::1".parse().unwrap();
        ServiceDescriptor {
            stype: ServiceT::ActorAuthentication,
            service_id: "test-service-ipv6".to_string(),
            service_uri: "https://auth.example.com:9443/auth".to_string(),
            zpr_addr: IpAddr::from(ipv6_addr),
            oidc: None,
        }
    }

    #[test]
    fn test_auth_services_list_update() {
        let mut list = AuthServicesList::default();
        let future_time = Some(SystemTime::now() + Duration::from_secs(3600));
        let services = vec![create_test_service_descriptor()];

        list.update(future_time, services.clone());

        assert_eq!(list.expiration, future_time);
        assert_eq!(list.services.len(), 1);
        assert_eq!(list.services[0].service_id, "test-service-123");
    }

    #[test]
    fn test_auth_services_list_is_expired() {
        let mut list = AuthServicesList::default();

        // Test with past time
        let past_time = Some(SystemTime::now() - Duration::from_secs(3600));
        list.expiration = past_time;
        assert!(list.is_expired());

        // Test with future time
        let future_time = Some(SystemTime::now() + Duration::from_secs(3600));
        list.expiration = future_time;
        assert!(!list.is_expired());
    }

    #[test]
    fn test_auth_services_list_is_empty() {
        let mut list = AuthServicesList::default();
        assert!(list.is_empty());

        list.services.push(create_test_service_descriptor());
        assert!(!list.is_empty());
    }

    #[test]
    fn test_auth_services_list_is_valid() {
        let mut list = AuthServicesList::default();

        // Empty and expired
        assert!(!list.is_valid());

        // Non-empty but expired
        list.services.push(create_test_service_descriptor());
        assert!(!list.is_valid());

        // Non-empty and not expired
        list.expiration = Some(SystemTime::now() + Duration::from_secs(3600));
        assert!(list.is_valid());

        // Empty but not expired
        list.services.clear();
        assert!(!list.is_valid());
    }

    #[test]
    fn test_service_descriptor_to_socket_addr_ipv4() {
        let descriptor = create_test_service_descriptor();
        let socket_addr = descriptor.get_socket_addr();

        assert!(socket_addr.is_some());
        let addr = socket_addr.unwrap();
        assert_eq!(addr.port(), 8443);
        assert!(addr.ip().is_ipv4());
        assert_eq!(addr.ip(), IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)));
    }

    #[test]
    fn test_service_descriptor_to_socket_addr_ipv6() {
        let descriptor = create_test_service_descriptor_v6();
        let socket_addr = descriptor.get_socket_addr();

        assert!(socket_addr.is_some());
        let addr = socket_addr.unwrap();
        assert_eq!(addr.port(), 9443);
        assert!(addr.ip().is_ipv6());
        assert_eq!(addr.ip(), IpAddr::V6("2001:db8::1".parse().unwrap()));
    }

    #[test]
    fn test_service_descriptor_to_socket_addr_invalid_uri() {
        let mut descriptor = create_test_service_descriptor();
        descriptor.service_uri = "not-a-valid-uri".to_string();

        let socket_addr = descriptor.get_socket_addr();
        assert!(socket_addr.is_none());
    }

    #[test]
    fn test_service_descriptor_to_socket_addr_no_port() {
        let mut descriptor = create_test_service_descriptor();
        descriptor.service_uri = "https://example.com/auth".to_string(); // No port

        let socket_addr = descriptor.get_socket_addr();
        assert!(socket_addr.is_none());
    }

    #[test]
    fn test_service_descriptor_to_socket_addr_default_port() {
        let mut descriptor = create_test_service_descriptor();
        descriptor.service_uri = "http://example.com/auth".to_string(); // HTTP default port

        let socket_addr = descriptor.get_socket_addr();
        // This should return None because url.port() returns None for default ports
        assert!(socket_addr.is_none());
    }

    #[test]
    fn test_service_descriptor_to_socket_addr_explicit_port() {
        let mut descriptor = create_test_service_descriptor();
        descriptor.service_uri = "http://example.com:8080/auth".to_string();

        let socket_addr = descriptor.get_socket_addr();
        assert!(socket_addr.is_some());
        assert_eq!(socket_addr.unwrap().port(), 8080);
    }

    #[test]
    fn test_visa_expiration_round_trip() {
        // A visa's expiry must survive get_expiration_timestamp -> reader without inflation.
        // 1.7B seconds since epoch: as-millis misread as seconds inflates it ~1000x.
        let expires = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let visa = Visa::new(
            1,
            0,
            expires,
            IpAddr::from([10, 0, 0, 1]),
            IpAddr::from([10, 0, 0, 2]),
            DockPepType::TCP(TcpUdpPep::new(1000, 2000, EndpointT::Any)),
            KeySet::new(&[0u8; 32], &[0u8; 32]),
            None,
        );

        let round_tripped =
            visa_expiration_timestamp_to_system_time(visa.get_expiration_timestamp());
        assert_eq!(round_tripped, expires);
    }
}
