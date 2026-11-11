use std::fmt;
use std::net::IpAddr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::vsapi::v1;
use crate::vsapi_types::error::ErrorCode;
use crate::vsapi_types::{ApiResponseError, Visa, VsapiTypeError};

/// A login nonce minted by the visa service (vs.capnp `LoginNonce`, returned by
/// `VSHandle.getLoginNonce`). The node uses `nonce` verbatim as the OIDC
/// authorization request's `nonce`; the visa service accepts it once, before
/// `expires_at`, for the actor and session it was issued to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoginNonce {
    pub nonce: String,
    pub expires_at: SystemTime,
}

impl LoginNonce {
    /// Expiry as unix seconds, the wire format of `LoginNonce.expiresAt`. A time
    /// before the epoch (never minted in practice) clamps to 0.
    pub fn expires_at_secs(&self) -> u64 {
        self.expires_at
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }
}

impl TryFrom<v1::login_nonce::Reader<'_>> for LoginNonce {
    type Error = VsapiTypeError;

    fn try_from(reader: v1::login_nonce::Reader<'_>) -> Result<Self, Self::Error> {
        Ok(LoginNonce {
            nonce: reader.get_nonce()?.to_string()?,
            // checked_add: an expiresAt beyond SystemTime's range is malformed
            // wire data and must be an error, not a panic.
            expires_at: UNIX_EPOCH
                .checked_add(Duration::from_secs(reader.get_expires_at()))
                .ok_or(VsapiTypeError::DeserializationError(
                    "loginNonce expiresAt out of range",
                ))?,
        })
    }
}

/// Info recieved from VS in response to ConnectRequest
#[derive(Debug)]
pub struct Connection {
    pub zpr_addr: IpAddr,
    pub auth_expires: u64,
}

#[derive(Debug)]
pub enum VisaResponse {
    Allowed(Visa),
    Denied(Denied),
    VsapiTypeError(ApiResponseError),
}

/// Denial information
#[derive(Debug)]
pub struct Denied {
    pub code: DenyCode,
    pub reason: Option<String>,
}

#[derive(Debug)]
pub enum VisaDecision {
    Allowed(Visa),
    Denied(Denied),
}

/// Disconnect reason, mirrors DisconnectReason in vs.capnp
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum DisconnectReason {
    RemoteDisconnect,
    Timeout,
    LinkError,
    NodeShutdown,
    Admin,
}

/// Denial code, match the codes in vs.capnp, except for Fail
#[derive(Debug, Eq, PartialEq)]
pub enum DenyCode {
    NoReason,
    NoMatch,
    Denied,
    SourceNotFound,
    DestNotFound,
    SourceAuthError,
    DestAuthError,
    QuotaExceeded,
    NoRoute,
}

#[derive(Debug)]
pub struct DisconnectNotice {
    /// None = node itself, Some = specific adapter
    pub zpr_addr: Option<IpAddr>,
    pub reason: DisconnectReason,
}

impl Connection {
    /// An `auth_expires` before the unix epoch cannot be represented on the wire
    /// (`authExpires` is a `UInt64` of seconds), so it collapses to 0 — already
    /// expired. Failing closed beats panicking on a bad upstream clock.
    pub fn new(zpr_addr: IpAddr, auth_expires: SystemTime) -> Self {
        Self {
            zpr_addr,
            auth_expires: auth_expires
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        }
    }
}

impl Denied {
    pub fn new(code: DenyCode, reason: Option<String>) -> Self {
        Self { code, reason }
    }
}

impl fmt::Display for DenyCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl fmt::Display for DisconnectReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl TryFrom<v1::connection::Reader<'_>> for Connection {
    type Error = VsapiTypeError;

    fn try_from(reader: v1::connection::Reader<'_>) -> Result<Self, Self::Error> {
        let zpr_addr = IpAddr::try_from(reader.get_zpr_addr()?)?;
        let auth_expires = reader.get_auth_expires();
        Ok(Connection {
            zpr_addr,
            auth_expires,
        })
    }
}

impl TryFrom<v1::visa_response::Reader<'_>> for VisaResponse {
    type Error = VsapiTypeError;

    /// Returns err if visa_response is Error, if Visa is poorly format, if DenyCode or ErrorCode are unrecognized
    fn try_from(capnp_visa_response: v1::visa_response::Reader) -> Result<Self, Self::Error> {
        match capnp_visa_response.which()? {
            v1::visa_response::Which::Allow(v) => {
                let cp_visa = v?;
                let visa = Visa::try_from(cp_visa)?;
                Ok(VisaResponse::Allowed(visa))
            }
            v1::visa_response::Which::Deny(dcode) => {
                let dcode = dcode?;
                let deny_code = DenyCode::from(dcode);
                Ok(VisaResponse::Denied(Denied::new(deny_code, None)))
            }
            v1::visa_response::Which::Error(err_obj) => {
                let err_obj = err_obj?;
                Ok(VisaResponse::VsapiTypeError(ApiResponseError::try_from(
                    err_obj,
                )?))
            }
        }
    }
}

impl TryFrom<VisaResponse> for VisaDecision {
    type Error = ApiResponseError;

    fn try_from(visa_response: VisaResponse) -> Result<Self, Self::Error> {
        match visa_response {
            VisaResponse::Allowed(v) => Ok(VisaDecision::Allowed(v)),
            VisaResponse::Denied(d) => Ok(VisaDecision::Denied(d)),
            VisaResponse::VsapiTypeError(e) => Err(e),
        }
    }
}

impl From<v1::VisaDenyCode> for DenyCode {
    fn from(code: v1::VisaDenyCode) -> Self {
        match code {
            v1::VisaDenyCode::NoReason => DenyCode::NoReason,
            v1::VisaDenyCode::NoMatch => DenyCode::NoMatch,
            v1::VisaDenyCode::Denied => DenyCode::Denied,
            v1::VisaDenyCode::SourceNotFound => DenyCode::SourceNotFound,
            v1::VisaDenyCode::DestNotFound => DenyCode::DestNotFound,
            v1::VisaDenyCode::SourceAuthError => DenyCode::SourceAuthError,
            v1::VisaDenyCode::DestAuthError => DenyCode::DestAuthError,
            v1::VisaDenyCode::QuotaExceeded => DenyCode::QuotaExceeded,
            v1::VisaDenyCode::NoRoute => DenyCode::NoRoute,
        }
    }
}

impl From<DenyCode> for v1::VisaDenyCode {
    fn from(code: DenyCode) -> Self {
        match code {
            DenyCode::NoReason => v1::VisaDenyCode::NoReason,
            DenyCode::NoMatch => v1::VisaDenyCode::NoMatch,
            DenyCode::Denied => v1::VisaDenyCode::Denied,
            DenyCode::SourceNotFound => v1::VisaDenyCode::SourceNotFound,
            DenyCode::DestNotFound => v1::VisaDenyCode::DestNotFound,
            DenyCode::SourceAuthError => v1::VisaDenyCode::SourceAuthError,
            DenyCode::DestAuthError => v1::VisaDenyCode::DestAuthError,
            DenyCode::QuotaExceeded => v1::VisaDenyCode::QuotaExceeded,
            DenyCode::NoRoute => v1::VisaDenyCode::NoRoute,
        }
    }
}

impl From<v1::DisconnectReason> for DisconnectReason {
    fn from(reason: v1::DisconnectReason) -> Self {
        match reason {
            v1::DisconnectReason::RemoteDisconnect => DisconnectReason::RemoteDisconnect,
            v1::DisconnectReason::Timeout => DisconnectReason::Timeout,
            v1::DisconnectReason::LinkError => DisconnectReason::LinkError,
            v1::DisconnectReason::NodeShutdown => DisconnectReason::NodeShutdown,
            v1::DisconnectReason::Admin => DisconnectReason::Admin,
        }
    }
}

impl From<DisconnectReason> for v1::DisconnectReason {
    fn from(reason: DisconnectReason) -> Self {
        match reason {
            DisconnectReason::RemoteDisconnect => v1::DisconnectReason::RemoteDisconnect,
            DisconnectReason::Timeout => v1::DisconnectReason::Timeout,
            DisconnectReason::LinkError => v1::DisconnectReason::LinkError,
            DisconnectReason::NodeShutdown => v1::DisconnectReason::NodeShutdown,
            DisconnectReason::Admin => v1::DisconnectReason::Admin,
        }
    }
}

impl From<v1::ErrorCode> for ErrorCode {
    fn from(code: v1::ErrorCode) -> Self {
        match code {
            v1::ErrorCode::Internal => ErrorCode::Internal,
            v1::ErrorCode::AuthRequired => ErrorCode::AuthRequired,
            v1::ErrorCode::InvalidOperation => ErrorCode::InvalidOperation,
            v1::ErrorCode::OutOfSync => ErrorCode::OutOfSync,
            v1::ErrorCode::NotFound => ErrorCode::NotFound,
            v1::ErrorCode::InvalidSignature => ErrorCode::InvalidSignature,
            v1::ErrorCode::QuotaExceeded => ErrorCode::QuotaExceeded,
            v1::ErrorCode::TemporarilyUnavailable => ErrorCode::TemporarilyUnavailable,
            v1::ErrorCode::AuthError => ErrorCode::AuthError,
            v1::ErrorCode::ParamError => ErrorCode::ParamError,
            v1::ErrorCode::PolicyDenied => ErrorCode::PolicyDenied,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::write_to::WriteTo;
    use std::net::Ipv4Addr;

    fn roundtrip_login_nonce(nonce: &LoginNonce) -> LoginNonce {
        let mut msg = capnp::message::Builder::new_default();
        {
            let mut root: v1::login_nonce::Builder<'_> = msg.init_root();
            nonce.write_to(&mut root);
        }
        let reader: v1::login_nonce::Reader<'_> = msg.get_root_as_reader().unwrap();
        LoginNonce::try_from(reader).unwrap()
    }

    // The nonce text is used verbatim and expiresAt is exact to the second.
    #[test]
    fn test_login_nonce_roundtrip() {
        let original = LoginNonce {
            nonce: "q7Zt-3vXr_9a".to_string(),
            expires_at: UNIX_EPOCH + Duration::from_secs(1_800_000_123),
        };
        let result = roundtrip_login_nonce(&original);
        assert_eq!(result, original);
    }

    // A malformed expiresAt beyond SystemTime's range must be a decode error, not
    // a panic: this is wire data from the visa service.
    #[test]
    fn test_login_nonce_overflowing_expires_at_is_an_error() {
        let mut msg = capnp::message::Builder::new_default();
        {
            let mut root: v1::login_nonce::Builder<'_> = msg.init_root();
            root.set_nonce("n");
            root.set_expires_at(u64::MAX);
        }
        let reader: v1::login_nonce::Reader<'_> = msg.get_root_as_reader().unwrap();
        assert!(LoginNonce::try_from(reader).is_err());
    }

    // expiresAt on the wire is unix seconds, not milliseconds like a visa's expiry.
    #[test]
    fn test_login_nonce_expires_at_is_seconds() {
        let mut msg = capnp::message::Builder::new_default();
        {
            let mut root: v1::login_nonce::Builder<'_> = msg.init_root();
            root.set_nonce("n");
            root.set_expires_at(1_800_000_000);
        }
        let reader: v1::login_nonce::Reader<'_> = msg.get_root_as_reader().unwrap();
        let nonce = LoginNonce::try_from(reader).unwrap();
        assert_eq!(
            nonce.expires_at,
            UNIX_EPOCH + Duration::from_secs(1_800_000_000)
        );
    }

    /// Every 1:1 pairing between the capnp deny code and our own.
    ///
    /// Asserted as explicit pairs rather than only round-tripped: a round trip
    /// still succeeds if two variants are swapped in *both* directions, which is
    /// exactly the copy/paste mistake these tables invite.
    const DENY_CODE_PAIRS: [(v1::VisaDenyCode, DenyCode); 9] = [
        (v1::VisaDenyCode::NoReason, DenyCode::NoReason),
        (v1::VisaDenyCode::NoMatch, DenyCode::NoMatch),
        (v1::VisaDenyCode::Denied, DenyCode::Denied),
        (v1::VisaDenyCode::SourceNotFound, DenyCode::SourceNotFound),
        (v1::VisaDenyCode::DestNotFound, DenyCode::DestNotFound),
        (v1::VisaDenyCode::SourceAuthError, DenyCode::SourceAuthError),
        (v1::VisaDenyCode::DestAuthError, DenyCode::DestAuthError),
        (v1::VisaDenyCode::QuotaExceeded, DenyCode::QuotaExceeded),
        (v1::VisaDenyCode::NoRoute, DenyCode::NoRoute),
    ];

    const DISCONNECT_REASON_PAIRS: [(v1::DisconnectReason, DisconnectReason); 5] = [
        (
            v1::DisconnectReason::RemoteDisconnect,
            DisconnectReason::RemoteDisconnect,
        ),
        (v1::DisconnectReason::Timeout, DisconnectReason::Timeout),
        (v1::DisconnectReason::LinkError, DisconnectReason::LinkError),
        (
            v1::DisconnectReason::NodeShutdown,
            DisconnectReason::NodeShutdown,
        ),
        (v1::DisconnectReason::Admin, DisconnectReason::Admin),
    ];

    /// The error codes that map 1:1. `UnknownStatusCode` and `Fail` are handled
    /// separately by `error_code_lossy_variants_collapse_to_internal`.
    const ERROR_CODE_PAIRS: [(v1::ErrorCode, ErrorCode); 11] = [
        (v1::ErrorCode::Internal, ErrorCode::Internal),
        (v1::ErrorCode::AuthRequired, ErrorCode::AuthRequired),
        (v1::ErrorCode::InvalidOperation, ErrorCode::InvalidOperation),
        (v1::ErrorCode::OutOfSync, ErrorCode::OutOfSync),
        (v1::ErrorCode::NotFound, ErrorCode::NotFound),
        (v1::ErrorCode::InvalidSignature, ErrorCode::InvalidSignature),
        (v1::ErrorCode::QuotaExceeded, ErrorCode::QuotaExceeded),
        (
            v1::ErrorCode::TemporarilyUnavailable,
            ErrorCode::TemporarilyUnavailable,
        ),
        (v1::ErrorCode::AuthError, ErrorCode::AuthError),
        (v1::ErrorCode::ParamError, ErrorCode::ParamError),
        (v1::ErrorCode::PolicyDenied, ErrorCode::PolicyDenied),
    ];

    /// Never called. Exists so that adding a variant to one of the enums above
    /// fails to compile until the matching table is extended.
    #[allow(dead_code)]
    fn exhaustiveness_guard(deny: &DenyCode, reason: &DisconnectReason, err: &ErrorCode) {
        match deny {
            DenyCode::NoReason
            | DenyCode::NoMatch
            | DenyCode::Denied
            | DenyCode::SourceNotFound
            | DenyCode::DestNotFound
            | DenyCode::SourceAuthError
            | DenyCode::DestAuthError
            | DenyCode::QuotaExceeded
            | DenyCode::NoRoute => {}
        }
        match reason {
            DisconnectReason::RemoteDisconnect
            | DisconnectReason::Timeout
            | DisconnectReason::LinkError
            | DisconnectReason::NodeShutdown
            | DisconnectReason::Admin => {}
        }
        match err {
            ErrorCode::Internal
            | ErrorCode::AuthRequired
            | ErrorCode::InvalidOperation
            | ErrorCode::OutOfSync
            | ErrorCode::NotFound
            | ErrorCode::InvalidSignature
            | ErrorCode::QuotaExceeded
            | ErrorCode::TemporarilyUnavailable
            | ErrorCode::AuthError
            | ErrorCode::ParamError
            | ErrorCode::PolicyDenied
            | ErrorCode::UnknownStatusCode
            | ErrorCode::Fail => {}
        }
    }

    #[test]
    fn deny_code_maps_each_variant_in_both_directions() {
        for (capnp_code, native_code) in DENY_CODE_PAIRS {
            assert_eq!(
                DenyCode::from(capnp_code),
                native_code,
                "decoding {capnp_code:?}"
            );
            assert_eq!(
                v1::VisaDenyCode::from(native_code),
                capnp_code,
                "encoding {capnp_code:?}"
            );
        }
    }

    #[test]
    fn disconnect_reason_maps_each_variant_in_both_directions() {
        for (capnp_reason, native_reason) in DISCONNECT_REASON_PAIRS {
            assert_eq!(
                DisconnectReason::from(capnp_reason),
                native_reason,
                "decoding {capnp_reason:?}"
            );
            assert_eq!(
                v1::DisconnectReason::from(native_reason),
                capnp_reason,
                "encoding {capnp_reason:?}"
            );
        }
    }

    #[test]
    fn error_code_maps_each_shared_variant_in_both_directions() {
        for (capnp_code, native_code) in ERROR_CODE_PAIRS {
            assert_eq!(
                ErrorCode::from(capnp_code),
                native_code,
                "decoding {capnp_code:?}"
            );
            let encoded: v1::ErrorCode = native_code.into();
            assert_eq!(encoded, capnp_code, "encoding {capnp_code:?}");
        }
    }

    /// `UnknownStatusCode` and `Fail` have no capnp counterpart, so they widen to
    /// `Internal` on the way out and cannot round-trip back.
    #[test]
    fn error_code_lossy_variants_collapse_to_internal() {
        for lossy in [ErrorCode::UnknownStatusCode, ErrorCode::Fail] {
            let encoded: v1::ErrorCode = lossy.clone().into();
            assert_eq!(encoded, v1::ErrorCode::Internal, "encoding {lossy:?}");
            assert_ne!(ErrorCode::from(encoded), lossy, "{lossy:?} is not 1:1");
        }
    }

    #[test]
    fn connection_new_converts_expiry_to_unix_seconds() {
        let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let expires = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);

        let conn = Connection::new(addr, expires);

        assert_eq!(conn.zpr_addr, addr);
        assert_eq!(conn.auth_expires, 1_700_000_000);
    }

    /// Sub-second precision is dropped rather than rounded up.
    #[test]
    fn connection_new_truncates_sub_second_expiry() {
        let addr = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let expires = SystemTime::UNIX_EPOCH + Duration::from_millis(1_999);

        let conn = Connection::new(addr, expires);

        assert_eq!(conn.auth_expires, 1);
    }

    /// A pre-epoch expiry is unrepresentable on the wire. It must fail closed to
    /// "already expired" rather than panic the caller.
    #[test]
    fn connection_new_treats_pre_epoch_expiry_as_expired() {
        let addr = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let expires = SystemTime::UNIX_EPOCH - Duration::from_secs(60);

        let conn = Connection::new(addr, expires);

        assert_eq!(conn.auth_expires, 0);
    }

    #[test]
    fn visa_decision_passes_denial_through() {
        let denied = Denied::new(DenyCode::QuotaExceeded, Some("over limit".to_string()));
        let response = VisaResponse::Denied(denied);

        let decision = VisaDecision::try_from(response).expect("denial is a valid decision");

        match decision {
            VisaDecision::Denied(d) => {
                assert_eq!(d.code, DenyCode::QuotaExceeded);
                assert_eq!(d.reason.as_deref(), Some("over limit"));
            }
            other => panic!("expected Denied, got {other:?}"),
        }
    }

    /// An error response is not a decision at all; it must surface as `Err`.
    #[test]
    fn visa_decision_rejects_error_response() {
        let api_err = ApiResponseError::new(ErrorCode::AuthRequired, "need auth", 30);
        let response = VisaResponse::VsapiTypeError(api_err);

        let err = VisaDecision::try_from(response).expect_err("error is not a decision");

        assert_eq!(err.code, ErrorCode::AuthRequired);
        assert_eq!(err.message, "need auth");
        assert_eq!(err.retry_in, 30);
    }

    #[test]
    fn deny_code_and_disconnect_reason_display_as_variant_names() {
        assert_eq!(DenyCode::SourceAuthError.to_string(), "SourceAuthError");
        assert_eq!(DisconnectReason::NodeShutdown.to_string(), "NodeShutdown");
    }
}
