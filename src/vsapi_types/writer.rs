use std::net::IpAddr;

use crate::vsapi::v1;
use crate::vsapi_types::{
    ApiResponseError, AuthBlob, ChallengeAlg, Claim, CommFlag, ConnectRequest, Connection, DockPep,
    DockPepType, EndpointT, FwdPep, FwdPepStyle, IcmpPep, KeySet, Link, LinkRole, LinkStateReport,
    LoginNonce, PacketDesc, Param, ParamValue, PublicKey, ReauthRequest, ServiceDescriptor,
    ServiceT, SockAddr, TcpUdpPep, VSConnectRequest, Visa, VisaOp, VisaType,
};
use crate::write_to::WriteTo;

impl WriteTo<v1::sock_addr::Builder<'_>> for SockAddr {
    fn write_to(&self, bldr: &mut v1::sock_addr::Builder<'_>) {
        let mut addr_bldr = bldr.reborrow().init_addr();
        self.addr.write_to(&mut addr_bldr);
        bldr.set_port(self.port);
    }
}

impl WriteTo<v1::link::Builder<'_>> for Link {
    fn write_to(&self, bldr: &mut v1::link::Builder<'_>) {
        bldr.set_link_id(&self.link_id);
        let mut peer_bldr = bldr.reborrow().init_peer();
        self.peer.write_to(&mut peer_bldr);
        bldr.set_role(match self.role {
            LinkRole::Active => v1::LinkRole::Active,
            LinkRole::Backup => v1::LinkRole::Backup,
        });
        let mut zpr_addr_bldr = bldr.reborrow().init_zpr_addr();
        self.zpr_addr.write_to(&mut zpr_addr_bldr);
        bldr.set_peer_cn(&self.peer_cn);
        let mut visas_bldr = bldr.reborrow().init_visas(self.visas.len() as u32);
        for (i, visa) in self.visas.iter().enumerate() {
            let mut visa_bldr = visas_bldr.reborrow().get(i as u32);
            visa.write_to(&mut visa_bldr);
        }
    }
}

impl WriteTo<v1::link_state_report::Builder<'_>> for LinkStateReport {
    fn write_to(&self, bldr: &mut v1::link_state_report::Builder<'_>) {
        bldr.set_peer_cn(&self.peer_cn);
        bldr.set_state(self.state.into());
    }
}

impl WriteTo<v1::login_nonce::Builder<'_>> for LoginNonce {
    fn write_to(&self, bldr: &mut v1::login_nonce::Builder<'_>) {
        bldr.set_nonce(&self.nonce);
        bldr.set_expires_at(self.expires_at_secs());
    }
}

impl WriteTo<v1::ip_addr::Builder<'_>> for IpAddr {
    fn write_to(&self, bldr: &mut v1::ip_addr::Builder<'_>) {
        match self {
            IpAddr::V4(ipv4) => {
                let v4_buf = bldr.reborrow().init_v4(4);
                v4_buf.copy_from_slice(&ipv4.octets());
            }
            IpAddr::V6(ipv6) => {
                let v6_buf = bldr.reborrow().init_v6(16);
                v6_buf.copy_from_slice(&ipv6.octets());
            }
        }
    }
}

// Write out a visa to a Cap'n Proto builder.
impl WriteTo<v1::visa::Builder<'_>> for Visa {
    fn write_to(&self, bldr: &mut v1::visa::Builder<'_>) {
        bldr.set_issuer_id(self.issuer_id);
        bldr.set_expiration(self.get_expiration_timestamp());

        match self.visa_type {
            VisaType::Full => bldr.set_visa_type(v1::VisaType::Full),
            VisaType::ForwardOnly => bldr.set_visa_type(v1::VisaType::ForwardOnly),
        }

        if let Some(dock_pep) = &self.dock_pep {
            let mut dock_pep_bldr = bldr.reborrow().init_dock_pep();
            dock_pep.write_to(&mut dock_pep_bldr);
        }

        if let Some(fpep) = &self.fwd_pep {
            let mut fwd_pep_bldr = bldr.reborrow().init_fwd_pep();
            fpep.write_to(&mut fwd_pep_bldr);
        }

        if self.cons.is_some() {
            unimplemented!("visa constraints serialization not implemented yet");
        }
    }
}

impl WriteTo<v1::fwd_pep::Builder<'_>> for FwdPep {
    fn write_to(&self, bldr: &mut v1::fwd_pep::Builder<'_>) {
        let mut ip_bldr = bldr.reborrow().init_next_hop();
        self.next_hop.write_to(&mut ip_bldr);

        match self.style {
            FwdPepStyle::Symmetric => bldr.set_symmetric(true),
            FwdPepStyle::OneWay => bldr.set_symmetric(false),
        }
    }
}

impl WriteTo<v1::dock_pep::Builder<'_>> for DockPep {
    fn write_to(&self, bldr: &mut v1::dock_pep::Builder<'_>) {
        let mut ip_bldr = bldr.reborrow().init_source_addr();
        self.source_addr.write_to(&mut ip_bldr);
        let mut ip_bldr = bldr.reborrow().init_dest_addr();
        self.dest_addr.write_to(&mut ip_bldr);
        let mut keyset_bldr = bldr.reborrow().init_session_key();
        self.session_key.write_to(&mut keyset_bldr);

        match &self.pep {
            DockPepType::TCP(pep) => {
                let mut tcp_bldr = bldr.reborrow().init_tcp();
                pep.write_to(&mut tcp_bldr);
            }
            DockPepType::UDP(pep) => {
                let mut udp_bldr = bldr.reborrow().init_udp();
                pep.write_to(&mut udp_bldr);
            }
            DockPepType::ICMP(pep) => {
                let mut icmp_bldr = bldr.reborrow().init_icmp();
                pep.write_to(&mut icmp_bldr);
            }
        }
    }
}

impl WriteTo<v1::dock_pep_tcp_udp::Builder<'_>> for TcpUdpPep {
    fn write_to(&self, bldr: &mut v1::dock_pep_tcp_udp::Builder<'_>) {
        bldr.set_source_port(self.source_port);
        bldr.set_dest_port(self.dest_port);
        match self.endpoint {
            EndpointT::Any => bldr.set_endpoint(v1::EndpointT::Any),
            EndpointT::Server => bldr.set_endpoint(v1::EndpointT::Server),
            EndpointT::Client => bldr.set_endpoint(v1::EndpointT::Client),
        }
    }
}

impl WriteTo<v1::dock_pep_icmp::Builder<'_>> for IcmpPep {
    fn write_to(&self, bldr: &mut v1::dock_pep_icmp::Builder<'_>) {
        let typecode: u16 = ((self.icmp_type as u16) << 8) | (self.icmp_code as u16);
        bldr.set_icmp_type_code(typecode);
    }
}

impl WriteTo<v1::key_set::Builder<'_>> for KeySet {
    fn write_to(&self, bldr: &mut v1::key_set::Builder<'_>) {
        bldr.set_format(v1::KeyFormat::ZprKF01);
        bldr.set_ingress_key(&self.ingress_key);
        bldr.set_egress_key(&self.egress_key);
    }
}

impl WriteTo<v1::public_key::Builder<'_>> for PublicKey {
    fn write_to(&self, bldr: &mut v1::public_key::Builder<'_>) {
        bldr.set_format(v1::KeyFormat::ZprKF01);
        bldr.set_public_key(&self.public_key);
    }
}

impl WriteTo<v1::packet_desc::Builder<'_>> for PacketDesc {
    fn write_to(&self, bldr: &mut v1::packet_desc::Builder<'_>) {
        let mut ip_bldr = bldr.reborrow().init_source_addr();
        self.source_addr().write_to(&mut ip_bldr);
        let mut ip_bldr = bldr.reborrow().init_dest_addr();
        self.dest_addr().write_to(&mut ip_bldr);
        bldr.set_protocol(self.protocol());
        bldr.set_source_port(self.source_port());
        bldr.set_dest_port(self.dest_port());
        match self.comm_flags {
            CommFlag::BiDirectional => bldr.set_comm_type(v1::CommType::Bidirectional),
            CommFlag::UniDirectional => bldr.set_comm_type(v1::CommType::Unidirectional),
            CommFlag::ReRequest(_) => bldr.set_comm_type(v1::CommType::Rerequest),
        }
    }
}

impl WriteTo<v1::visa_op::Builder<'_>> for VisaOp {
    fn write_to(&self, bldr: &mut v1::visa_op::Builder<'_>) {
        match self {
            VisaOp::Grant(v) => {
                let mut grant_bldr = bldr.reborrow().init_grant();
                v.write_to(&mut grant_bldr);
            }
            VisaOp::RevokeVisaId(id) => {
                bldr.set_revoke_visa_id(*id);
            }
        }
    }
}

impl WriteTo<v1::service_descriptor::Builder<'_>> for ServiceDescriptor {
    fn write_to(&self, bldr: &mut v1::service_descriptor::Builder<'_>) {
        let stype = match self.stype {
            ServiceT::ActorAuthentication => v1::ServiceT::ActorAuthentication,
            ServiceT::OidcAuthentication => v1::ServiceT::OidcAuthentication,
        };
        bldr.set_stype(stype);
        bldr.set_service_id(self.service_id.clone());
        bldr.set_service_uri(self.service_uri.clone());
        let mut ip_bldr = bldr.reborrow().init_zpr_addr();
        self.zpr_addr.write_to(&mut ip_bldr);

        // Only initialise the oidc pointer when a config is present, so it reads
        // back as has_oidc() == false otherwise.
        if let Some(oidc) = &self.oidc {
            let mut oidc_bldr = bldr.reborrow().init_oidc();
            oidc_bldr.set_issuer(&oidc.issuer);
            oidc_bldr.set_client_id(&oidc.client_id);
            // None is encoded as "" on the wire (Contract 2).
            oidc_bldr.set_client_secret(oidc.client_secret.as_deref().unwrap_or(""));
            let mut scopes = oidc_bldr.reborrow().init_scopes(oidc.scopes.len() as u32);
            for (i, s) in oidc.scopes.iter().enumerate() {
                scopes.set(i as u32, s);
            }
            oidc_bldr.set_allow_offline_access(oidc.allow_offline_access);
        }
    }
}

impl WriteTo<v1::error::Builder<'_>> for ApiResponseError {
    fn write_to(&self, bldr: &mut v1::error::Builder<'_>) {
        bldr.set_code(self.code.clone().into());
        bldr.set_message(&self.message);
        bldr.set_retry_in(self.retry_in);
    }
}

impl WriteTo<v1::connection::Builder<'_>> for Connection {
    fn write_to(&self, bldr: &mut v1::connection::Builder<'_>) {
        let mut ip_bldr = bldr.reborrow().init_zpr_addr();
        self.zpr_addr.write_to(&mut ip_bldr);
        bldr.set_auth_expires(self.auth_expires as u64);
    }
}

impl WriteTo<v1::claim::Builder<'_>> for Claim {
    fn write_to(&self, bldr: &mut v1::claim::Builder<'_>) {
        bldr.set_key(&self.key);
        bldr.set_value(&self.value);
    }
}

impl WriteTo<v1::auth_blob::Builder<'_>> for AuthBlob {
    fn write_to(&self, bldr: &mut v1::auth_blob::Builder<'_>) {
        match self {
            AuthBlob::SS(ss) => {
                let mut ss_bldr = bldr.reborrow().init_ss();
                let alg = match ss.alg {
                    ChallengeAlg::RsaSha256Pkcs1v15 => v1::ChallengeAlg::RsaSha256Pkcs1v15,
                };
                ss_bldr.set_alg(alg);
                ss_bldr.set_challenge(&ss.challenge);
                ss_bldr.set_cn(&ss.cn);
                ss_bldr.set_timestamp(ss.timestamp);
                ss_bldr.set_signature(&ss.signature);
            }
            AuthBlob::AC(ac) => {
                let mut ac_bldr = bldr.reborrow().init_ac();
                let mut ip_bldr = ac_bldr.reborrow().init_asa_addr();
                ac.asa_addr.write_to(&mut ip_bldr);
                ac_bldr.set_code(&ac.code);
                ac_bldr.set_pkce(&ac.pkce);
                ac_bldr.set_client_id(&ac.client_id);
            }
            AuthBlob::Oidc(oidc) => {
                let mut oidc_bldr = bldr.reborrow().init_oidc();
                oidc_bldr.set_issuer(&oidc.issuer);
                oidc_bldr.set_id_token(&oidc.id_token);
                oidc_bldr.set_nonce(&oidc.nonce);
            }
        }
    }
}

impl WriteTo<v1::connect_request::Builder<'_>> for ConnectRequest {
    fn write_to(&self, bldr: &mut v1::connect_request::Builder<'_>) {
        let mut blobs_bldr = bldr.reborrow().init_blobs(self.blobs.len() as u32);
        for (i, blob) in self.blobs.iter().enumerate() {
            let mut blob_bldr = blobs_bldr.reborrow().get(i as u32);
            blob.write_to(&mut blob_bldr);
        }
        let mut claims_bldr = bldr.reborrow().init_claims(self.claims.len() as u32);
        for (i, claim) in self.claims.iter().enumerate() {
            let mut claim_bldr = claims_bldr.reborrow().get(i as u32);
            claim.write_to(&mut claim_bldr);
        }
        let mut ip_bldr = bldr.reborrow().init_substrate_addr();
        self.substrate_addr.write_to(&mut ip_bldr);
        bldr.set_dock_interface(self.dock_interface);
        let mut key_bldr = bldr.reborrow().init_a2a_dh_public_key();
        self.a2a_dh_public_key.write_to(&mut key_bldr);
    }
}

impl WriteTo<v1::reauth_request::Builder<'_>> for ReauthRequest {
    fn write_to(&self, bldr: &mut v1::reauth_request::Builder<'_>) {
        let mut ip_bldr = bldr.reborrow().init_zpr_addr();
        self.zpr_addr.write_to(&mut ip_bldr);
        let mut blobs_bldr = bldr.reborrow().init_blobs(self.blobs.len() as u32);
        for (i, blob) in self.blobs.iter().enumerate() {
            let mut blob_bldr = blobs_bldr.reborrow().get(i as u32);
            blob.write_to(&mut blob_bldr);
        }
    }
}

impl WriteTo<v1::v_s_connect_request::Builder<'_>> for VSConnectRequest {
    fn write_to(&self, bldr: &mut v1::v_s_connect_request::Builder<'_>) {
        bldr.set_cn(&self.cn);
        bldr.set_ctype(self.ctype.into());
        if let Some(params) = &self.params {
            let mut params_bldr = bldr.reborrow().init_params(params.len() as u32);
            for (i, param) in params.iter().enumerate() {
                let mut param_bldr = params_bldr.reborrow().get(i as u32);
                param.write_to(&mut param_bldr);
            }
        }
    }
}

impl WriteTo<v1::param::Builder<'_>> for Param {
    fn write_to(&self, bldr: &mut v1::param::Builder<'_>) {
        bldr.set_name(&self.name);

        match &self.value {
            ParamValue::StrParam(s) => {
                bldr.set_ptype(v1::ParamT::String);
                bldr.set_value_text(s);
            }
            ParamValue::IpParam(ipa) => match ipa {
                IpAddr::V4(addr) => {
                    bldr.set_ptype(v1::ParamT::Ipv4);
                    bldr.set_value_data(&addr.octets());
                }
                IpAddr::V6(addr) => {
                    bldr.set_ptype(v1::ParamT::Ipv6);
                    bldr.set_value_data(&addr.octets());
                }
            },
            ParamValue::U64Param(val) => {
                bldr.set_ptype(v1::ParamT::U64);
                bldr.set_value_u64(*val);
            }
            ParamValue::X25519PubKey(pubkey) => {
                bldr.set_ptype(v1::ParamT::X25519Pubkey);
                bldr.set_value_data(pubkey.as_bytes());
            }
        }
    }
}
