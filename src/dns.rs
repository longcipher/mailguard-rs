use std::{net::Ipv4Addr, time::Duration};

use trust_dns_resolver::{TokioAsyncResolver, config::*};

use crate::{
    error::{MailGuardError, Result},
    threat::ThreatType,
};

/// DNS query client
pub struct DnsClient {
    resolver: TokioAsyncResolver,
}

impl DnsClient {
    /// Create a new DNS client
    pub fn new() -> Self {
        let resolver =
            TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());

        Self { resolver }
    }

    /// Create a DNS client with custom timeout
    pub fn with_timeout(timeout: Duration) -> Self {
        let mut opts = ResolverOpts::default();
        opts.timeout = timeout;

        let resolver = TokioAsyncResolver::tokio(ResolverConfig::default(), opts);

        Self { resolver }
    }

    /// Query domain SURBL status
    ///
    /// Query format: domain.tempmail.so.multi.surbl.org
    pub async fn query_surbl(&self, domain: &str) -> Result<Option<ThreatType>> {
        let surbl_domain = format!("{domain}.tempmail.so.multi.surbl.org");

        tracing::debug!("Querying SURBL: {surbl_domain}");
        match self.resolver.lookup_ip(&surbl_domain).await {
            Ok(response) => {
                // Check if there are A records pointing to 127.0.0.x
                for ip in response.iter() {
                    if let std::net::IpAddr::V4(ipv4) = ip
                        && self.is_surbl_positive_response(ipv4)
                    {
                        let threat_type = ThreatType::from_ip_last_octet(ipv4.octets()[3]);
                        tracing::info!("Detected threat domain: {domain} -> {threat_type:?}");
                        return Ok(Some(threat_type));
                    }
                }

                tracing::debug!("Domain {domain} not found in SURBL");
                Ok(None)
            }
            Err(err) => {
                // DNS query failure usually indicates domain is not in blacklist
                match err.kind() {
                    trust_dns_resolver::error::ResolveErrorKind::NoRecordsFound { .. } => {
                        tracing::debug!("Domain {domain} not in SURBL blacklist");
                        Ok(None)
                    }
                    _ => {
                        tracing::warn!("DNS query failed: {surbl_domain} - {err}");
                        Err(MailGuardError::DnsError(err))
                    }
                }
            }
        }
    }

    /// Check if IP is a SURBL positive response (127.0.0.x)
    fn is_surbl_positive_response(&self, ip: Ipv4Addr) -> bool {
        let octets = ip.octets();
        octets[0] == 127 && octets[1] == 0 && octets[2] == 0 && octets[3] > 1
    }

    /// Validate domain format
    pub fn validate_domain(&self, domain: &str) -> Result<()> {
        if domain.is_empty() {
            return Err(MailGuardError::InvalidDomain(
                "Domain cannot be empty".to_string(),
            ));
        }

        if domain.len() > 253 {
            return Err(MailGuardError::InvalidDomain(
                "Domain length exceeds limit".to_string(),
            ));
        }

        // Simple domain format validation
        if !domain
            .chars()
            .all(|c| c.is_alphanumeric() || c == '.' || c == '-')
        {
            return Err(MailGuardError::InvalidDomain(format!(
                "Invalid domain characters: {domain}"
            )));
        }

        if domain.starts_with('.') || domain.ends_with('.') || domain.contains("..") {
            return Err(MailGuardError::InvalidDomain(format!(
                "Invalid domain format: {domain}"
            )));
        }

        Ok(())
    }
}

impl Default for DnsClient {
    fn default() -> Self {
        Self::new()
    }
}
