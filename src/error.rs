/// MailGuard error types
#[derive(Debug, thiserror::Error)]
pub enum MailGuardError {
    #[error("DNS query failed: {0}")]
    DnsError(#[from] trust_dns_resolver::error::ResolveError),

    #[error("Invalid email format: {0}")]
    InvalidEmail(String),

    #[error("Invalid domain format: {0}")]
    InvalidDomain(String),
}

pub type Result<T> = std::result::Result<T, MailGuardError>;
