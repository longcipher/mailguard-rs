//! MailGuard-RS: Fast temporary email detection Rust library
//!
//! Detect temporary emails and malicious domains by querying SURBL DNS records.

pub mod cache;
pub mod detector;
pub mod dns;
pub mod error;
pub mod threat;

pub use detector::{DomainStatus, EmailStatus, MailGuard, MailGuardConfig};
pub use error::MailGuardError;
pub use threat::ThreatType;

/// Check a single email address
///
/// # Example
///
/// ```rust
/// use mailguard_rs::check_email;
///
/// #[tokio::main]
/// async fn main() -> Result<(), Box<dyn std::error::Error>> {
///     let status = check_email("test@tempmail.com").await?;
///     println!("Email status: {:?}", status);
///     Ok(())
/// }
/// ```
pub async fn check_email(email: &str) -> Result<EmailStatus, MailGuardError> {
    let detector = MailGuard::new();
    detector.check_email(email).await
}

/// Check domain
pub async fn check_domain(domain: &str) -> Result<DomainStatus, MailGuardError> {
    let detector = MailGuard::new();
    detector.check_domain(domain).await
}

/// Batch check emails
pub async fn check_emails_batch(emails: &[&str]) -> Vec<Result<EmailStatus, MailGuardError>> {
    let detector = MailGuard::new();
    detector.check_emails_batch(emails).await
}
