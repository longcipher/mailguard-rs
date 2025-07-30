# GitHub Copilot Instructions for MailGuard-RS

## Project Overview

MailGuard-RS is a high-performance Rust library for detecting temporary emails and malicious domains using SURBL DNS queries. This library provides async functionality, smart caching, and threat classification capabilities.

## Architecture & Key Concepts

### Core Components

- **`src/lib.rs`**: Main library interface with convenience functions (`check_email`, `check_domain`, `check_emails_batch`)
- **`src/detector.rs`**: Primary `MailGuard` struct with configurable detection logic
- **`src/dns.rs`**: DNS client using `trust-dns-resolver` for SURBL queries
- **`src/threat.rs`**: Threat type classification based on DNS response IP addresses
- **`src/cache.rs`**: Conditional LRU cache implementation (feature-gated)
- **`src/error.rs`**: Comprehensive error handling with `thiserror`

### Key Design Patterns

1. **Conditional Compilation**: Cache functionality is feature-gated with `#[cfg(feature = "cache")]`
2. **Async-First**: All public APIs use `async`/`await` with Tokio runtime
3. **Result Types**: Consistent use of `Result<T, MailGuardError>` for error handling
4. **Structured Logging**: Uses `tracing` crate for observability
5. **DNS-Based Detection**: Queries `domain.tempmail.so.multi.surbl.org` for threat classification

### SURBL Integration

- **Query Format**: `{domain}.tempmail.so.multi.surbl.org`
- **Response Interpretation**: IP addresses in `127.0.0.x` range indicate threats
- **Threat Mapping**: Last octet determines threat type (e.g., 2/9=Spam, 3=Phishing, 4/6/7/11=Malware)

## Development Guidelines

### Code Style & Standards

- **Edition**: Rust 2024 with latest language features
- **Formatting**: Use `just format` (cargo +nightly fmt + taplo fmt)
- **Linting**: Use `just lint` with strict clippy rules and machete for unused deps
- **Testing**: Comprehensive test coverage via `just test`

### Language & Internationalization

- **English Only**: All code, comments, error messages, and logs must be in English
- **No Chinese Text**: Ensure complete internationalization compliance
- **Documentation**: Maintain both `README.md` (English) and `README.zh.md` (Chinese)

### Feature Management

```toml
[features]
default = []
cache = ["lru"]  # Optional LRU caching
```

- Default build has no caching
- Enable with `features = ["cache"]` in dependencies
- Use conditional compilation for cache-related code

### Error Handling Patterns

```rust
// Use thiserror for error definitions
#[derive(Debug, thiserror::Error)]
pub enum MailGuardError {
    #[error("DNS query failed: {0}")]
    DnsError(#[from] trust_dns_resolver::error::ResolveError),
    
    #[error("Invalid email format: {0}")]
    InvalidEmail(String),
    
    #[error("Invalid domain format: {0}")]
    InvalidDomain(String),
}
```

### Async Patterns

```rust
// Prefer tokio::spawn for concurrent operations
pub async fn check_emails_batch(&self, emails: &[&str]) -> Vec<Result<EmailStatus, MailGuardError>> {
    let mut results = Vec::with_capacity(emails.len());
    for email in emails {
        let result = self.check_email(email).await;
        results.push(result);
    }
    results
}
```

### Logging Best Practices

```rust
// Use appropriate log levels
tracing::debug!("Querying SURBL: {surbl_domain}");
tracing::info!("Detected threat domain: {domain} -> {threat_type:?}");
tracing::warn!("DNS query failed: {surbl_domain} - {err}");
```

## API Design Principles

### Public Interface

1. **Convenience Functions**: Top-level functions for simple use cases
2. **Configurable Detector**: `MailGuard` struct for advanced configuration
3. **Batch Operations**: Support for bulk processing
4. **Type Safety**: Strong typing with custom structs (`EmailStatus`, `DomainStatus`)

### Configuration Options

```rust
pub struct MailGuardConfig {
    pub dns_timeout: Duration,     // DNS query timeout
    pub enable_cache: bool,        // Enable/disable caching
    pub cache_ttl: Duration,       // Cache time-to-live
}
```

### Return Types

```rust
pub struct EmailStatus {
    pub email: String,
    pub domain: String,
    pub is_threat: bool,
    pub threat_type: Option<ThreatType>,
    pub from_cache: bool,
}
```

## Common Implementation Patterns

### DNS Client Usage

```rust
// Always validate domain format first
self.dns_client.validate_domain(domain)?;

// Query SURBL with proper error handling
match self.dns_client.query_surbl(&domain).await {
    Ok(threat_type) => { /* handle result */ },
    Err(err) => { /* handle DNS errors */ },
}
```

### Cache Integration

```rust
// Check cache first (if enabled)
if let Some(cache) = &self.cache
    && let Some(cached_threat) = cache.get(&domain)
{
    return Ok(/* cached result */);
}

// Update cache after DNS query
if let Some(cache) = &self.cache {
    cache.set(domain.clone(), threat_type.clone());
}
```

### Email Validation

```rust
// Use regex for email format validation
let email_regex = Regex::new(
    r"^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$"
).expect("Invalid email regex");

if !self.email_regex.is_match(email) {
    return Err(MailGuardError::InvalidEmail(email.to_string()));
}
```

## Testing Strategy

### Test Structure

- **`tests/integration_tests.rs`**: End-to-end functionality tests
- **`tests/cache_tests.rs`**: Cache-specific functionality tests
- **Unit Tests**: Embedded in modules where appropriate

### Example Test Patterns

```rust
#[tokio::test]
async fn test_check_email_valid() {
    let detector = MailGuard::new();
    let result = detector.check_email("user@gmail.com").await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_invalid_email_format() {
    let detector = MailGuard::new();
    let result = detector.check_email("invalid-email").await;
    assert!(matches!(result, Err(MailGuardError::InvalidEmail(_))));
}
```

## Dependencies & Tooling

### Core Dependencies

- **`tokio`**: Async runtime with full features
- **`trust-dns-resolver`**: DNS resolution
- **`regex`**: Email validation
- **`thiserror`**: Error handling
- **`serde`**: Serialization support
- **`tracing`**: Structured logging
- **`lru`**: Optional caching (feature-gated)

### Development Tools

- **`just`**: Task runner for common operations
- **`taplo`**: TOML formatting
- **`cargo-machete`**: Unused dependency detection
- **Nightly Rust**: Required for formatting and advanced clippy lints

## Examples & Usage

### Simple Usage Pattern

```rust
use mailguard_rs::check_email;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let status = check_email("test@tempmail.com").await?;
    if status.is_threat {
        println!("⚠️  Detected threat: {}", status.email);
    }
    Ok(())
}
```

### Advanced Configuration

```rust
use mailguard_rs::{MailGuard, MailGuardConfig};

let config = MailGuardConfig {
    dns_timeout: Duration::from_secs(3),
    enable_cache: true,
    cache_ttl: Duration::from_secs(600),
};

let detector = MailGuard::with_config(config);
```

## Common Pitfalls & Solutions

### 1. Chinese Text in Code
❌ **Wrong**: Comments or strings in Chinese
✅ **Correct**: All text in English

### 2. Feature Gate Usage
❌ **Wrong**: Using cache without feature check
✅ **Correct**: Wrap cache code in `#[cfg(feature = "cache")]`

### 3. Error Handling
❌ **Wrong**: Using `unwrap()` or `expect()` in library code
✅ **Correct**: Proper error propagation with `?` operator

### 4. DNS Query Patterns
❌ **Wrong**: Treating all DNS errors as threats
✅ **Correct**: Distinguish between network errors and "not found" responses

## Future Development

### Planned Features
- Metrics collection support
- Additional threat intelligence sources
- Performance optimizations
- WebAssembly support

### Extension Points
- Custom threat classification rules
- Pluggable cache implementations
- Alternative DNS providers
- Custom validation patterns

---

Remember: This library prioritizes performance, safety, and ease of use. Always consider the async nature of operations, proper error handling, and the conditional compilation model when making changes.
