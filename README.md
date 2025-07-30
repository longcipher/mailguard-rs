# MailGuard-RS

🛡️ A fast temporary email and malicious domain detection library using SURBL DNS queries

[中文文档](README.zh.md)

## Features

- ⚡ **Fast Detection**: Quick temporary email detection via SURBL DNS queries
- 🔍 **Threat Classification**: Identify different threat types (spam, phishing, malware, etc.) based on DNS responses
- 🚀 **Async Support**: Tokio-based asynchronous DNS queries
- 💾 **Smart Caching**: Built-in cache mechanism to avoid duplicate queries
- 📦 **Batch Processing**: Support for batch detection of multiple emails or domains
- 🎯 **Type Safety**: Full Rust type system support

## How It Works

This library detects temporary emails and malicious domains by querying DNS A records for `domain.tempmail.so.multi.surbl.org`. If the query returns an IP address in the `127.0.0.x` range, it indicates the domain is blacklisted.

### Threat Type Classification

Threat types are determined by the last octet of the returned IP address:

| Last Octet | Threat Type | Severity | Description |
|------------|-------------|----------|-------------|
| 2, 9       | Spam        | 2        | Spam source |
| 3          | Phishing    | 4        | Phishing website |
| 4, 6, 7, 11| Malware     | 5        | Malware |
| 5          | Botnet      | 4        | Botnet |
| 10         | PUP         | 1        | Potentially Unwanted Program |

## Quick Start

Add the following to your `Cargo.toml`:

```toml
[dependencies]
mailguard-rs = "0.1.0"
tokio = { version = "1.0", features = ["full"] }
```

### Features

This library supports optional features:

- `cache` - Enable LRU caching functionality (disabled by default)

To enable caching:

```toml
[dependencies]
mailguard-rs = { version = "0.1.0", features = ["cache"] }
tokio = { version = "1.0", features = ["full"] }
```

### Basic Usage

```rust
use mailguard_rs::check_email;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Check a single email
    let status = check_email("test@10minutemail.com").await?;
    
    if status.is_threat {
        println!("⚠️  Detected temporary email: {}", status.email);
        if let Some(threat_type) = &status.threat_type {
            println!("Threat type: {} (Level: {})", 
                threat_type.description(), 
                threat_type.severity_level()
            );
        }
    } else {
        println!("✅ Email is safe: {}", status.email);
    }
    
    Ok(())
}
```

### Advanced Usage

```rust
use mailguard_rs::{MailGuard, MailGuardConfig};
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create detector with custom configuration
    let config = MailGuardConfig {
        dns_timeout: Duration::from_secs(3),
        enable_cache: true,
        cache_ttl: Duration::from_secs(600), // 10 minutes cache
    };
    
    let detector = MailGuard::with_config(config);
    
    // Batch detection
    let emails = vec![
        "user1@gmail.com",
        "user2@10minutemail.com",
        "user3@guerrillamail.com",
    ];
    
    let results = detector.check_emails_batch(&emails).await;
    
    for (email, result) in emails.iter().zip(results.iter()) {
        match result {
            Ok(status) => {
                let cache_indicator = if status.from_cache { " [cached]" } else { "" };
                println!("{}: {} {}", 
                    email,
                    if status.is_threat { "⚠️ Temporary" } else { "✅ Safe" },
                    cache_indicator
                );
            }
            Err(e) => {
                println!("{}: ❌ Error: {}", email, e);
            }
        }
    }
    
    // Show cache statistics
    if let Some(cache_size) = detector.cache_stats() {
        println!("Cache entries: {}", cache_size);
    }
    
    Ok(())
}
```

### Domain-Only Detection

```rust
use mailguard_rs::check_domain;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let status = check_domain("mailinator.com").await?;
    
    if status.is_threat {
        println!("⚠️  Malicious domain: {}", status.domain);
    } else {
        println!("✅ Domain is safe: {}", status.domain);
    }
    
    Ok(())
}
```

## API Documentation

### Structs

#### `EmailStatus`
```rust
pub struct EmailStatus {
    pub email: String,              // Email address
    pub domain: String,             // Domain name
    pub is_threat: bool,            // Whether it's a threat
    pub threat_type: Option<ThreatType>, // Threat type if any
    pub from_cache: bool,           // Whether result is from cache
}
```

#### `DomainStatus`
```rust
pub struct DomainStatus {
    pub domain: String,             // Domain name
    pub is_threat: bool,            // Whether it's a threat
    pub threat_type: Option<ThreatType>, // Threat type if any
    pub from_cache: bool,           // Whether result is from cache
}
```

#### `ThreatType`
```rust
pub enum ThreatType {
    Spam,                           // Spam source
    Phishing,                       // Phishing website
    Malware,                        // Malware
    Botnet,                         // Botnet
    Pup,                           // Potentially Unwanted Program
    Unknown(u8),                   // Unknown threat type
}
```

### Main Functions

- `check_email(email: &str) -> Result<EmailStatus, MailGuardError>`
- `check_domain(domain: &str) -> Result<DomainStatus, MailGuardError>`
- `check_emails_batch(emails: &[&str]) -> Vec<Result<EmailStatus, MailGuardError>>`

## Running Examples

```bash
# Clone the repository
git clone https://github.com/longcipher/mailguard-rs.git
cd mailguard-rs

# Run the main example
cargo run

# Run simple example
cargo run --example simple_usage

# Run advanced example
cargo run --example advanced_usage

# Run tests
cargo test
```

## Performance Characteristics

- **DNS Queries**: Default timeout of 5 seconds
- **Caching**: Default TTL of 5 minutes
- **Memory Usage**: Low memory footprint with LRU cache strategy
- **Concurrency**: Supports high-concurrency async queries

## Error Handling

```rust
use mailguard_rs::{check_email, MailGuardError};

match check_email("invalid-email").await {
    Ok(status) => println!("Detection result: {:?}", status),
    Err(MailGuardError::InvalidEmail(email)) => {
        println!("Invalid email format: {}", email);
    }
    Err(MailGuardError::DnsError(e)) => {
        println!("DNS query failed: {}", e);
    }
    Err(e) => {
        println!("Other error: {}", e);
    }
}
```

## Configuration

### `MailGuardConfig`
```rust
pub struct MailGuardConfig {
    pub dns_timeout: Duration,      // DNS query timeout (default: 5s)
    pub enable_cache: bool,         // Enable caching (default: true)
    pub cache_ttl: Duration,        // Cache TTL (default: 5 minutes)
}
```

## Dependencies

- `tokio` - Async runtime
- `trust-dns-resolver` - DNS queries
- `regex` - Email validation
- `thiserror` - Error handling
- `serde` - Serialization support
- `lru` - Cache implementation
- `tracing` - Structured logging support

## License

Apache-2.0 License

## Contributing

Issues and Pull Requests are welcome!

## Related Projects

- [SURBL](https://www.surbl.org/) - URI DNS Blacklist Service

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for detailed version history.

## Support

If you find this project helpful, please consider giving it a ⭐ on GitHub!
