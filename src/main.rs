use mailguard_rs::{MailGuard, check_domain, check_email};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    println!("🛡️  MailGuard-RS Temporary Email Detection Tool");
    println!("================================================");

    // Test some known temporary email domains
    let test_emails = vec![
        "test@gmail.com",         // Normal email
        "user@10minutemail.com",  // Temporary email
        "temp@guerrillamail.com", // Temporary email
        "example@mailinator.com", // Temporary email
        "valid@outlook.com",      // Normal email
    ];

    println!("\n📧 Testing Email Detection:");
    println!("--------------------------");

    for email in &test_emails {
        match check_email(email).await {
            Ok(status) => {
                let threat_info = if status.is_threat {
                    if let Some(threat_type) = &status.threat_type {
                        format!(
                            " (⚠️  {description}: {level})",
                            description = threat_type.description(),
                            level = threat_type.severity_level()
                        )
                    } else {
                        " (⚠️  Unknown Threat)".to_string()
                    }
                } else {
                    " (✅ Safe)".to_string()
                };

                let cache_info = if status.from_cache { " [Cached]" } else { "" };

                println!(
                    "  {} -> {}{}{}",
                    email,
                    if status.is_threat {
                        "Temp Email"
                    } else {
                        "Normal Email"
                    },
                    threat_info,
                    cache_info
                );
            }
            Err(e) => {
                println!("  {email} -> Error: {e}");
            }
        }
    }

    // Test domain detection
    let test_domains = vec![
        "gmail.com",
        "10minutemail.com",
        "guerrillamail.com",
        "mailinator.com",
    ];

    println!("\n🌐 Testing Domain Detection:");
    println!("---------------------------");

    for domain in &test_domains {
        match check_domain(domain).await {
            Ok(status) => {
                let threat_info = if status.is_threat {
                    if let Some(threat_type) = &status.threat_type {
                        format!(
                            " (⚠️  {description}: Level {level})",
                            description = threat_type.description(),
                            level = threat_type.severity_level()
                        )
                    } else {
                        " (⚠️  Unknown Threat)".to_string()
                    }
                } else {
                    " (✅ Safe)".to_string()
                };

                let cache_info = if status.from_cache { " [Cached]" } else { "" };

                println!(
                    "  {} -> {}{}{}",
                    domain,
                    if status.is_threat {
                        "Malicious Domain"
                    } else {
                        "Normal Domain"
                    },
                    threat_info,
                    cache_info
                );
            }
            Err(e) => {
                println!("  {domain} -> Error: {e}");
            }
        }
    }

    // Test batch detection
    println!("\n📦 Testing Batch Detection:");
    println!("----------------------------");

    let detector = MailGuard::new();
    let batch_results = detector.check_emails_batch(&test_emails).await;

    for (email, result) in test_emails.iter().zip(batch_results.iter()) {
        match result {
            Ok(status) => {
                println!(
                    "  {} -> {} (cached: {})",
                    email,
                    if status.is_threat { "⚠️ " } else { "✅" },
                    status.from_cache
                );
            }
            Err(e) => {
                println!("  {email} -> ❌ {e}");
            }
        }
    }

    // Display cache statistics
    if let Some(cache_size) = detector.cache_stats() {
        println!("\n📊 Cache Statistics: {cache_size} entries");
    }

    println!("\n✨ Detection Complete!");

    Ok(())
}
