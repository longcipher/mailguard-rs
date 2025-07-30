use mailguard_rs::check_email;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🚀 MailGuard-RS Simple Example");
    println!("===============================");

    // Simple email detection
    let emails = vec![
        "user@gmail.com",
        "temp@10minutemail.com",
        "test@guerrillamail.com",
        "admin@mailinator.com",
        "invalid-email",
    ];

    for email in emails {
        match check_email(email).await {
            Ok(status) => {
                if status.is_threat {
                    println!("⚠️  {} -> Temp/Malicious Email", email);
                    if let Some(threat_type) = &status.threat_type {
                        println!(
                            "   Type: {} (Threat Level: {})",
                            threat_type.description(),
                            threat_type.severity_level()
                        );
                    }
                } else {
                    println!("✅ {} -> Safe", email);
                }
            }
            Err(e) => {
                println!("❌ {} -> Error: {}", email, e);
            }
        }
    }

    Ok(())
}
