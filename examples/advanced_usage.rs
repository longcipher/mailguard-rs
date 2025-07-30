use std::time::Duration;

use mailguard_rs::{MailGuard, MailGuardConfig, ThreatType};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    println!("🔍 MailGuard-RS Advanced Example");
    println!("=================================");

    // Create detector with custom configuration
    let config = MailGuardConfig {
        dns_timeout: Duration::from_secs(3),
        enable_cache: true,
        cache_ttl: Duration::from_secs(600), // 10-minute cache
    };

    let detector = MailGuard::with_config(config);

    // Test a series of email addresses
    let test_cases = vec![
        (
            "正常邮箱",
            vec!["user@example.com", "test@google.com", "admin@microsoft.com"],
        ),
        (
            "可疑域名",
            vec![
                "temp@tempmail.org",
                "test@guerrillamail.com",
                "user@mailinator.com",
                "fake@10minutemail.com",
            ],
        ),
        (
            "无效格式",
            vec![
                "invalid-email",
                "@missing-user.com",
                "missing-domain@",
                "double@@domain.com",
            ],
        ),
    ];

    for (category, emails) in test_cases {
        println!("\n📂 {} ({} 个):", category, emails.len());
        println!("{}", "-".repeat(50));

        for email in emails {
            match detector.check_email(email).await {
                Ok(status) => {
                    let threat_indicator = if status.is_threat { "⚠️ " } else { "✅" };
                    let cache_indicator = if status.from_cache {
                        " [缓存]"
                    } else {
                        " [查询]"
                    };

                    if let Some(threat_type) = &status.threat_type {
                        println!(
                            "  {} {} -> {} (等级: {}, 类型: {}){}",
                            threat_indicator,
                            email,
                            threat_type.description(),
                            threat_type.severity_level(),
                            format!("{:?}", threat_type),
                            cache_indicator
                        );
                    } else {
                        println!(
                            "  {} {} -> 安全{}",
                            threat_indicator, email, cache_indicator
                        );
                    }
                }
                Err(e) => {
                    println!("  ❌ {} -> 错误: {}", email, e);
                }
            }
        }

        // 显示当前缓存状态
        if let Some(cache_size) = detector.cache_stats() {
            println!("    💾 缓存条目: {}", cache_size);
        }
    }

    // 演示威胁类型功能
    println!("\n🎯 威胁类型详细信息:");
    println!("===================");

    let threat_types = vec![
        ThreatType::Spam,
        ThreatType::Phishing,
        ThreatType::Malware,
        ThreatType::Botnet,
        ThreatType::Pup,
        ThreatType::Unknown(42),
    ];

    for threat_type in threat_types {
        println!(
            "  {:?}: {} (等级: {})",
            threat_type,
            threat_type.description(),
            threat_type.severity_level()
        );
    }

    // 演示IP分类功能
    println!("\n🔢 IP 分类示例:");
    println!("================");

    for octet in [2, 3, 4, 5, 6, 7, 9, 10, 11, 42, 255] {
        let threat_type = ThreatType::from_ip_last_octet(octet);
        println!(
            "  127.0.0.{} -> {:?} ({})",
            octet,
            threat_type,
            threat_type.description()
        );
    }

    // 批量测试性能
    println!("\n⚡ 批量处理性能测试:");
    println!("=====================");

    let batch_emails = vec![
        "test1@example.com",
        "test2@gmail.com",
        "temp1@tempmail.org",
        "temp2@guerrillamail.com",
        "user@mailinator.com",
    ];

    let start = std::time::Instant::now();
    let results = detector.check_emails_batch(&batch_emails).await;
    let duration = start.elapsed();

    println!("  处理 {} 个邮箱用时: {:?}", batch_emails.len(), duration);
    println!("  平均每个邮箱: {:?}", duration / batch_emails.len() as u32);

    let mut threats_found = 0;
    let mut cache_hits = 0;
    for result in &results {
        if let Ok(status) = result {
            if status.is_threat {
                threats_found += 1;
            }
            if status.from_cache {
                cache_hits += 1;
            }
        }
    }

    println!("  发现威胁: {} 个", threats_found);
    println!("  缓存命中: {} 个", cache_hits);

    // 缓存管理演示
    println!("\n💾 缓存管理:");
    println!("=============");

    println!("  当前缓存大小: {:?}", detector.cache_stats());

    // 清理过期条目
    detector.cleanup_cache();
    println!("  清理后缓存大小: {:?}", detector.cache_stats());

    // 清空缓存
    detector.clear_cache();
    println!("  清空后缓存大小: {:?}", detector.cache_stats());

    println!("\n✨ 示例完成!");
    Ok(())
}
