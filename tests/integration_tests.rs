use std::time::Duration;

use mailguard_rs::{MailGuard, MailGuardConfig, ThreatType, check_domain, check_email};

#[tokio::test]
async fn test_valid_email_format() {
    let result = check_email("test@example.com").await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_invalid_email_format() {
    let result = check_email("invalid-email").await;
    assert!(result.is_err());

    let result = check_email("@example.com").await;
    assert!(result.is_err());

    let result = check_email("test@").await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_domain_validation() {
    let result = check_domain("").await;
    assert!(result.is_err());

    let result = check_domain(".example.com").await;
    assert!(result.is_err());

    let result = check_domain("example..com").await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_threat_type_classification() {
    assert_eq!(ThreatType::from_ip_last_octet(2), ThreatType::Spam);
    assert_eq!(ThreatType::from_ip_last_octet(3), ThreatType::Phishing);
    assert_eq!(ThreatType::from_ip_last_octet(4), ThreatType::Malware);
    assert_eq!(ThreatType::from_ip_last_octet(5), ThreatType::Botnet);
    assert_eq!(ThreatType::from_ip_last_octet(10), ThreatType::Pup);

    match ThreatType::from_ip_last_octet(255) {
        ThreatType::Unknown(255) => (),
        _ => panic!("Expected Unknown threat type"),
    }
}

#[tokio::test]
async fn test_threat_type_severity() {
    assert_eq!(ThreatType::Malware.severity_level(), 5);
    assert_eq!(ThreatType::Phishing.severity_level(), 4);
    assert_eq!(ThreatType::Botnet.severity_level(), 4);
    assert_eq!(ThreatType::Spam.severity_level(), 2);
    assert_eq!(ThreatType::Pup.severity_level(), 1);
}

#[cfg(feature = "cache")]
#[tokio::test]
async fn test_cache_functionality() {
    let config = MailGuardConfig {
        dns_timeout: Duration::from_secs(5),
        enable_cache: true,
        cache_ttl: Duration::from_secs(300),
    };

    let detector = MailGuard::with_config(config);

    // 第一次查询
    let result1 = detector.check_domain("example.com").await;
    assert!(result1.is_ok());
    assert!(!result1.unwrap().from_cache);

    // 第二次查询应该来自缓存
    let result2 = detector.check_domain("example.com").await;
    assert!(result2.is_ok());
    assert!(result2.unwrap().from_cache);
}

#[tokio::test]
async fn test_batch_processing() {
    let detector = MailGuard::new();

    let emails = vec!["test1@example.com", "test2@example.org", "invalid-email"];

    let results = detector.check_emails_batch(&emails).await;
    assert_eq!(results.len(), 3);

    // 前两个应该成功，第三个应该失败
    assert!(results[0].is_ok());
    assert!(results[1].is_ok());
    assert!(results[2].is_err());
}

#[tokio::test]
async fn test_email_domain_extraction() {
    let detector = MailGuard::new();

    let result = detector.check_email("user@sub.example.com").await;
    assert!(result.is_ok());

    let status = result.unwrap();
    assert_eq!(status.domain, "sub.example.com");
    assert_eq!(status.email, "user@sub.example.com");
}

#[cfg(feature = "cache")]
#[tokio::test]
async fn test_cache_stats() {
    let detector = MailGuard::new();

    // 初始缓存应该为空
    assert_eq!(detector.cache_stats(), Some(0));

    // 执行一次查询
    let _ = detector.check_domain("example.com").await;

    // 缓存应该有一个条目
    assert_eq!(detector.cache_stats(), Some(1));

    // 清空缓存
    detector.clear_cache();
    assert_eq!(detector.cache_stats(), Some(0));
}

#[tokio::test]
async fn test_disabled_cache() {
    let config = MailGuardConfig {
        dns_timeout: Duration::from_secs(5),
        enable_cache: false,
        cache_ttl: Duration::from_secs(300),
    };

    let detector = MailGuard::with_config(config);

    // 没有缓存时应该返回 None 或 Some(0)
    let cache_stats = detector.cache_stats();
    assert!(cache_stats.is_none() || cache_stats == Some(0));

    let result = detector.check_domain("example.com").await;
    assert!(result.is_ok());
    assert!(!result.unwrap().from_cache);
}

#[tokio::test]
async fn test_threat_descriptions() {
    assert_eq!(ThreatType::Spam.description(), "Spam Source");
    assert_eq!(ThreatType::Phishing.description(), "Phishing Website");
    assert_eq!(ThreatType::Malware.description(), "Malware");
    assert_eq!(ThreatType::Botnet.description(), "Botnet");
    assert_eq!(
        ThreatType::Pup.description(),
        "Potentially Unwanted Program"
    );
    assert_eq!(ThreatType::Unknown(42).description(), "Unknown Threat Type");
}
