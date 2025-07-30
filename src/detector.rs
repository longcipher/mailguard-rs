use std::time::Duration;

use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::{
    cache::Cache,
    dns::DnsClient,
    error::{MailGuardError, Result},
    threat::ThreatType,
};

/// Email detection status
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmailStatus {
    /// Email address
    pub email: String,
    /// Domain
    pub domain: String,
    /// Whether it's a temporary email or malicious domain
    pub is_threat: bool,
    /// Threat type (if exists)
    pub threat_type: Option<ThreatType>,
    /// Whether from cache
    pub from_cache: bool,
}

/// Domain detection status
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DomainStatus {
    /// Domain
    pub domain: String,
    /// Whether it's a malicious domain
    pub is_threat: bool,
    /// Threat type (if exists)
    pub threat_type: Option<ThreatType>,
    /// Whether from cache
    pub from_cache: bool,
}

/// Email detector configuration
#[derive(Debug, Clone)]
pub struct MailGuardConfig {
    /// DNS query timeout
    pub dns_timeout: Duration,
    /// 是否启用缓存
    pub enable_cache: bool,
    /// 缓存 TTL
    pub cache_ttl: Duration,
}

impl Default for MailGuardConfig {
    fn default() -> Self {
        Self {
            dns_timeout: Duration::from_secs(5),
            enable_cache: true,
            cache_ttl: Duration::from_secs(300), // 5分钟
        }
    }
}

/// 主要的邮箱检测器
pub struct MailGuard {
    dns_client: DnsClient,
    cache: Option<Cache>,
    email_regex: Regex,
    #[allow(dead_code)]
    config: MailGuardConfig,
}

impl MailGuard {
    /// 创建新的检测器实例
    pub fn new() -> Self {
        Self::with_config(MailGuardConfig::default())
    }

    /// 使用自定义配置创建检测器
    pub fn with_config(config: MailGuardConfig) -> Self {
        let dns_client = DnsClient::with_timeout(config.dns_timeout);
        let cache = if config.enable_cache {
            Some(Cache::with_ttl(config.cache_ttl))
        } else {
            None
        };

        // 邮箱格式验证正则表达式
        let email_regex = Regex::new(
            r"^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$"
        ).expect("Invalid email regex");

        Self {
            dns_client,
            cache,
            email_regex,
            config,
        }
    }

    /// 检查单个邮箱地址
    pub async fn check_email(&self, email: &str) -> Result<EmailStatus> {
        // 验证邮箱格式
        if !self.email_regex.is_match(email) {
            return Err(MailGuardError::InvalidEmail(email.to_string()));
        }

        // 提取域名
        let domain = self.extract_domain(email)?;

        // 检查域名
        let domain_status = self.check_domain(&domain).await?;

        Ok(EmailStatus {
            email: email.to_string(),
            domain: domain_status.domain,
            is_threat: domain_status.is_threat,
            threat_type: domain_status.threat_type,
            from_cache: domain_status.from_cache,
        })
    }

    /// 检查域名
    pub async fn check_domain(&self, domain: &str) -> Result<DomainStatus> {
        // 验证域名格式
        self.dns_client.validate_domain(domain)?;

        let domain = domain.to_lowercase();

        // 检查缓存
        if let Some(cache) = &self.cache
            && let Some(cached_threat) = cache.get(&domain)
        {
            return Ok(DomainStatus {
                domain: domain.clone(),
                is_threat: cached_threat.is_some(),
                threat_type: cached_threat,
                from_cache: true,
            });
        }

        // 执行 DNS 查询
        let threat_type = self.dns_client.query_surbl(&domain).await?;

        // 更新缓存
        if let Some(cache) = &self.cache {
            cache.set(domain.clone(), threat_type.clone());
        }

        Ok(DomainStatus {
            domain,
            is_threat: threat_type.is_some(),
            threat_type,
            from_cache: false,
        })
    }

    /// 批量检查邮箱
    pub async fn check_emails_batch(&self, emails: &[&str]) -> Vec<Result<EmailStatus>> {
        let mut results = Vec::with_capacity(emails.len());

        for email in emails {
            let result = self.check_email(email).await;
            results.push(result);
        }

        results
    }

    /// 批量检查域名
    pub async fn check_domains_batch(&self, domains: &[&str]) -> Vec<Result<DomainStatus>> {
        let mut results = Vec::with_capacity(domains.len());

        for domain in domains {
            let result = self.check_domain(domain).await;
            results.push(result);
        }

        results
    }

    /// 从邮箱地址提取域名
    fn extract_domain(&self, email: &str) -> Result<String> {
        if let Some(at_pos) = email.rfind('@') {
            let domain = &email[at_pos + 1..];
            if domain.is_empty() {
                return Err(MailGuardError::InvalidEmail("邮箱域名为空".to_string()));
            }
            Ok(domain.to_string())
        } else {
            Err(MailGuardError::InvalidEmail("邮箱格式无效".to_string()))
        }
    }

    /// 清理缓存中的过期条目
    pub fn cleanup_cache(&self) {
        if let Some(cache) = &self.cache {
            cache.cleanup_expired();
        }
    }

    /// 获取缓存统计信息
    pub fn cache_stats(&self) -> Option<usize> {
        self.cache.as_ref().map(|cache| cache.size())
    }

    /// 清空缓存
    pub fn clear_cache(&self) {
        if let Some(cache) = &self.cache {
            cache.clear();
        }
    }
}

impl Default for MailGuard {
    fn default() -> Self {
        Self::new()
    }
}
