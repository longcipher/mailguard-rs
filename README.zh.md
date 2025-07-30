# MailGuard-RS

🛡️ 一个快速检测临时邮箱和恶意域名的 Rust 库

[English Documentation](README.md)

## 功能特性

- ⚡ **快速检测**: 通过 SURBL DNS 查询快速判断临时邮箱
- 🔍 **威胁分类**: 根据 DNS 响应识别不同类型的威胁（垃圾邮件、钓鱼、恶意软件等）
- 🚀 **异步支持**: 基于 Tokio 的异步 DNS 查询
- 💾 **智能缓存**: 内置缓存机制，避免重复查询
- 📦 **批量处理**: 支持批量检测多个邮箱或域名
- 🎯 **类型安全**: 完整的 Rust 类型系统支持

## 工作原理

本库通过查询 `域名.tempmail.so.multi.surbl.org` 的 DNS A 记录来判断域名是否为临时邮箱或恶意域名。如果查询返回 `127.0.0.x` 的 IP 地址，则表示该域名在黑名单中。

### 威胁类型分类

根据返回 IP 地址的最后一位数字判断威胁类型：

| IP 最后一位 | 威胁类型 | 严重等级 | 描述 |
|------------|----------|----------|------|
| 2, 9       | Spam     | 2        | 垃圾邮件源 |
| 3          | Phishing | 4        | 钓鱼网站 |
| 4, 6, 7, 11| Malware  | 5        | 恶意软件 |
| 5          | Botnet   | 4        | 僵尸网络 |
| 10         | PUP      | 1        | 潜在不需要的程序 |

## 快速开始

将以下内容添加到你的 `Cargo.toml`：

```toml
[dependencies]
mailguard-rs = "0.1.0"
tokio = { version = "1.0", features = ["full"] }
```

### 功能特性 (Features)

此库支持可选的功能特性：

- `cache` - 启用 LRU 缓存功能（默认禁用）

启用缓存功能：

```toml
[dependencies]
mailguard-rs = { version = "0.1.0", features = ["cache"] }
tokio = { version = "1.0", features = ["full"] }
```

### 基本用法

```rust
use mailguard_rs::check_email;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 检查单个邮箱
    let status = check_email("test@10minutemail.com").await?;
    
    if status.is_threat {
        println!("⚠️  检测到临时邮箱: {}", status.email);
        if let Some(threat_type) = &status.threat_type {
            println!("威胁类型: {} (等级: {})", 
                threat_type.description(), 
                threat_type.severity_level()
            );
        }
    } else {
        println!("✅ 邮箱安全: {}", status.email);
    }
    
    Ok(())
}
```

### 高级用法

```rust
use mailguard_rs::{MailGuard, MailGuardConfig};
use std::time::Duration;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 创建自定义配置的检测器
    let config = MailGuardConfig {
        dns_timeout: Duration::from_secs(3),
        enable_cache: true,
        cache_ttl: Duration::from_secs(600), // 10分钟缓存
    };
    
    let detector = MailGuard::with_config(config);
    
    // 批量检测
    let emails = vec![
        "user1@gmail.com",
        "user2@10minutemail.com",
        "user3@guerrillamail.com",
    ];
    
    let results = detector.check_emails_batch(&emails).await;
    
    for (email, result) in emails.iter().zip(results.iter()) {
        match result {
            Ok(status) => {
                let cache_indicator = if status.from_cache { " [缓存]" } else { "" };
                println!("{}: {} {}", 
                    email,
                    if status.is_threat { "⚠️ 临时邮箱" } else { "✅ 安全" },
                    cache_indicator
                );
            }
            Err(e) => {
                println!("{}: ❌ 错误: {}", email, e);
            }
        }
    }
    
    // 显示缓存统计
    if let Some(cache_size) = detector.cache_stats() {
        println!("缓存条目数: {}", cache_size);
    }
    
    Ok(())
}
```

### 仅检测域名

```rust
use mailguard_rs::check_domain;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let status = check_domain("mailinator.com").await?;
    
    if status.is_threat {
        println!("⚠️  恶意域名: {}", status.domain);
    } else {
        println!("✅ 域名安全: {}", status.domain);
    }
    
    Ok(())
}
```

## API 文档

### 结构体

#### `EmailStatus`
```rust
pub struct EmailStatus {
    pub email: String,              // 邮箱地址
    pub domain: String,             // 域名
    pub is_threat: bool,            // 是否为威胁
    pub threat_type: Option<ThreatType>, // 威胁类型
    pub from_cache: bool,           // 是否来自缓存
}
```

#### `DomainStatus`
```rust
pub struct DomainStatus {
    pub domain: String,             // 域名
    pub is_threat: bool,            // 是否为威胁
    pub threat_type: Option<ThreatType>, // 威胁类型
    pub from_cache: bool,           // 是否来自缓存
}
```

#### `ThreatType`
```rust
pub enum ThreatType {
    Spam,                           // 垃圾邮件源
    Phishing,                       // 钓鱼网站
    Malware,                        // 恶意软件
    Botnet,                         // 僵尸网络
    Pup,                           // 潜在不需要的程序
    Unknown(u8),                   // 未知威胁类型
}
```

### 主要函数

- `check_email(email: &str) -> Result<EmailStatus, MailGuardError>`
- `check_domain(domain: &str) -> Result<DomainStatus, MailGuardError>`
- `check_emails_batch(emails: &[&str]) -> Vec<Result<EmailStatus, MailGuardError>>`

## 运行示例

```bash
# 克隆仓库
git clone https://github.com/longcipher/mailguard-rs.git
cd mailguard-rs

# 运行示例
cargo run

# 运行测试
cargo test
```

## 性能特性

- **DNS 查询**: 默认超时 5 秒
- **缓存**: 默认 TTL 5 分钟
- **内存使用**: 低内存占用，LRU 缓存策略
- **并发**: 支持高并发异步查询

## 错误处理

```rust
use mailguard_rs::{check_email, MailGuardError};

match check_email("invalid-email").await {
    Ok(status) => println!("检测结果: {:?}", status),
    Err(MailGuardError::InvalidEmail(email)) => {
        println!("无效的邮箱格式: {}", email);
    }
    Err(MailGuardError::DnsError(e)) => {
        println!("DNS 查询失败: {}", e);
    }
    Err(e) => {
        println!("其他错误: {}", e);
    }
}
```

## 许可证

Apache-2.0 License

## 贡献

欢迎提交 Issue 和 Pull Request！

## 相关项目

- [SURBL](https://www.surbl.org/) - URI DNS 黑名单服务
