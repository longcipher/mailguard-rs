#[cfg(feature = "cache")]
use std::collections::HashMap;
#[cfg(feature = "cache")]
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::threat::ThreatType;

/// 缓存条目
#[derive(Debug, Clone)]
pub struct CacheEntry {
    pub threat_type: Option<ThreatType>,
    pub timestamp: Instant,
    pub ttl: Duration,
}

impl CacheEntry {
    pub fn new(threat_type: Option<ThreatType>, ttl: Duration) -> Self {
        Self {
            threat_type,
            timestamp: Instant::now(),
            ttl,
        }
    }

    pub fn is_expired(&self) -> bool {
        self.timestamp.elapsed() > self.ttl
    }
}

#[cfg(feature = "cache")]
/// 内存缓存 (需要 cache feature)
#[derive(Debug, Clone)]
pub struct Cache {
    inner: Arc<Mutex<HashMap<String, CacheEntry>>>,
    default_ttl: Duration,
}

#[cfg(feature = "cache")]
impl Cache {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
            default_ttl: Duration::from_secs(300), // 5分钟默认TTL
        }
    }

    pub fn with_ttl(ttl: Duration) -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
            default_ttl: ttl,
        }
    }

    /// 获取缓存条目
    pub fn get(&self, key: &str) -> Option<Option<ThreatType>> {
        let mut cache = self.inner.lock().unwrap();

        if let Some(entry) = cache.get(key) {
            if !entry.is_expired() {
                return Some(entry.threat_type.clone());
            } else {
                // 移除过期条目
                cache.remove(key);
            }
        }

        None
    }

    /// 设置缓存条目
    pub fn set(&self, key: String, threat_type: Option<ThreatType>) {
        let entry = CacheEntry::new(threat_type, self.default_ttl);
        let mut cache = self.inner.lock().unwrap();
        cache.insert(key, entry);
    }

    /// 清理过期条目
    pub fn cleanup_expired(&self) {
        let mut cache = self.inner.lock().unwrap();
        cache.retain(|_, entry| !entry.is_expired());
    }

    /// 获取缓存大小
    pub fn size(&self) -> usize {
        let cache = self.inner.lock().unwrap();
        cache.len()
    }

    /// 清空缓存
    pub fn clear(&self) {
        let mut cache = self.inner.lock().unwrap();
        cache.clear();
    }
}

#[cfg(feature = "cache")]
impl Default for Cache {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(not(feature = "cache"))]
/// 无操作缓存实现 (cache feature 未启用)
#[derive(Debug, Clone)]
pub struct Cache;

#[cfg(not(feature = "cache"))]
impl Cache {
    pub fn new() -> Self {
        Cache
    }

    pub fn with_ttl(_ttl: Duration) -> Self {
        Cache
    }

    pub fn get(&self, _key: &str) -> Option<Option<ThreatType>> {
        None
    }

    pub fn set(&self, _key: String, _threat_type: Option<ThreatType>) {
        // 无操作
    }

    pub fn cleanup_expired(&self) {
        // 无操作
    }

    pub fn size(&self) -> usize {
        0
    }

    pub fn clear(&self) {
        // 无操作
    }
}

#[cfg(not(feature = "cache"))]
impl Default for Cache {
    fn default() -> Self {
        Self::new()
    }
}
