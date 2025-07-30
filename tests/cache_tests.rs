#[cfg(feature = "cache")]
use std::time::Duration;

#[cfg(feature = "cache")]
use mailguard_rs::ThreatType;
#[cfg(feature = "cache")]
use mailguard_rs::cache::{Cache, CacheEntry};

#[cfg(feature = "cache")]
#[test]
fn test_cache_creation() {
    let cache = Cache::new();
    assert_eq!(cache.size(), 0);
}

#[cfg(feature = "cache")]
#[test]
fn test_cache_with_custom_ttl() {
    let ttl = Duration::from_secs(60);
    let cache = Cache::with_ttl(ttl);
    assert_eq!(cache.size(), 0);
}

#[cfg(feature = "cache")]
#[test]
fn test_cache_set_and_get() {
    let cache = Cache::new();

    // 设置一个条目
    cache.set("example.com".to_string(), Some(ThreatType::Spam));
    assert_eq!(cache.size(), 1);

    // 获取条目
    let result = cache.get("example.com");
    assert!(result.is_some());
    assert_eq!(result.unwrap(), Some(ThreatType::Spam));
}

#[cfg(feature = "cache")]
#[test]
fn test_cache_get_nonexistent() {
    let cache = Cache::new();
    let result = cache.get("nonexistent.com");
    assert!(result.is_none());
}

#[cfg(feature = "cache")]
#[test]
fn test_cache_clear() {
    let cache = Cache::new();

    cache.set("example1.com".to_string(), Some(ThreatType::Spam));
    cache.set("example2.com".to_string(), None);
    assert_eq!(cache.size(), 2);

    cache.clear();
    assert_eq!(cache.size(), 0);
}

#[cfg(feature = "cache")]
#[test]
fn test_cache_entry_expiration() {
    let ttl = Duration::from_millis(1);
    let entry = CacheEntry::new(Some(ThreatType::Spam), ttl);

    // 立即检查应该未过期
    assert!(!entry.is_expired());

    // 等待一下
    std::thread::sleep(Duration::from_millis(10));

    // 现在应该过期了
    assert!(entry.is_expired());
}

#[cfg(feature = "cache")]
#[test]
fn test_cache_cleanup_expired() {
    let cache = Cache::with_ttl(Duration::from_millis(1));

    // 添加一些条目
    cache.set("example1.com".to_string(), Some(ThreatType::Spam));
    cache.set("example2.com".to_string(), None);
    assert_eq!(cache.size(), 2);

    // 等待过期
    std::thread::sleep(Duration::from_millis(10));

    // 清理过期条目
    cache.cleanup_expired();
    assert_eq!(cache.size(), 0);
}

#[cfg(feature = "cache")]
#[test]
fn test_cache_thread_safety() {
    use std::{sync::Arc, thread};

    let cache = Arc::new(Cache::new());
    let mut handles = vec![];

    // 启动多个线程同时写入缓存
    for i in 0..10 {
        let cache_clone = Arc::clone(&cache);
        let handle = thread::spawn(move || {
            let key = format!("example{}.com", i);
            cache_clone.set(key, Some(ThreatType::Spam));
        });
        handles.push(handle);
    }

    // 等待所有线程完成
    for handle in handles {
        handle.join().unwrap();
    }

    // 验证所有条目都已添加
    assert_eq!(cache.size(), 10);
}
