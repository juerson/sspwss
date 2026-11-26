//! DNS 缓存 + singleflight 并发去重。
//!
//! 缓存语义（shoes dns_tuning 文档 + clash-rs 实践）：
//! - 仅缓存成功且非空的结果；NXDOMAIN/NODATA/SERVFAIL 等不缓存
//!   （但会把响应码原样返回给调用方，监听器据此回正确的 rcode）；
//! - TTL 取上游响应里的最小记录 TTL，钳制上限（默认 300s）；
//! - 并发同域查询单飞合并：所有 miss 参与者共享一次上游查询的结果；
//! - 应用层缓存条目独立过期，不回写上游（应用缓存 ≠ DNS TTL）。

use super::{DnsAnswer, DnsResult};
use ahash::AHashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex as StdMutex};
use std::time::{Duration, Instant};
use tokio::sync::oneshot;

const DEFAULT_TTL_CAP: Duration = Duration::from_secs(300);
const MAX_ENTRIES: usize = 4096;
/// follower 等待 leader 完成的上限：略大于上游交换超时（10s）。
const LEADER_WAIT_CAP: Duration = Duration::from_secs(11);

#[derive(Debug, Clone)]
struct CacheEntry {
    ips: Vec<IpAddr>,
    inserted: Instant,
    ttl: Duration,
}

impl CacheEntry {
    fn is_expired(&self) -> bool {
        self.inserted.elapsed() >= self.ttl
    }

    /// 剩余 TTL（至少 1s），用于把缓存命中回给客户端时给出合理 TTL。
    fn remaining(&self) -> Duration {
        self.ttl
            .saturating_sub(self.inserted.elapsed())
            .max(Duration::from_secs(1))
    }
}

/// singleflight 共享状态：leader 写 result 并唤醒所有 waiter（全部在同一把锁下，无竞态窗口）。
#[derive(Debug)]
struct Inflight {
    result: Option<Arc<DnsResult<DnsAnswer>>>,
    waiters: Vec<oneshot::Sender<Arc<DnsResult<DnsAnswer>>>>,
}

#[derive(Debug, Default)]
pub struct DnsCache {
    entries: StdMutex<AHashMap<String, CacheEntry>>,
    inflight: StdMutex<AHashMap<String, Arc<StdMutex<Inflight>>>>,
    ttl_cap: Duration,
    /// follower 等待 leader 的上限；超时认为 leader 已死（被取消），接管重查。
    wait_cap: StdMutex<Duration>,
}

impl DnsCache {
    pub fn new() -> Self {
        Self {
            ttl_cap: DEFAULT_TTL_CAP,
            wait_cap: StdMutex::new(LEADER_WAIT_CAP),
            ..Default::default()
        }
    }

    /// 仅供测试调整 follower 等待上限。
    #[cfg(test)]
    pub fn set_wait_cap(&self, cap: Duration) {
        *self.wait_cap.lock().unwrap() = cap;
    }

    fn lookup(&self, name: &str) -> Option<(Vec<IpAddr>, Duration)> {
        let mut map = self.entries.lock().unwrap();
        if let Some(entry) = map.get(name) {
            if !entry.is_expired() {
                return Some((entry.ips.clone(), entry.remaining()));
            }
            map.remove(name);
        }
        None
    }

    fn store(&self, name: &str, ips: &[IpAddr], ttl: Duration) {
        if ips.is_empty() {
            return; // 空结果不缓存
        }
        let mut map = self.entries.lock().unwrap();
        if map.len() >= MAX_ENTRIES {
            // 先清过期；仍满则不再缓存新条目（等待自然淘汰）
            map.retain(|_, v| !v.is_expired());
            if map.len() >= MAX_ENTRIES {
                return;
            }
        }
        let ttl = ttl.min(self.ttl_cap).max(Duration::from_secs(1));
        map.insert(
            name.to_string(),
            CacheEntry {
                ips: ips.to_vec(),
                inserted: Instant::now(),
                ttl,
            },
        );
    }

    /// 缓存优先 + singleflight。`task` 只应由 leader 执行一次。
    ///
    /// 成功且非空的答案在这里统一写缓存（TTL 来自上游响应），
    /// 失败/NXDOMAIN/NODATA 只透传、不缓存。
    pub async fn resolve_via<F>(&self, name: &str, task: F) -> DnsResult<DnsAnswer>
    where
        F: std::future::Future<Output = DnsResult<DnsAnswer>>,
    {
        if let Some((ips, ttl)) = self.lookup(name) {
            return Ok(DnsAnswer::positive(ips, ttl));
        }

        let (shared, is_leader) = {
            let mut inflight = self.inflight.lock().unwrap();
            if let Some(state) = inflight.get(name) {
                (state.clone(), false)
            } else {
                let state = Arc::new(StdMutex::new(Inflight {
                    result: None,
                    waiters: Vec::new(),
                }));
                inflight.insert(name.to_string(), state.clone());
                (state, true)
            }
        };

        if is_leader {
            let result = Arc::new(task.await);
            if let Ok(answer) = result.as_ref() {
                if answer.is_positive() {
                    self.store(name, &answer.ips, answer.ttl);
                }
            }
            {
                let mut inner = shared.lock().unwrap();
                inner.result = Some(result.clone());
                // 唤醒所有在 leader 执行期间加入的 follower
                for tx in inner.waiters.drain(..) {
                    let _ = tx.send(result.clone());
                }
            }
            self.inflight.lock().unwrap().remove(name);
            (*result).clone()
        } else {
            // follower：在持锁状态下登记（避免错过唤醒），然后限时等待 leader
            let rx = {
                let mut inner = shared.lock().unwrap();
                if let Some(result) = &inner.result {
                    let (tx, rx) = oneshot::channel();
                    let _ = tx.send(result.clone());
                    rx
                } else {
                    let (tx, rx) = oneshot::channel();
                    inner.waiters.push(tx);
                    rx
                }
            };
            let wait_cap = *self.wait_cap.lock().unwrap();
            match tokio::time::timeout(wait_cap, rx).await {
                Ok(Ok(result)) => (*result).clone(),
                // leader 被取消/卡死（inflight 残留）：清掉残留并自己执行任务
                _ => {
                    {
                        let mut inflight = self.inflight.lock().unwrap();
                        if inflight
                            .get(name)
                            .map(|s| Arc::ptr_eq(s, &shared))
                            .unwrap_or(false)
                        {
                            inflight.remove(name);
                        }
                    }
                    task.await
                }
            }
        }
    }

    /// 直接写入（测试 / 预置条目用）。
    pub fn store_with_ttl(&self, name: &str, ips: &[IpAddr], ttl: Duration) {
        self.store(name, ips, ttl);
    }

    /// 当前有效条目数（测试用）。
    #[cfg(test)]
    pub fn entry_count(&self) -> usize {
        self.entries.lock().unwrap().len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    fn ips(v: &[&str]) -> Vec<IpAddr> {
        v.iter().map(|s| s.parse().unwrap()).collect()
    }

    fn answer(v: &[&str], ttl: u64) -> DnsResult<DnsAnswer> {
        Ok(DnsAnswer::positive(ips(v), Duration::from_secs(ttl)))
    }

    #[tokio::test]
    async fn caches_success_only() {
        let cache = DnsCache::new();
        cache.store_with_ttl("a.com", &ips(&["1.1.1.1"]), Duration::from_secs(60));
        assert_eq!(cache.entry_count(), 1);
        cache.store_with_ttl("b.com", &[], Duration::from_secs(60));
        assert_eq!(cache.entry_count(), 1, "empty result must not be cached");
    }

    #[tokio::test]
    async fn cache_hit_avoids_task() {
        let cache = DnsCache::new();
        cache.store_with_ttl("a.com", &ips(&["1.1.1.1"]), Duration::from_secs(60));
        let hit = cache
            .resolve_via("a.com", async { panic!("must not run") })
            .await
            .unwrap();
        assert_eq!(hit.ips, ips(&["1.1.1.1"]));
        assert_eq!(hit.rcode, hickory_proto::op::ResponseCode::NoError);
    }

    #[tokio::test]
    async fn singleflight_dedupes_concurrent_queries() {
        let cache = Arc::new(DnsCache::new());
        let counter = Arc::new(AtomicU32::new(0));

        let mut handles = Vec::new();
        for _ in 0..20 {
            let cache = cache.clone();
            let counter = counter.clone();
            handles.push(tokio::spawn(async move {
                cache
                    .resolve_via("x.com", async {
                        counter.fetch_add(1, Ordering::SeqCst);
                        // 模拟上游延迟，让 follower 有机会加入
                        tokio::time::sleep(Duration::from_millis(20)).await;
                        answer(&["2.2.2.2"], 60)
                    })
                    .await
                    .unwrap()
            }));
        }
        for h in handles {
            h.await.unwrap();
        }
        assert_eq!(
            counter.load(Ordering::SeqCst),
            1,
            "upstream hit exactly once"
        );
        // 成功答案由 leader 自动写缓存，后续命中不再打上游
        assert_eq!(cache.entry_count(), 1);
        let hit = cache
            .resolve_via("x.com", async { panic!("must not run") })
            .await
            .unwrap();
        assert_eq!(hit.ips, ips(&["2.2.2.2"]));
        assert_eq!(counter.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn failure_not_cached_and_shared() {
        let cache = Arc::new(DnsCache::new());
        let mut handles = Vec::new();
        for _ in 0..5 {
            let cache = cache.clone();
            handles.push(tokio::spawn(async move {
                cache
                    .resolve_via("fail.com", async {
                        tokio::time::sleep(Duration::from_millis(10)).await;
                        Err(super::super::DnsError("nxdomain".into()))
                    })
                    .await
            }));
        }
        for h in handles {
            assert!(h.await.unwrap().is_err());
        }
        assert_eq!(cache.entry_count(), 0, "failure must not be cached");
    }

    #[tokio::test]
    async fn negative_answers_are_returned_but_not_cached() {
        let cache = DnsCache::new();
        let ans = cache
            .resolve_via("nope.com", async {
                Ok(DnsAnswer::negative(
                    hickory_proto::op::ResponseCode::NXDomain,
                ))
            })
            .await
            .unwrap();
        assert_eq!(ans.rcode, hickory_proto::op::ResponseCode::NXDomain);
        assert!(ans.ips.is_empty());
        assert_eq!(cache.entry_count(), 0);
    }

    #[tokio::test]
    async fn follower_survives_leader_abort() {
        // leader 被 drop（Future 被 cancel）后 inflight 残留，follower 应在
        // wait_cap 内接管并自己重查，而不是永久卡死
        let cache = Arc::new(DnsCache::new());
        cache.set_wait_cap(Duration::from_millis(200));

        // 创建 leader 但立即取消
        {
            let cache = cache.clone();
            let leader = tokio::spawn(async move {
                cache
                    .resolve_via("y.com", async {
                        tokio::time::sleep(Duration::from_secs(5)).await;
                        answer(&["3.3.3.3"], 60)
                    })
                    .await
            });
            tokio::time::sleep(Duration::from_millis(20)).await;
            leader.abort();
        }
        // inflight 残留：follower 加入后 leader 永不完成 → 超时接管自查
        let result = cache
            .resolve_via("y.com", async { answer(&["3.3.3.3"], 60) })
            .await
            .unwrap();
        assert_eq!(result.ips, ips(&["3.3.3.3"]));
    }
}
