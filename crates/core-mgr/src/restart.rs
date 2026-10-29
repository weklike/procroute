// SPDX-License-Identifier: GPL-3.0-or-later
//! 内核异常退出后的重启预算（C-PERF-05）：任意 1 分钟内最多自动重启 3 次，超出即放弃并上报。
//!
//! 纯逻辑、不碰时钟：调用方传入每次崩溃的时刻，便于在任何平台上测试。

use std::collections::VecDeque;
use std::time::{Duration, Instant};

/// 重启策略。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RestartPolicy {
    /// 窗口内最多自动重启的次数。
    pub max_restarts: usize,
    /// 统计窗口。
    pub window: Duration,
    /// 崩溃后等待多久再重启（给 TUN 网卡的撤销留出时间）。
    pub delay: Duration,
    /// 首次启动时等待控制 API 可连接的最长时间。
    pub startup_timeout: Duration,
}

impl Default for RestartPolicy {
    /// C-PERF-05：1 分钟内最多 3 次。
    fn default() -> Self {
        Self {
            max_restarts: 3,
            window: Duration::from_secs(60),
            delay: Duration::from_secs(1),
            startup_timeout: Duration::from_secs(10),
        }
    }
}

/// 滑动窗口内的重启计数。
#[derive(Debug, Clone)]
pub struct RestartBudget {
    max: usize,
    window: Duration,
    restarts: VecDeque<Instant>,
}

impl RestartBudget {
    pub fn new(policy: &RestartPolicy) -> Self {
        Self {
            max: policy.max_restarts,
            window: policy.window,
            restarts: VecDeque::with_capacity(policy.max_restarts),
        }
    }

    /// 记录一次崩溃。还有预算时登记一次重启并返回本窗口内的第几次（从 1 开始）；
    /// 预算用尽返回 `None`，调用方应停止重启。
    pub fn on_crash(&mut self, now: Instant) -> Option<u32> {
        while self
            .restarts
            .front()
            .is_some_and(|&t| now.saturating_duration_since(t) >= self.window)
        {
            self.restarts.pop_front();
        }
        if self.restarts.len() >= self.max {
            return None;
        }
        self.restarts.push_back(now);
        u32::try_from(self.restarts.len()).ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn budget() -> RestartBudget {
        RestartBudget::new(&RestartPolicy::default())
    }

    #[test]
    fn fourth_crash_within_a_minute_exhausts_the_budget() {
        let t0 = Instant::now();
        let mut b = budget();
        assert_eq!(b.on_crash(t0), Some(1));
        assert_eq!(b.on_crash(t0 + Duration::from_secs(10)), Some(2));
        assert_eq!(b.on_crash(t0 + Duration::from_secs(20)), Some(3));
        assert_eq!(b.on_crash(t0 + Duration::from_secs(59)), None);
    }

    #[test]
    fn old_restarts_leave_the_window() {
        let t0 = Instant::now();
        let mut b = budget();
        for i in 0..3 {
            assert!(b.on_crash(t0 + Duration::from_secs(i)).is_some());
        }
        // 第一次重启满 60 秒后离开窗口，又有一次预算
        assert_eq!(b.on_crash(t0 + Duration::from_secs(60)), Some(3));
        assert_eq!(b.on_crash(t0 + Duration::from_secs(60)), None);
        assert_eq!(b.on_crash(t0 + Duration::from_secs(200)), Some(1));
    }

    #[test]
    fn zero_budget_never_restarts() {
        let mut b = RestartBudget::new(&RestartPolicy {
            max_restarts: 0,
            ..RestartPolicy::default()
        });
        assert_eq!(b.on_crash(Instant::now()), None);
    }
}
