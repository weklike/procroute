// SPDX-License-Identifier: GPL-3.0-or-later
//! 假后端：不碰网络，供上层在任何平台上测试（启用 `mock` 特性）。
//!
//! 测试通过 [`MockHandle`] 注入「新流」「无法处理的包」「流结束」，假后端按与真实
//! 后端相同的 [`decide`] / [`unprocessable`] 判定，发出同样的事件、更新同样的计数器，
//! 并把「已安装的过滤器数」暴露出来，便于验证停止后无残留（C-NET-06）。

use std::collections::HashSet;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use crate::backend::{
    Counters, InterceptError, InterceptStats, Interceptor, StartContext, Verdict, decide, emit,
    unprocessable,
};
use crate::exclude::ExclusionSet;
use crate::flow::{FlowEvent, FlowKey, NewFlow, ProcessKey};

/// 假后端本身，交给 svc 当作 `Box<dyn Interceptor>` 使用。
#[derive(Default)]
pub struct MockInterceptor {
    shared: Arc<Shared>,
}

/// 测试侧的遥控器，可以克隆。
#[derive(Clone)]
pub struct MockHandle {
    shared: Arc<Shared>,
}

#[derive(Default)]
struct Shared {
    running: Mutex<Option<Running>>,
    counters: Counters,
}

struct Running {
    ctx: StartContext,
    /// 已改道、尚未结束的流。
    redirected: HashSet<FlowKey>,
}

impl MockInterceptor {
    pub fn new() -> (Self, MockHandle) {
        let me = Self::default();
        let handle = MockHandle {
            shared: Arc::clone(&me.shared),
        };
        (me, handle)
    }
}

impl Shared {
    fn lock(&self) -> MutexGuard<'_, Option<Running>> {
        // 假后端里没有需要在 panic 后保持的不变量，中毒也照常使用
        self.running.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl Interceptor for MockInterceptor {
    fn name(&self) -> &'static str {
        "mock"
    }

    fn start(&mut self, ctx: StartContext) -> Result<(), InterceptError> {
        let mut running = self.shared.lock();
        if running.is_some() {
            return Err(InterceptError::AlreadyRunning);
        }
        *running = Some(Running {
            ctx,
            redirected: HashSet::new(),
        });
        Ok(())
    }

    fn stop(&mut self) -> Result<(), InterceptError> {
        self.shared
            .lock()
            .take()
            .map(drop)
            .ok_or(InterceptError::NotRunning)
    }

    fn is_active(&self) -> bool {
        self.shared.lock().is_some()
    }

    fn update_exclusions(&mut self, exclusions: ExclusionSet) -> Result<(), InterceptError> {
        let mut running = self.shared.lock();
        let r = running.as_mut().ok_or(InterceptError::NotRunning)?;
        r.ctx.exclusions = exclusions;
        Ok(())
    }

    fn stats(&self) -> InterceptStats {
        self.shared.counters.snapshot()
    }
}

impl Drop for MockInterceptor {
    fn drop(&mut self) {
        // 与真实后端一样：对象销毁即撤销全部过滤器（C-NET-06）
        self.shared.lock().take();
    }
}

impl MockHandle {
    /// 模拟后端看到一条新流（已完成归属）。
    pub fn new_flow(&self, flow: NewFlow) -> Result<Verdict, InterceptError> {
        let mut running = self.shared.lock();
        let r = running.as_mut().ok_or(InterceptError::NotRunning)?;
        let counters = &self.shared.counters;
        let verdict = decide(
            &flow,
            &r.ctx.settings,
            &r.ctx.exclusions,
            r.ctx.policy.as_ref(),
            counters,
        );
        match verdict {
            Verdict::Redirect { group } => {
                // decide 只在归属成功时改道
                if let Some(process) = flow.process {
                    r.redirected.insert(flow.key);
                    let event = FlowEvent::Redirected {
                        key: flow.key,
                        process,
                        group,
                    };
                    emit(&r.ctx.events, event, counters);
                }
            }
            Verdict::Block => {
                let event = FlowEvent::Blocked {
                    key: flow.key,
                    process: flow.process,
                };
                emit(&r.ctx.events, event, counters);
            }
            Verdict::Bypass(_) => {}
        }
        Ok(verdict)
    }

    /// 模拟一个处理不了的数据包（例如 IPv6 分片重组失败）。
    ///
    /// 只有目标进程的包按 fail_policy 处理；其他进程的包原样放行（C-NET-02、C-NET-07）。
    pub fn unprocessable(
        &self,
        key: FlowKey,
        process: ProcessKey,
    ) -> Result<Option<Verdict>, InterceptError> {
        let mut running = self.shared.lock();
        let r = running.as_mut().ok_or(InterceptError::NotRunning)?;
        if r.ctx.policy.target_group(&process).is_none() {
            return Ok(None);
        }
        let verdict = unprocessable(r.ctx.settings.fail_policy, &self.shared.counters);
        if verdict == Verdict::Block {
            let event = FlowEvent::Blocked {
                key,
                process: Some(process),
            };
            emit(&r.ctx.events, event, &self.shared.counters);
        }
        Ok(Some(verdict))
    }

    /// 模拟一条改道过的流结束。返回该流此前是否处于改道状态。
    pub fn close_flow(&self, key: FlowKey) -> Result<bool, InterceptError> {
        let mut running = self.shared.lock();
        let r = running.as_mut().ok_or(InterceptError::NotRunning)?;
        let was = r.redirected.remove(&key);
        if was {
            emit(
                &r.ctx.events,
                FlowEvent::Closed { key },
                &self.shared.counters,
            );
        }
        Ok(was)
    }

    /// 当前安装的过滤器数：运行中为 1，停止或销毁后必须为 0（C-NET-06）。
    pub fn installed_filters(&self) -> usize {
        usize::from(self.shared.lock().is_some())
    }

    /// 仍处于改道状态的流数。
    pub fn redirected_flows(&self) -> usize {
        self.shared
            .lock()
            .as_ref()
            .map_or(0, |r| r.redirected.len())
    }
}

#[cfg(test)]
mod tests;
