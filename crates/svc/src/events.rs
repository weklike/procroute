// SPDX-License-Identifier: GPL-3.0-or-later
//! 服务主动推送的事件。
//!
//! - 会话状态放在 `watch` 里：它既是状态的唯一来源（`session.status` 方法直接读它），也会在每次变化时
//!   推给所有已握手的连接（`session.status` 事件，C-UI-02 要求界面如实显示）；
//! - 日志与连接事件走 `broadcast`：只发给调用过 `log.subscribe` / `conn.subscribe` 的连接。
//!   某个连接处理不过来时丢弃它落下的事件（界面本来就只显示最近的若干条），不拖慢服务。
//!   连接事件的来源（中继与拦截层）随 M2 接入。

use procroute_proto::event::{ConnEvent, LogEvent};
use procroute_proto::session::SessionStatus;
use tokio::sync::{broadcast, watch};

/// 每个连接最多积压的日志 / 连接事件数，超出后丢弃最旧的。
pub const STREAM_CAPACITY: usize = 1024;

/// 高频事件。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StreamEvent {
    Log(LogEvent),
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "连接事件的生产者（中继、拦截层）随 M2 接入，届时去掉"
        )
    )]
    Conn(ConnEvent),
}

/// 事件的发送端，由服务状态持有。
#[derive(Debug)]
pub struct EventHub {
    session: watch::Sender<SessionStatus>,
    stream: broadcast::Sender<StreamEvent>,
}

/// 一个连接的接收端。
#[derive(Debug)]
pub struct Subscription {
    pub session: watch::Receiver<SessionStatus>,
    pub stream: broadcast::Receiver<StreamEvent>,
}

impl EventHub {
    #[cfg(test)]
    pub fn new(initial: SessionStatus) -> Self {
        Self::with_stream(initial, broadcast::channel(STREAM_CAPACITY).0)
    }

    /// 使用已有的高频事件发送端（日志层在服务状态之前就要创建它）。
    pub fn with_stream(initial: SessionStatus, stream: broadcast::Sender<StreamEvent>) -> Self {
        Self {
            session: watch::channel(initial).0,
            stream,
        }
    }

    /// 当前会话状态的副本。
    pub fn session(&self) -> SessionStatus {
        self.session.borrow().clone()
    }

    /// 修改会话状态；只有真的变了才通知订阅者。返回修改后的状态。
    pub fn update_session(&self, f: impl FnOnce(&mut SessionStatus)) -> SessionStatus {
        self.session.send_if_modified(|s| {
            let before = s.clone();
            f(s);
            *s != before
        });
        self.session()
    }

    /// 高频事件的发送端（测试里用它直接发事件）。
    #[cfg(test)]
    pub fn stream_sender(&self) -> broadcast::Sender<StreamEvent> {
        self.stream.clone()
    }

    pub fn subscribe(&self) -> Subscription {
        Subscription {
            session: self.session.subscribe(),
            stream: self.stream.subscribe(),
        }
    }
}

#[cfg(test)]
mod tests {
    use procroute_proto::session::SessionState;

    use super::*;

    #[tokio::test]
    async fn only_real_changes_notify_subscribers() {
        let hub = EventHub::new(SessionStatus::default());
        let mut sub = hub.subscribe();
        hub.update_session(|_| {});
        assert!(!sub.session.has_changed().expect("open"));
        let s = hub.update_session(|s| s.state = SessionState::Running);
        assert_eq!(s.state, SessionState::Running);
        sub.session.changed().await.expect("changed");
        assert_eq!(sub.session.borrow_and_update().state, SessionState::Running);
    }

    #[tokio::test]
    async fn stream_events_reach_every_subscriber() {
        let hub = EventHub::new(SessionStatus::default());
        let mut a = hub.subscribe();
        let mut b = hub.subscribe();
        let e = ConnEvent {
            conn_id: 1,
            phase: procroute_proto::event::ConnPhase::Opened,
            pid: 1,
            process: "a.exe".into(),
            target: "example.com:443".into(),
            network: procroute_proto::event::Network::Tcp,
            group: "g".into(),
            outbound: "o".into(),
            upload_bytes: 0,
            download_bytes: 0,
            started_at_ms: 0,
        };
        hub.stream_sender()
            .send(StreamEvent::Conn(e.clone()))
            .expect("two receivers");
        assert_eq!(
            a.stream.recv().await.expect("a"),
            StreamEvent::Conn(e.clone())
        );
        assert_eq!(b.stream.recv().await.expect("b"), StreamEvent::Conn(e));
    }
}
