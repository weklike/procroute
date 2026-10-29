// SPDX-License-Identifier: GPL-3.0-or-later
//! 生成前端使用的 TypeScript 定义（`app/src/api/generated.ts`）。
//!
//! 输出只依赖类型本身，与运行环境无关，重复生成结果逐字节相同。

use std::any::TypeId;
use std::collections::{BTreeMap, HashSet};
use std::fmt::Write as _;

use ts_rs::{Config, TS, TypeVisitor};

use crate::IPC_PROTOCOL_VERSION;
use crate::error::{ErrorCode, IpcError};
use crate::methods::{self, METHODS};
use crate::profile::PROFILE_SCHEMA_VERSION;

/// 生成文件的完整内容。
pub fn typescript_bindings() -> String {
    // 64 位整数（字节数、毫秒时间戳）在 JSON 里就是 number，不用 bigint。
    let cfg = Config::new().with_large_int("number");

    let mut collector = Collector {
        cfg: &cfg,
        seen: HashSet::new(),
        decls: BTreeMap::new(),
    };
    methods::visit_method_types(&mut collector);
    methods::visit_event_types(&mut collector);
    collector.visit::<IpcError>();
    collector.visit::<ErrorCode>();

    let mut out = String::new();
    out.push_str("// SPDX-License-Identifier: GPL-3.0-or-later\n");
    out.push_str(
        "// 本文件由 `cargo xtask gen-types` 从 crates/proto 生成，禁止手改（C-ARCH-04）。\n\n",
    );
    let _ = writeln!(
        out,
        "export const IPC_PROTOCOL_VERSION = {IPC_PROTOCOL_VERSION};\n"
    );
    let _ = writeln!(
        out,
        "export const PROFILE_SCHEMA_VERSION = {PROFILE_SCHEMA_VERSION};\n"
    );

    for decl in collector.decls.values() {
        let _ = writeln!(out, "{decl}\n");
    }

    let names = methods::method_ts_names(&cfg);
    out.push_str("/** 方法名 → 参数类型 */\nexport interface IpcRequest {\n");
    for (name, params, _) in &names {
        let _ = writeln!(out, "  \"{name}\": {params};");
    }
    out.push_str("}\n\n/** 方法名 → 返回值类型 */\nexport interface IpcResult {\n");
    for (name, _, result) in &names {
        let _ = writeln!(out, "  \"{name}\": {result};");
    }
    out.push_str("}\n\n/** 事件通道 → 负载类型 */\nexport interface IpcEvent {\n");
    for (channel, payload) in methods::event_ts_names(&cfg) {
        let _ = writeln!(out, "  \"{channel}\": {payload};");
    }
    out.push_str("}\n\nexport type IpcMethod = keyof IpcRequest;\n");
    out.push_str("export type IpcChannel = keyof IpcEvent;\n\n");
    out.push_str("/** 会修改服务状态的方法（服务端会写审计日志） */\n");
    out.push_str("export const MUTATING_METHODS: readonly IpcMethod[] = [\n");
    for m in METHODS.iter().filter(|m| m.mutating) {
        let _ = writeln!(out, "  \"{}\",", m.name);
    }
    out.push_str("];\n");
    out
}

/// 从方法与事件的类型出发，递归收集所有需要声明的类型。
struct Collector<'a> {
    cfg: &'a Config,
    seen: HashSet<TypeId>,
    decls: BTreeMap<String, String>,
}

impl TypeVisitor for Collector<'_> {
    fn visit<T: TS + 'static + ?Sized>(&mut self) {
        if !self.seen.insert(TypeId::of::<T>()) {
            return;
        }
        // 只有派生了 TS 的具名类型才有导出路径；原始类型和 Vec/Option 等包装类型没有。
        if T::output_path().is_some() {
            let mut decl = T::docs().unwrap_or_default();
            decl.push_str("export ");
            decl.push_str(&T::decl(self.cfg));
            self.decls.insert(T::ident(self.cfg), decl);
        }
        T::visit_dependencies(self);
        T::visit_generics(self);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn output_is_deterministic() {
        assert_eq!(typescript_bindings(), typescript_bindings());
    }

    #[test]
    fn contains_every_reachable_type_and_the_maps() {
        let ts = typescript_bindings();
        for needle in [
            "export type Profile =",
            "export type MatchRule =",
            "export type NodeInfo =",
            "export type ConnEvent =",
            "export type SessionStatus =",
            "export type ErrorCode =",
            "export interface IpcRequest",
            "\"profile.save\": Profile;",
            "\"conn.subscribe\": ConnEvent;",
            "export const IPC_PROTOCOL_VERSION = 1;",
            "export const PROFILE_SCHEMA_VERSION = 2;",
        ] {
            assert!(ts.contains(needle), "missing `{needle}` in:\n{ts}");
        }
    }

    #[test]
    fn large_integers_are_numbers_not_bigint() {
        assert!(!typescript_bindings().contains("bigint"));
    }
}
