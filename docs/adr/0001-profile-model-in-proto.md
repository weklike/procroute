# ADR 0001：方案数据结构放在 proto，config 负责校验与迁移

- 状态：已采纳
- 日期：2026-10-28
- 涉及约束：C-ARCH-02、C-ARCH-04、C-ARCH-06

## 背景

TASKS.md 原计划在 `crates/config` 里定义 `Profile`（T-020），`crates/proto` 只放一个最小版本（T-005）再「对齐」。
但 `Profile` 既是落盘格式，也是 `profile.get` / `profile.save` 的线上格式；两处各定义一份，迟早不一致，
而 C-ARCH-04 要求 IPC 契约只有一个事实来源。

## 决定

- `procroute-proto::profile` 定义完整的 `Profile`、`Group`、`MatchRule` 及相关枚举，并派生 TypeScript 类型。
- `procroute-rules` 依赖 proto，对这些类型做匹配。
- `procroute-config` 依赖 proto 与 rules，提供：
  - 校验（规则能否编译、组标签是否唯一等），复用 rules 的编译器，保证「校验通过」与「引擎能用」是同一个判断；
  - 按 `schema_version` 的迁移；
  - 从 JSON 文本到合法 `Profile` 的一站式入口。

依赖方向：`proto ← rules ← config`，三者都不依赖平台 crate、都不做 IO（C-ARCH-02）。

## 影响

- T-020 改为「在 config 中重新导出 proto 的方案类型并写明边界」。
- T-021 的校验调用 `procroute_rules::matcher::Matcher::compile`。
- 将来方案结构变更时，同时修改 proto（类型）与 config（迁移函数 + fixture），并提升 `PROFILE_SCHEMA_VERSION`。
