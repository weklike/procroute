# ProcRoute

Windows 优先的进程级代理客户端：只让指定的进程（及其子进程）走代理，其余流量不受影响。

## 下载

从 [Releases](https://github.com/weklike/procroute/releases) 下载 `ProcRoute_<版本>_x64-setup.exe` 并运行，支持 Windows 10 22H2 及以上、Windows 11（x64）。
安装包用临时生成的自签名证书签名，Windows 会提示「未知发布者」，SmartScreen 拦截时点「更多信息 → 仍要运行」，不需要安装任何证书。
每个 Release 都附有校验和与构建来源证明（[原因](./docs/adr/0002-release-signing-same-certificate.md)）。

## 开发

- 开发约定：[`AGENTS.md`](./AGENTS.md)
- 硬性约束：[`CONSTRAINTS.md`](./CONSTRAINTS.md)
- 任务清单：[`TASKS.md`](./TASKS.md)
- Windows 开发机配置：[`scripts/setup-windows-dev.ps1`](./scripts/setup-windows-dev.ps1)

许可证：GPL-3.0-or-later
