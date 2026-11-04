
## 下载与安装

下载 `{{INSTALLER}}` 并运行，支持 Windows 10 22H2 及以上、Windows 11（x64）。

- 安装包用每次发版临时生成的自签名证书签名，Windows 会提示「未知发布者」，SmartScreen 可能拦截：点「更多信息 → 仍要运行」。**不需要安装任何证书**。
- 安装时会注册 `ProcRoute` 系统服务；卸载时一并移除。方案、节点与日志保留在 `%ProgramData%\ProcRoute`。
- 部分杀毒软件和游戏反作弊对 WinDivert 驱动敏感，遇到冲突可以改用 TUN 分流模式。

## 校验

确认下载的文件完整，且确实由本仓库的 GitHub Actions 从这个版本的源码构建：

```text
SHA-256: {{SHA256}}
gh attestation verify {{INSTALLER}} --repo {{REPO}}
```

## 源码与许可

ProcRoute 以 GPL-3.0-or-later 发布，本版本的源码：<https://github.com/{{REPO}}/tree/{{TAG}}>。
安装包内含 sing-box 与 WinDivert，它们的版本、许可证和源码地址见 [NOTICE](https://github.com/{{REPO}}/blob/{{TAG}}/NOTICE)。

本软件不内置任何节点或订阅，也不收集遥测。请遵守所在地的法律法规。
