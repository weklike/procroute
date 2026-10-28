<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# sing-box 版本锁

ProcRoute 以独立子进程方式使用 [sing-box](https://github.com/SagerNet/sing-box)（C-ARCH-03）。
本目录只提交版本锁，**不提交二进制**（C-DEP-04）。

| 项 | 值 |
| --- | --- |
| 版本 | 1.14.4（`v1.14.4`，发布于 2026-10-24） |
| 源码修订 | `c005f35300ce76427dc285481ec5695f5b179cd2` |
| 许可证 | GPL-3.0-or-later，附加条款：衍生作品未经许可不得使用其名称或暗示关联 |
| 源码 | <https://github.com/SagerNet/sing-box/tree/v1.14.4> |

## 文件

- `lock.json`：每个平台的发布包地址、发布包 SHA256，以及从包里取出的文件和各自的 SHA256。
  目前只锁 `windows-x86_64`（支持矩阵见 C-DRV-05）。
- `bin/`：`cargo xtask fetch-deps` 的输出目录，已在 `.gitignore` 中忽略。

只取出 `sing-box.exe` 和 `LICENSE`。发布包里的 `libcronet.dll` 只给 naive 出站用，
ProcRoute 不支持该协议，因此不取出也不分发。

## 拉取与校验

```bash
cargo xtask fetch-deps
```

在 Windows 上用系统自带的 `curl.exe` 下载、`tar.exe` 解包，并用 Windows CNG 计算 SHA256
（`procroute-platform-win::hash`）。发布包或任一取出文件的哈希与 `lock.json` 不一致都会直接失败，
不会留下未校验的文件。已存在且哈希一致的文件不会重新下载。

运行时服务同样按锁文件校验 `sing-box.exe` 后才启动它（C-SEC-06，T-056）。

## 兼容性验证记录

### 1.14.4（初次锁定）

- 发布包 SHA256 与 GitHub 发布页给出的 digest 一致。
- `sing-box.exe version` 输出 `sing-box version 1.14.4`，Go 1.26.10，
  构建标签含 `with_gvisor`、`with_quic`、`with_utls`、`with_clash_api`。
- 配置生成器（T-055）以本版本的文档和 `sing-box check` 为准；生成配置的回归测试在
  `crates/core-mgr` 中，用这里锁定的二进制执行 `sing-box check`。

## 升级流程

升级必须单独提 PR，只改本目录的版本锁与本文件的验证记录（AGENTS 4.2、C-DEP-04）：

1. 更新 `lock.json` 的版本、修订、发布包地址与全部 SHA256；
2. `cargo xtask fetch-deps` 拉取新版本；
3. 对照新版本的 `docs/deprecated.md` 与 `docs/migration.md` 检查生成器用到的字段；
4. 跑 `cargo nextest run -p procroute-core-mgr`（T-055 起含 `sing-box check` 回归）；
5. 在上面追加一条兼容性验证记录，同步 `NOTICE` 中的版本号。
