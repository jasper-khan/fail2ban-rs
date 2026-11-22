# Fail2Ban 1.1.1 纯 Rust 重写 Roadmap

目标：在 `rust-rewrite` 分支上将 `fail2ban-rs` 做成 **Fail2Ban 1.1.1（commit `f6097861`）的完整替代品**，严格以原版 1.1.1 公开行为为准，不多增功能、不少功能，交付静态二进制（`fail2ban-server`、`fail2ban-client`、`fail2ban-regex` 及辅助二进制 `apache-fakegooglebot`），SQLite v4 为单一真源。

> [!NOTE]
> **明确搁置的两项**：**SMTP STARTTLS**（`smtp.py` `ssl=true`）与**第三方自定义 `.py` action** 已移出当前分支并单独归档。当前版本内置纯 Rust 明文/认证 `smtp.py`，对其他自定义 `.py` action 明确返回不支持错误。

---

## 1. 架构路线与目录边界

采用 **原生 1:1 架构重写 + 复用已对拍底层纯模块** 方案：
- 纯 Rust 内核全部位于 [src/f2b/](../src/f2b/) 与 [src/bin/](../src/bin/)，通过 [Cargo.toml](../Cargo.toml) 的 `[lib] path = "src/f2b/lib.rs"` + `autobins = false` 构建，已彻底移除原 fork 的旧非 1.1.1 代码（TOML / `etchdb` / MaxMind / `tell` / `webhook` / 88 硬编码 filter / JSON socket）。
- 零新增生产依赖（依赖表裁剪至 11 个已有 crate：`chrono`、`fancy-regex`、`ipnet`、`memchr`、`nix`、`regex`、`rusqlite`、`serde`、`serde_json`、`thiserror`、`tokio`）。
- 统一采用 Fail2Ban 1.1.1 原生命令流架构：
  ```
  /etc/fail2ban (INI + includes + filter.d + action.d)
        │
        ▼
  Configurator ──► Pickle 2–5 (<F2B_END_COMMAND>) ──► Transmitter ──► Server / Jails
                                                                            │
                 ┌──────────────────────────────────────────────────────────┤
                 ▼                                                          ▼
    Filter + DateDetector + Backends                             FailManager + BanManager
    (polling / inotify / systemd)                                + Observer (bantime.*)
                 │                                                          │
                 └──────────────────────────► Ticket ◄──────────────────────┘
                                                │
                             ┌──────────────────┴──────────────────┐
                             ▼                                     ▼
                    SQLite v4 (Fail2BanDb)             Actions (CommandAction + SmtpAction)
  ```

---

## 2. 阶段完成度总览

| 阶段 | 模块 / 交付物 | 状态 | 验证证据（InstaBox Linux + Rust 1.94.0 + Fail2Ban 1.1.1 `f6097861`） |
| --- | --- | --- | --- |
| **M0 环境与基线** | 同步 `rust-rewrite`、接入 InstaBox Linux（`rustc 1.94.0` + Python 3.13 + 原版 1.1.1 源码 `f6097861`） | **已完成** | InstaBox 基准编译、测试与对拍环境就绪 |
| **M1 基础设施与配置层** | [error.rs](../src/f2b/error.rs)、[duration.rs](../src/f2b/duration.rs)、[logging.rs](../src/f2b/logging.rs)、[ticket.rs](../src/f2b/ticket.rs)、[protocol/](../src/f2b/protocol/)、[config/](../src/f2b/config/) | **已完成并验收** | Python 3 pickle 2–5 双向互操作通过；原版 103 个 `filter.d` + 65 个 `action.d` + `fail2ban.conf`/`jail.conf` 全量加载通过 |
| **M2A 状态机与 SQLite v4** | [failmanager.rs](../src/f2b/failmanager.rs)、[banmanager.rs](../src/f2b/banmanager.rs)、[observer.rs](../src/f2b/observer.rs)、[db/mod.rs](../src/f2b/db/mod.rs) | **已完成并验收** | 速率窗口、永久/延长/CIDR 封禁、`bantime.*` AST 求值与自然过期递增、`overalljails` 布尔/字符串语义、SQLite v1–v3→v4 升级与 `del_ban` 双表清理通过 |
| **M2B 动作与纯 Rust SMTP** | [action/](../src/f2b/action/)（`cmd`/`policy`/`tags`/`command_action`/`smtp`） | **已完成并验收** | `start_on_demand`、双栈家族去重、`actioncheck`→`actionrepair` 重试、`actionreban`/`prolong`/`flush`、标签转义、本地 TCP SMTP 实测通过（STARTTLS 搁置） |
| **M2C 客户端与美化输出** | [client/beautifier.rs](../src/f2b/client/beautifier.rs)、[client/mod.rs](../src/f2b/client/mod.rs)、[src/bin/fail2ban-client.rs](../src/bin/fail2ban-client.rs) | **已完成并验收** | CLI 23/23 命令、`fail2ban-client -h`/`fail2ban-server -h`、`--str2sec`、`-i` 交互模式、`start`/`restart`/`reload` 均与原版 1.1.1 逐字节对齐；移除非 1.1.1 的多余 `configure` 命令 |
| **M2D 日期、正则、过滤与日志后端** | [date/](../src/f2b/date/) + [filter/](../src/f2b/filter/)（`strptime`/`template`/`DateDetector`/`FailRegex`/`ipdns`/`Filter`/`polling`/`inotify`/`systemd`）+ [apache-fakegooglebot.rs](../src/bin/apache-fakegooglebot.rs) | **已完成并验收** | 17 组默认日期模板（`Epoch`/`LongEpoch` 命名与排序对齐原版）、线性 `regex` + `fancy-regex` 回退、`<F-MLFID>`/`<F-NOFAIL>`、纯 Rust Cymru DNS TXT 查询、`ignoreself`/`ignoreip`（含 `file:`）/`ignorecommand`/`ignorecache`、`logencoding`（`auto`/`utf-8`/`latin1`/`ascii`/`cp1252`/`utf-16`/`utf-16le`/`utf-16be` 含 `U+020A` 安全换行切分）、冷启动 `seekToTime` 二分定位、`polling`/`inotify`/`systemd`（含 `journalfiles`/`namespace`/`rotated` 与 SQLite `systemd-journal` 游标持久化续读）全实测通过 |
| **M3A `fail2ban-regex` 工具** | [regex_tool.rs](../src/f2b/regex_tool.rs) + [src/bin/fail2ban-regex.rs](../src/bin/fail2ban-regex.rs) | **已完成并验收** | 96/96 官方日志样本 `--out=ip` 100% 一致；移除非 1.1.1 的 `--out=json` 特殊分支（返回 `None` 对齐原版）；全量 CLI 模式（默认报告/`--out=*` 含自定义标签/`--print-all-*`/`--print-no-*`/`--invert`/`-d`/`--timezone`/`-v`/`-vv`/`-D`/`-r`/`--usedns`/非法选项退出码 `2`/非法正则退出码 `255`）与原版一致 |
| **M3B 服务端与全量协议** | [src/f2b/server/](../src/f2b/server/)（`mod.rs`/`jail.rs`/`transmitter.rs`）+ [src/bin/fail2ban-server.rs](../src/bin/fail2ban-server.rs) | **已完成并验收** | `-b` 管道就绪同步（绑定/加载完成后父进程退出 `0`，冲突或失败返回 `255`）、`SIGTERM`/`SIGINT`/`SIGUSR1`、systemd socket activation、`logtarget`（含 `SYSOUT`、`[datetime/padding/facility/format]`、`SYSLOG` socket 校验、拒绝不存在父目录不自动 `mkdir`、`SYSTEMD-JOURNAL` 直连 `/run/systemd/journal/socket`）、`action <act> <METHOD> [JSONKWARGS]` 方法分发、`[Thread] stacksize`、90 条管理命令 87/90 一致（余 3 项为沙箱缺 `dnspython` 及 CPython 3.13 `stack_size()` 归零 bug） |
| **M4 全量头对头对拍与端到端验收** | 103 stock filters 全量编译、96 日志样本对拍、双向互操作、SQLite 接管与回滚、nftables/iptables 双栈、安装包暂存升级 | **已完成并验收** | 126 项库单测 + 3 项集成对拍 + `cargo fmt --check` + `clippy -D warnings` 全绿；amd64/arm64 静态包已重建并在 amd64 暂存目录跑通安装、升级保配置与运行态验收 |
| **M5 清理旧代码与收尾交付** | 移除全部 258 个旧遗留文件、更新构建/安装/文档并提交至 `rust-rewrite` | **已完成** | 旧源码/测试/基准/TOML 配置/旧服务单元已全部清空且无空目录残留；`dist/fail2ban.{service,socket}`、`scripts/{build-release,install}.sh`、`justfile`、`README.md`、`docs/MIGRATION_AND_ROLLBACK.md` 已更新并推送 |

---

## 3. 已验收的核心对拍矩阵（InstaBox Linux）

1. **Stock `filter.d` 与 `action.d`**：
   - `tests/f2b_parity.rs` 全量加载并实际编译全部 runnable `filter.d/*.conf`（96 份，零报错）及 65 份 `action.d/*.conf` + `fail2ban.conf` + `jail.conf`。
   - `compare-stock.py` 对拍官方 `fail2ban/tests/files/logs` 下 96 份日志样本：`96/96` 一致。
2. **管理协议、`fail2ban-client` 与 `fail2ban-server` CLI**：
   - `management-parity.py` 90 条管理命令对拍：87/90 完全一致；剩余 3 项中 1 项为原版沙箱缺少 `dnspython`（Rust 已内置纯 Rust DNS TXT Cymru 查询并经本地 UDP mock 单测验证），2 项为 CPython 3.13 `_thread.stack_size()` 无参调用归零 bug（Rust 正确保留已设 `stacksize`）。
   - `fail2ban-client` / `fail2ban-server` CLI 对拍逐字节一致：`-h`、`-V`/`--version`、`--str2sec`（含 `1.5m -> 90.0`）、`-t`、`-i`、`start`/`restart`/`reload`（含 `--if-exists`）、`-b` 守护就绪同步与重复 socket 退出码 `255`、`configure` 返回 `Invalid command`、`logtarget`（`SYSOUT`/`STDOUT[datetime=off]`/`[format="..."]`/`SYSLOG` socket 校验/拒绝不存在父目录/`SYSTEMD-JOURNAL` 直连 `/run/systemd/journal/socket` 并由 `journalctl` 读回/`flushlogs`）、`set <jail> action <act> <METHOD> [JSONKWARGS]`（含 `escapeTag`/`invalidateBanEpoch`/`replaceTag`/`executeCmd` 与 `TypeError` 参数校验）。
   - 原版客户端↔Rust 服务端、Rust 客户端↔原版服务端双向互操作通过。
3. **`fail2ban-regex` CLI**：
   - 全量用例（`-V`、`--version`、stock `sshd`/jail 名、单行输入、`--out=ip/id/msg/row/<ip> <F-USER>`、`--out=json` 返回 `None`、`--print-all-matched/missed/ignored`、`--print-no-missed/ignored`、`--invert`、`-d`、`--timezone`、`-r`、`--usedns=no`、`-v`/`-vv`、`-D`、非法选项退出码 `2`、非法正则退出码 `255`）输出与退出码逐字节对齐（仅处理耗时行 Rust 为 `0.00 sec` 对比 Python `0.01 sec`）。
4. **状态机、过滤忽略规则、SQLite v4 与动作恢复**：
   - 实时对拍 `bantime.increment` 自然过期递增（`2s -> 4s`）、`bantime.overalljails=false` 隔离（`10s`）与 `overalljails=true` 跨 jail 累积（`80s`）、`ignoreself`/`ignoreip = file:...`/`ignorecommand` + `ignorecache`（验证二次命中走缓存不重复调用命令）、`recidive.conf` 识别 Rust 日志行、`actioncheck`→`actionrepair` 恢复、纯 Rust `smtp.py`（明文 TCP）均与原版 1.1.1 一致。
   - SQLite v4 双向接管与回滚演练（原版写→Rust 接管并 reload 保留→原版接管恢复并 `unban --all`）通过；`systemd-journal` 游标时间戳写入 `logs` 表并跨重启续读实测通过（不重放旧条目且捕获新条目）。
5. **Linux 运行态、防火墙与打包安装**：
   - 隔离网络命名空间内实测 `nftables-multiport` 与 `iptables-multiport` 的 IPv4 + IPv6 封禁、重载保规则、解封与退出清理，双引擎一致。
   - `polling`（`-b` 守护模式、10 万行历史大文件 0.35s 冷启动 `seekToTime` 二分跳转、`utf-16be`/`utf-16le` 含 `U+020A` 实测封禁）、`pyinotify`（日志轮转）、`systemd`（`systemd-socket-activate` + `journald` + SQLite 续读）实测通过。
   - 暂存安装与覆盖升级验证：保留既有 `jail.local`、`fail2ban.conf`、`fail2ban.sqlite3`，安装纯 Rust `apache-fakegooglebot`、systemd units 与 manpages；交叉构建产出最新静态 Linux 发布包：
     - `fail2ban-rs-1.1.1-linux-amd64.tar.gz`（SHA-256: `7dba13f51c4be21a1f4e8ce555520f92dc7d7f4a4d9aa10634c14277d170dab1`）
     - `fail2ban-rs-1.1.1-linux-arm64.tar.gz`（SHA-256: `a393e5b79195e068ad4bb10cbd7cd55472dcf81c1668b3fd1082eaffa455748c`，交叉构建 + ELF/SHA-256 校验，尚未在真机/QEMU 运行）

---

## 4. 标准验证命令

```bash
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
export FAIL2BAN_111_SOURCE=/path/to/fail2ban-1.1.1
cargo test --locked --no-fail-fast
bash scripts/build-release.sh 1.1.1
```

---

## 5. 收尾状态与已知边界

1. **旧代码清理已完成**：258 个旧遗留源码/测试/基准/TOML 配置/旧服务单元与文档已全部移除，仓库仅保留纯 Rust Fail2Ban 1.1.1 实现。
2. **明确搁置项**：SMTP STARTTLS（`ssl=true`）与第三方自定义 `.py` action。
3. **已知工程边界**：`[Thread] stacksize` 对 `< 1024 KiB` 保留栈保护下限以防 Rust 正则栈溢出；`arm64` 静态二进制仅完成交叉编译与 ELF/SHA-256 校验，尚未在真机/QEMU 运行态实测。
