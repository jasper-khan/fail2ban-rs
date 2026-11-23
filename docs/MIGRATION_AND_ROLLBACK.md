# 从 Fail2Ban 1.1.1 切换与回滚

以下步骤适用于 systemd Linux。保留原版 1.1.1 的安装包。Rust 发布包将程序和 unit
安装到 `/usr/local`，继续使用原来的 `/etc/fail2ban` 配置和 SQLite v4 数据库。
自定义 unit 或 drop-in 指定了启动路径时，先核对它实际执行的二进制。

## 切换前验证

用隔离的配置和数据目录执行切换演练。`DESTDIR` 可以把发布包安装到临时目录。
测试配置应设置自己的 `socket`、`pidfile`、`logtarget` 和 `dbfile`，并选用测试动作。
记录 `status`、`get <jail> banip` 和 `get dbfile` 的结果，作为后续对照。

```bash
DESTDIR="$stage" bash scripts/install.sh "$archive"
"$stage/usr/local/bin/fail2ban-client" -c "$stage/etc/fail2ban" -t
```

## 切换

1. 停止原版服务，并停用正在运行的 `fail2ban.socket`。原版和 Rust 服务应轮流持有套接字和数据库。
2. 在服务停止后备份 `/etc/fail2ban` 和数据库所在目录，保留 SQLite 旁文件。
3. 用 `sudo bash scripts/install.sh "$archive"` 安装（首次覆盖安装前会在 `/usr/local/lib/fail2ban-rs/backup` 中保留原有 `/usr/local` 下的二进制、unit、man 手册及被替换的原版 `apache-fakegooglebot`，并在 `/usr/local/lib/fail2ban-rs/systemd-state` 中记录切换前 `fail2ban.service` 与 `fail2ban.socket` 的完整 `systemctl is-enabled` 状态，包括 `enabled`、`enabled-runtime`、`disabled`、`masked`、`masked-runtime` 等），再执行 `sudo /usr/local/bin/fail2ban-client -t`。
4. 启动 `fail2ban.service`。核对 `systemctl cat fail2ban.service` 显示的程序路径、启用的 jail、
   当前封禁、相应防火墙规则和日志来源。

## 回滚

1. 停止 Rust 服务和已启用的套接字。通过 `sudo bash scripts/install.sh --uninstall` 移除 Rust 安装的 `/usr/local` 程序和 unit，先按备份原样还原切换前被覆盖的原版文件，再执行 `systemctl daemon-reload` 并按记录的原状态精确恢复 `fail2ban.service` 与 `fail2ban.socket`（`enabled-runtime` / `masked-runtime` 使用 `--runtime` 恢复）；若恢复失败则保留 `/usr/local/lib/fail2ban-rs/backup` 与 `systemd-state` 并返回非零退出码以便修正后重试。
2. 确认 systemd 使用原版 1.1.1 的 unit 并核对 `systemctl is-enabled fail2ban.service`。需要恢复切换前状态时，先将当前配置和 SQLite 数据另行备份，再恢复切换前的备份。
3. 启动原版，核对 jail、活动封禁和日志来源。安装程序仅在原版 `apache-fakegooglebot` 脚本与
   1.1.1 发布源码完全一致时替换它，并在 `--uninstall` 时随其他被覆盖文件一并恢复；若此前还手动修改过配置目录，从备份恢复对应文件。

Python 与 Rust 服务端轮流接管同一个 SQLite v4 数据库的集成测试使用原版 1.1.1 源码运行。

```bash
FAIL2BAN_111_SOURCE=/path/to/fail2ban-1.1.1 cargo test --locked --test f2b_parity
```
