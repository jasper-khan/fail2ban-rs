# Fail2Ban 1.1.1 → fail2ban-rs 迁移、验收与回滚指南

本文档面向在隔离 Linux 环境验证或从原版 Fail2Ban 1.1.1（`f6097861`）切换至 `fail2ban-rs` 兼容模式的运维与测试人员。**兼容模式尚不是生产替换方案。** 以下为隔离环境验证流程，不保证所有原版配置可加载或状态可以无损互转。

## 1. 运行模式说明

| 模式 | 启动参数 | 防火墙行为 | 数据库行为 |
| --- | --- | --- | --- |
| 只读记录演练（推荐先跑） | `fail2ban-rs run --legacy-dir <DIR> --record-decisions <FILE>` | 不改防火墙，仅追加 `BAN`/`UNBAN` 到 `<FILE>` | 原版 `fail2ban.sqlite3` 严格只读，导入一次后由隔离目录 `<FILE>.fail2ban-rs/state/` 持久化 |
| 原版客户端联调 | 追加 `--legacy-socket <SOCK>` | 同上 | 同上；仅支持原版客户端协议的一个子集；socket 父目录必须由运行用户预先创建、持有且其他用户不可写 |
| 实执行动作 + SQLite 双向直写（替换/回滚演练） | `fail2ban-rs run --legacy-dir <DIR> --legacy-execute-actions --legacy-sqlite-rw --legacy-socket <SOCK>` | 执行 `action.d/*.conf` 中的 `actionstart/ban/unban/stop` | 镜像写入原版 v4 `fail2ban.sqlite3`（`jails`/`logs`/`bans`/`bips`）；Rust WAL 与 SQLite 之间没有跨库原子事务；不能用作无损回滚保证 |

## 2. 隔离环境升级演练步骤

1. **停止原版服务，再备份原版配置与数据库**（确保无双写竞争）：
   ```bash
   fail2ban-client stop
   cp -a /etc/fail2ban /tmp/f2b-backup-etc
   cp -a /var/lib/fail2ban/fail2ban.sqlite3 /tmp/f2b-backup.sqlite3
   ```
2. **先以只读记录模式做影子验收**：
   ```bash
   run_dir=$(mktemp -d)
   fail2ban-rs run --legacy-dir /etc/fail2ban --record-decisions "$run_dir/decisions.log" --legacy-socket "$run_dir/control.sock"
   ```
   使用原版客户端检查状态：
   ```bash
   fail2ban-client -c /etc/fail2ban -s "$run_dir/control.sock" ping
   fail2ban-client -c /etc/fail2ban -s "$run_dir/control.sock" status
   fail2ban-client -c /etc/fail2ban -s "$run_dir/control.sock" status sshd
   ```
3. **切入实执行动作 + SQLite 直写模式**（隔离测试环境）：
   ```bash
   fail2ban-rs run --legacy-dir <ISOLATED_ETC> --legacy-execute-actions --legacy-sqlite-rw --legacy-socket <ISOLATED_SOCK>
   ```
   验证 `reload`、`set <jail> banip/unbanip`、日志轮转与重启续读。

## 3. 回滚到原版 Fail2Ban 1.1.1

1. 优雅停止 `fail2ban-rs`（触发 `actionstop` 并刷新 WAL 与 `fail2ban.sqlite3`）：
   ```bash
   fail2ban-client -c <ISOLATED_ETC> -s <ISOLATED_SOCK> stop
   ```
2. 若启用了 `--legacy-sqlite-rw`，先验证原版能读到期望的活动封禁与每个文件的断点；若停机前有镜像写入错误、进程异常退出或状态不一致，勿把同一份 `fail2ban.sqlite3` 当作可靠回滚来源；若仅使用只读记录模式，原库自始至终未被修改，直接重启原版 `fail2ban-server` 即可。
3. 如需恢复升级前快照：
   ```bash
   cp -a /tmp/f2b-backup.sqlite3 /var/lib/fail2ban/fail2ban.sqlite3
   ```

## 4. 已知边界

- 未达到封禁阈值的失败计数仍只在内存中；文件断点可以保存，重启不会恢复这些计数。
- 日志断点获批只表示已经处理并刷新了相关 Rust 状态，不保证外部动作已经生效，也不保证 journal 游标会在重启后恢复。
- 升级前先停止旧服务，再备份或使用 SQLite 在线备份接口；运行中的 SQLite 主文件单独复制不一定包含其日志状态。

## 5. 可重复自动化验收命令

```bash
export FAIL2BAN_111_SOURCE=/path/to/fail2ban-1.1.1
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --lib control_test
cargo test --test compat_chain
cargo test --test compat_chain -- --ignored
cargo test --test replacement_acceptance
cargo test --test replacement_acceptance -- --ignored
cargo test --lib -- --ignored
```
