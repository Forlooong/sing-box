# 更新中断后的独立恢复

更新被断电、进程强制终止等事件打断时，先执行：

```sh
sudo sb transaction recover
```

入口会在进入 `/opt/sb/current` 和导入管理模块之前，转交同目录的 `sb-recover`。
它是包含完整恢复依赖的单文件 Python ZIP 可执行文件，不依赖正在更新的运行目录。
若恢复更早的历史事务已经还原了旧版 `sb` 启动脚本，可直接执行：

```sh
sudo /usr/local/bin/sb-recover
```

恢复沿用现有事务日志、全局管理锁、文件及服务状态回滚、准备阶段和 ACME 恢复逻辑。
已撤销订阅 token 不会因恢复重新有效。恢复本身再次中断时，可以重复执行同一命令；
不要删除 `/var/backups/sb/transactions` 或其中的 `before`、`stage`、`journal.json`。

## 证书副本事务的恢复边界

`cert sync` 的 `certificate copies` 事务只负责已验证副本、服务读取权限和持久激活队列。
如果进程在文件事务提交前中断，`transaction recover` 仍恢复旧副本和原队列；该事务不保存
服务重启计划，恢复文件不会重启依赖坏证书的服务。如果文件已提交、服务尚未完成激活，
应运行 `sb cert sync` 或等待定时重试，`transaction recover` 不会撤回已提交的副本。

已提交的 `certificate copies` 事务明确拒绝手工 `transaction rollback`；当前没有通用证书
回退功能。请检查并修复受管 Certbot lineage，再通过 `sb cert sync` 校验、同步和激活。
较新的证书副本事务不会阻挡无文件重叠的普通配置回滚，但重叠时拒绝覆盖续期结果。
其他较新的普通事务仍需要先逆序回滚。

回归覆盖显式证书回滚拒绝且不变更文件/队列、实际子进程中断后的文件及队列恢复、
无重叠配置回滚保留新证书、重叠拒绝以及普通事务的顺序限制。Linux root 还验证了
两项服务均暂缓激活时健康证书文件的实际组归属和权限；非 root 环境明确跳过该权限用例。

## 安装和兼容范围

- 既有 `/opt/sb/current` 实目录保持原有布局，无需转换为符号链接。
- 候选更新完成配置生成、下载校验及规则验证后，先原子安装并同步持久化 `sb-recover`，
  再原子更新已确认属于本项目的 `sb` 启动脚本，最后将清单交给当前版本的事务执行器。
  因此首次由旧版逐文件更新器发起的更新也有独立恢复入口。
- 新安装先安装独立恢复程序，原有 `sb` 仍由安装事务备份及替换；准备失败不会提前覆盖上游入口。
- 恢复程序以及升级时安装的兼容启动脚本是持久安全工具，不随失败的更新回滚。
  配置验证或安装后续步骤失败后，它们仍可能保留；未知的同名 `sb-recover` 不会被覆盖。
- ZIP 来自同一份经过下载校验的候选源码，仅打包 runtime 白名单内容，不包含管理状态或凭证。
  安装前检查 ZIP 的独立启动，执行时使用 Python `-I` 隔离当前目录和 `PYTHONPATH`。

当前没有新增开机自动回滚服务。机器在更新中途重启后，systemd 可能先尝试启动尚未恢复的配置；
管理员需执行上述命令恢复事务及之前的服务状态。首次安装若在独立恢复程序安装前失败，
仍需从原来的完整源码目录运行 `python3 -m sbmanager.cli transaction recover`。

## 故障回归

```sh
python3 -m unittest tests.test_recovery tests.test_bootstrap tests.test_state_transaction tests.test_updates -v
```

2026-10-13，WSL/Python 3.10 隔离目录验证：40 项通过。新增测试在真实更新子进程写入依赖
尚未发布的新 CLI 后调用 `os._exit(99)`，随后从已安装的 shell 入口启动恢复，并核对
事务变为 `rolled-back`、旧 CLI 恢复启动、`current` 仍为实目录。修复前，两项基础用例均报
`ModuleNotFoundError`，日志停在 `applying`。

还验证了撤销 token 不复活、恢复子进程在还原文件时再次强制退出后可重试、
新安装保留原入口及拒绝覆盖无关恢复命令。系统服务恢复回调在这些隔离用例中关闭；
它们不代替 Debian 12 实机服务恢复或断电验收。
