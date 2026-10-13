# 可复现验证与尚未覆盖的环境

四项后续稳定性修复、订阅发布解耦及客户端持续验证见[稳定性记录](stability-2026-10-13.md)。
下文保留此前各轮测试的时间、数量和范围，不将历史结果解释为新版本验收。

后续已完成一台 Debian 12 amd64 服务器的真实安装、证书签发/续期演练、公网 REALITY/HY2 与运维验收；订阅名称和帮助修复后，WSL 与服务器最终单元回归均为 128 项。完整结果见 [测试服务器验收](server-validation-2026-10-13.md)。下文保留此前 WSL 隔离验证的具体范围。

2026-10-13 在 WSL Ubuntu 22.04、Linux amd64 上执行隔离验证。WSL 在此仅作为开发测试环境；目标新安装系统仍为 Debian 12/13 或 Ubuntu 24.04，不能把本次结果解释为这些系统及 arm64 的安装验收。

```sh
python3 -B -m unittest discover -s tests -p 'test_*.py' -v
python3 tests/integration_core.py --traffic --remote-rules
```

实核测试需要 Python 3.10+、PyYAML、cryptography，以及已有的 OpenSSL、curl（含 HTTP/2）、gpg/gpgv、dpkg-deb。脚本不会安装软件、启动 systemd 单元或修改系统 CA。它将核对根目录 `versions.json` 指定的官方发布文件 SHA-256，再把 sing-box 与 Mihomo 解包到临时目录；Nginx 使用官方签名密钥验证 `Release.gpg → Release → Packages → .deb`，同样只解包。下载缓存位于被 Git 忽略的 `.test-runtime/core-archives`。

最终单元回归：114 项通过，shell 入口语法检查通过。以下是实际核心运行结果，而非 mock 校验：

- sing-box 1.14.3 对 20 种本地协议/传输配置执行 `check`：VMess HTTP/1；VLESS REALITY TCP/H2；VLESS、VMess、Trojan 的 TLS TCP/WS/H2/HTTPUpgrade；HY2、TUIC、AnyTLS、Shadowsocks、SOCKS。
- 同一批节点经过原始 URI 往返后，Mihomo 连接配置保持一致。
- Mihomo 1.19.32 接受完整单组配置与四来源规则合成 fixture。fixture 的每份 MRS 都由实际 Mihomo 编码，随后由实际核心解码校验。
- 负向测试将 MRS 换成无效内容并同步更新 manifest 哈希，仍被核心解码检查拒绝，确认校验不限于哈希或 YAML 语法。
- 上游真实四来源构建 `rules-38341249423-1` 的 manifest、所有文件哈希、MRS 数据和完整生成配置通过校验。该结果对应测试时的构建，不代表未来任意候选构建都已验证。
- Nginx 1.30.5 的生成配置在临时高位端口执行 `nginx -t` 并启动。普通 TLS 请求经 REALITY 回落到本地站点，实际协商 HTTP/2；独立订阅 SNI 返回生成的 HTTPS 订阅。
- Mihomo 通过 REALITY TCP/Vision、HY2 和 VMess HTTP/1 连接 sing-box，读取仅监听 loopback 的测试源站内容。错误 REALITY/VMess UUID 与错误 HY2 证书 pin 都被拒绝。
- 事务健康检查实际使用的 `probe.local_nodes` 也在同一运行拓扑通过；测试仅在子进程环境中通过 `SSL_CERT_FILE` 信任测试证书，不关闭普通证书验证。

证书是临时测试证书，不申请公开证书，不修改系统信任库。测试只把公开监听地址改成 loopback 高位端口并重定位文件路径，保留生成的 SNI 分流和 REALITY 回落关系。所有测试进程会在 `finally` 中退出，临时凭证与运行目录随后删除。

单元测试还覆盖 URI 未知参数与静默降级拒绝、旧 Shadowsocks 编码保真、证书 pin 保留、TLS 开关冲突、单组约束、历史路由的精确退役、令牌撤销不能被回滚复活、精确 Host/路径、HEAD、重复请求头拒绝、坏 bundle 重载保留旧版本、规则哈希与同 tag 篡改拒绝、事务中断恢复、遗漏证书 hook 的定时补偿、旧 Nginx 语法与模块包选择。它们不能替代真实网络验证。

尚需在对应环境验收：Debian 13、Ubuntu 24.04 与 arm64 安装；生产证书自然到期后的实际更换；长连接与实际套餐流量；真实旧 Caddy/订阅部署的停机切换与恢复；客户端 GUI 行为；不同中国境内网络的直连质量。单台测试服务器通过的部分不能推广到这些未验证条件。

`sb capabilities` 对宽泛协议类别保守保留 `end_to_end_verified=false`：例如本次 REALITY TCP 流量通过，不意味着该类别下所有 VLESS 传输都经过流量测试。部署验收应同时参考这里列出的具体组合。
