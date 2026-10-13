"""Chinese task-oriented help, safe to display before a server is installed."""
from __future__ import annotations

from textwrap import dedent


OVERVIEW = """
sb — 订阅与节点管理

最常用的操作
  sb sub name "最伟大的派送员"  # 修改客户端导入时显示的订阅名称
  sb sub name                  # 查看当前订阅名称
  sb sub url                   # 查看订阅地址，用于导入客户端
  sb status                    # 查看节点、域名与服务状态
  sb check                     # 检查配置、证书与服务是否正常

修改订阅地址
  sb sub path private          # 修改路径前缀；原地址继续可用
  sb sub rotate                # 更换随机密钥，全部旧链接立即失效
  轮换后用 sb sub url 获取新地址，并重新导入客户端。

按操作查看详细帮助
  sb help sub                  # 订阅名称、地址、模板和流量信息
  sb help node                 # 添加、导入、改名与停用节点
  sb help domain               # 更换网站域名或订阅域名
  sb help site                 # 更换网站首页
  sb help rules                # 规则更新
  sb help cert                 # 证书状态与续期
  sb help transaction          # 变更记录与恢复
  sb help install              # 首次安装
  sb help migrate              # 旧部署迁移
  sb help update               # 更新管理脚本

sub 是 subscription 的简写，旧命令继续可用。命令参数详情用 -h，例如 sb node add -h。
帮助无需 root；管理操作请在服务器上以 root 执行。订阅地址含访问密钥，请勿公开。
"""


TOPICS = {
    "subscription": """
订阅管理 — sb sub（等同于 sb subscription）

名称与导入
  sb sub name                       # 查看订阅名称
  sb sub name "最伟大的派送员"       # 自定义客户端导入时的名称
  sb sub url                        # 查看 YAML 与 raw 订阅地址
  通常将 YAML 地址导入 Mihomo / Clash 客户端。改名不改变订阅地址或节点名称。
  已导入的订阅可能保留客户端本地名称，可在客户端改名或重新导入。

地址与密钥
  sb sub path private               # 将路径前缀改为 private
  sb domain subscription sub.example.com  # 更换订阅域名；须先配置 DNS
  sb sub aliases                    # 查看仍可用的历史域名与路径
  sb sub retire old-sub.example.com old/path  # 停用指定历史地址
  sb sub rotate                     # 更换随机密钥，全部旧链接立即失效
  修改域名或前缀会保留旧地址；rotate 会撤销全部旧链接，回滚也不会恢复。
  轮换后运行 sb sub url 获取新地址，再到客户端重新导入。

客户端配置与手工流量信息
  sb sub template                   # 查看当前客户端配置模板
  sb sub template --file /root/client.yaml  # 应用 YAML 模板覆盖
  sb sub metadata                   # 查看手工填写的流量、到期和重置信息
  sb sub metadata --file /root/traffic.json  # 应用 JSON 信息
  流量单位为字节；upload、download、total 必须一起填写。这不是实时流量统计。
  客户端收到每 12 小时更新的建议；实际周期由客户端设置决定。

名称含空格时请保留引号。订阅地址含访问密钥，请勿公开。
参数详情：sb sub name -h、sb sub template -h。
""",
    "node": """
节点管理 — sb node

查看与改名
  sb node list                      # 列出节点及其 ID，不显示密码
  sb node show NODE_ID               # 查看一个节点的公开配置
  sb node rename NODE_ID "新的节点名"  # 修改节点名称
  NODE_ID 替换为 sb node list 中的 id；订阅整体改名请用 sb sub name。

添加与导入
  sb node add --name "第二个 REALITY"
  sb node add --name "备用 HY2" --protocol hysteria2 --port 24443
  sb node import --file /root/links.txt --name "外部节点"
  add 创建本机节点，需确保对应端口可从公网访问。其他协议参数见 sb node add -h。
  默认 REALITY 继续使用 TCP 443；相同 SNI 共用监听密钥和独立 UUID，新 SNI 自动分配内部监听。
  同 SNI 的传输和路径须一致；不同组合请指定独立公网端口或另一个已受管 SNI。
  import 从本地文件导入分享链接；不抓取远程订阅。批量导入使用链接各自的节点名称。

修改、停用与删除
  sb node set NODE_ID --file /root/node-settings.json  # 修改公开配置
  sb node credentials NODE_ID --file /root/node-credentials.json  # 修改凭证
  sb node disable NODE_ID            # 停用节点；本机撤销其凭证，共用监听的其他用户保留
  sb node enable NODE_ID             # 重新启用节点
  sb node remove NODE_ID             # 删除非迁移保留的节点
  sb node retire NODE_ID             # 明确停止迁移保留的旧节点监听
  导入的节点仅停止订阅导出。迁移保留的旧监听不会因 disable 被关闭，需用 retire。

  sb node show NODE_ID --uri         # 明确输出包含凭证的分享链接，请勿公开
参数详情：sb node add -h、sb node import -h、sb node set -h。
""",
    "domain": """
域名管理 — sb domain

  sb domain site site.example.com          # 更换网站域名，供新增节点使用
  sb domain subscription sub.example.com   # 更换订阅域名
  sb domain retire old.example.com         # 停用一个历史域名

先将新域名全部 A/AAAA 记录指向服务器，并关闭 CDN 代理。
命令会检查解析，为管理的域名申请证书，并保留旧域名的兼容入口。
旧节点继续使用原网站 SNI；新增节点使用新域名。仍被节点依赖的域名不能直接停用。
网站与订阅使用两个独立域名；改名后的旧域名要继续保持 DNS 和证书有效。
只想修改订阅路径请用 sb sub path；只想修改客户端显示名称请用 sb sub name。
参数详情：sb domain site -h、sb domain subscription -h。
""",
    "rules": """
规则管理 — sb rules

  sb rules status                   # 查看当前规则版本与启用状态
  sb rules update                   # 手动检查并应用已构建的新规则

规则来自 Forlooong/clash-rules-mrs。服务器每 15 分钟检查一次候选构建；只下载新版本。
下载、校验或客户端配置验证失败时继续使用上一份可用规则。
首次安装使用 --without-rules 跳过规则后，也可通过 sb rules update 启用。
参数详情：sb rules update -h。
""",
    "cert": """
证书管理 — sb cert

  sb cert status                    # 查看管理域名的证书状态
  sb cert renew                     # 手动检查续期，符合续期条件时执行
  sb cert sync                      # 将已签发的新证书同步到服务

证书自动申请和续期使用 Let's Encrypt，通过公网 TCP80 验证域名。
日常无需手动续期；同步定时器会补偿证书签发后未成功加载的情况。
这里使用普通联系邮箱，不需要邮箱密码或 Cloudflare API 令牌。
deploy 是续期钩子使用的命令；需要查看参数时运行 sb cert deploy -h。
""",
    "site": """
网站首页 — sb site

  sb site show                      # 输出当前首页 HTML
  sb site set --file /root/index.html  # 用 UTF-8 HTML 文件替换首页

更换首页保留现有网站域名。更换网站域名请用 sb domain site。
首页文件上限为 1 MiB。请先将准备好的 HTML 文件放在服务器上。
参数详情：sb site set -h。
""",
    "transaction": """
变更记录与恢复 — sb transaction

  sb transaction list               # 查看配置变更记录及其 ID
  sb transaction recover            # 恢复上次被中断的变更
  sb transaction rollback TRANSACTION_ID  # 回退指定变更

TRANSACTION_ID 替换为 sb transaction list 中的事务 id。
普通变更失败时会自动回滚；断电或进程中止后，也可显式执行 recover。
回滚会恢复相关文件和配置，可能引起短暂重连；已撤销的订阅密钥不会复活。
参数详情：sb transaction rollback -h。
""",
    "install": """
首次安装 — sb install

准备两个独立域名，全部 A/AAAA 记录指向服务器并关闭 CDN 代理。
还需要普通联系邮箱、公网 TCP80/443 和 UDP443，以及完整的本项目源码或发行包。

  sb install --site site.example.com --subscription-domain sub.example.com --email admin@example.com

首次尚无 sb 命令时，在完整源码目录用 sh install.sh 加上同样参数。
安装默认创建 REALITY 与 HY2 节点、网站、证书和私有订阅。
--email 填普通邮箱地址，不是密码或 API 令牌。脚本不会修改 SSH 或防火墙。
旧部署请先查看 sb help migrate；详细安装参数用 sb install -h。
""",
    "migrate": """
迁移旧部署 — sb migrate

  sb migrate inspect                # 只审查现有部署能否迁移
  sb migrate apply --site site.example.com --subscription-domain sub.example.com --email admin@example.com --public-server OLD_SERVER

OLD_SERVER 替换为旧节点客户端一直使用的原 IP 或域名。
先运行 inspect 并检查结果；apply 会修改服务并可能引起短暂重连。
自动迁移支持可识别的 233boy sing-box/Caddy 和本项目原独立订阅服务。
旧端口、凭证、SNI、核心版本及证书 pin 会保留；不支持的配置会阻止迁移。
尚未安装 sb 时，可在完整源码目录运行 python3 -m sbmanager.cli migrate inspect。
参数详情：sb migrate apply -h。
""",
    "update": """
更新管理脚本 — sb update

  sb update VERSION                 # 更新到本项目一个明确的已发布版本

VERSION 替换为实际发行版本号。发行版须包含 code.tar.gz 和 SHA256SUMS。
命令先下载、校验并验证候选配置，再切换服务；失败时回滚。
本命令更新管理脚本；规则更新请用 sb rules update，证书续期请用 sb cert renew。
参数详情：sb update -h。
""",
    "status": """
查看当前状态

  sb status                         # 显示脱敏配置与服务状态
  sb check                          # 进一步检查完整配置、证书和服务

仅查询状态不会输出订阅令牌和节点密码。获取订阅地址请明确运行 sb sub url。
""",
    "check": """
检查部署

  sb check                          # 检查配置、证书与服务
  sb status                         # 查看当前状态，便于定位问题

本机检查不能代替从客户端网络验证公网连接；客户端仍应实际测试 REALITY 和 HY2。
""",
    "capabilities": """
查看协议支持范围

  sb capabilities                   # 显示支持的协议、传输方式和导出能力

添加本机节点请用 sb help node；不支持的组合会在变更时明确拒绝。
""",
}


def render(topic: str | None = None) -> str:
    """Return one help page; never inspect files, secrets, state, or privileges."""
    if topic is None:
        return dedent(OVERVIEW).strip() + "\n"
    topic = "subscription" if topic == "sub" else topic
    try:
        return dedent(TOPICS[topic]).strip() + "\n"
    except KeyError:
        raise ValueError(f"未知帮助主题：{topic}；运行 sb help 查看可用主题") from None
