# Approved implementation contract

Baseline: Forlooong/sing-box 2d78583b5aecccb0da0148a816bc1495a284509f.
Approved 2026-10-13: standalone stack on each host; Nginx TCP SNI routing,
self-hosted REALITY target, trusted HY2, private single-group Mihomo subscription,
four-source rule snapshots, and compatibility-preserving legacy migration.
No production deployment is performed by local development tests.

## Shared module contract

Python package `sbmanager` (Python >=3.11, PyYAML), no shell interpolation.
All paths below are logical Linux paths; tests map them under a temporary root.
`state.json` and `secrets.json` live under `/etc/sb/` and are root-owned.
State and secrets are passed separately to pure renderers. Renderers return
`dict[str, bytes]` keyed by absolute Linux paths. Services never read management
secrets directly. The transaction writer sets modes from explicit path policies.

State schema v1:

```json
{
  "schema_version": 1,
  "installation_id": "uuid",
  "domains": {"site": "site.example.com", "subscription": "sub.example.com", "site_aliases": [], "subscription_aliases": []},
  "email": "admin@example.com",
  "ports": {"reality": 2443, "site_tls": 8443, "sub_tls": 8444, "sub_http": 8767, "hy2": 443},
  "site": {"root": "/var/www/sb-site"},
  "subscription": {"prefix": "private", "aliases": [], "metadata": {}, "template": {}},
  "nodes": [],
  "rules": {"enabled": true, "active_build": null},
  "legacy": {"entries": [], "files": {}, "services": []}
}
```

Subscription aliases are `{domain, prefix, suffix}` objects; suffix is empty
or `/clash.yaml` (legacy), and raw remains the corresponding `/raw` endpoint.
All aliases use the current token, so rotating it revokes every old route.
Site aliases are old domain strings; retiring one must check dependent nodes.

Node (public) required fields: `id`, `name`, `protocol`, `source` (`local`,
`uri`, `legacy`), `enabled`, `server`, `port`, `transport`, `security`.
Optional fields: `sni`, `flow`, `public_key`, `short_id`, `fingerprint`,
`obfs`, `alpn`, `method`, `path`, `host`, `legacy`, `listen_port`, `listen`.
`protocol` uses core names (`vless`, `hysteria2`, `shadowsocks`, etc.).
Legacy configs may retain `legacy_config` references but never contain secrets.
Credentials: `secrets["nodes"][node_id]` holds uuid/password/private_key/obfs_password.
`secrets["subscription_token"]` is secrets.token_urlsafe(32).
Never expose private_key in a client config or raw URI.

## Module ownership and interfaces

- Root: state.py, transaction.py, cli.py, system.py, updates.py, shell integration,
  install.sh, workflows, integration tests, documentation.
- Subscription agent: protocols.py, subscription.py, rules.py, server.py,
  tests/test_protocols.py, test_subscription.py, test_rules.py, template.yaml.
  `protocols.parse_uri(uri) -> (node_dict, credentials_dict)`;
  `protocols.to_mihomo(node, credentials) -> dict`;
  `protocols.to_uri(node, credentials) -> str`;
  `subscription.render(state, secrets, snapshot=None) -> dict[path, bytes]`.
  Export runtime config/artifacts under `/var/lib/sb/subscription/`; local health
  route `/healthz`, never expose the management API. snapshot=(manifest, inline).
  `rules.py` wraps vendored runtime with explicit stage/validate/activate separation.
- Network agent: render.py, certificates.py, assets/index.html, tests/test_render.py,
  test_certificates.py; `render.render(state, secrets) -> dict[path, bytes]`.
  Generate `/etc/nginx/sb/` snippets, `/etc/sing-box/sb/config.json` for NEW local
  nodes, systemd units (new `sb-sing-box`, `sb-subscription`, `sb-rules`), cert hook.
  Do not overwrite global nginx.conf; installer injects one owned top-level stream
  include and one http include, after checking existing config ownership.
  Runtime code is installed at `/opt/sb/current`; core at `/opt/sb/bin/sing-box`.
- Migration agent: migration.py, tests/test_migration.py, docs/migration.md;
  `inspect(root=Path('/')) -> dict` read-only report;
  `prepare(report, state, secrets) -> (new_state, new_secrets, files_dict)` pure.
  Include blockers and compatibility entries; never execute old shell code.
  Unknown Caddy/global rules/source-IP dependency blocks apply; preserve all old
  runtime secrets and bytes in protected backup, no raw secrets in inspect report.

## Non-negotiable behavior

One `节点选择` select group. URI import deduplicates connections, not names.
New routes `/<prefix>/<token>` and `/raw`; legacy paths remain aliases.
Preserve old SNI/credentials/cert pins/ports on migration; new secure nodes coexist.
Domain changes retain aliases until explicit retirement; token rotation immediate.
No source IP assumptions behind stream (no PROXY protocol in v1).
No remote subscription fetching, no telemetry, no public administrative API.
All writes checked/staged/backed up/healthchecked; root mutation only on Linux.
No automatic firewall disabling, SSH changes, Caddy directory deletion, or latest
version downloads. Certificate and artifact downloads must validate TLS.
Rule updates never run on subscription requests, and do not rebuild MRS.
Unknown/unsupported protocols must not silently become TCP or disappear.
New installs Debian12/13 or Ubuntu24.04; pinned sing-box1.14.3, Mihomo1.19.32,
Nginx1.30.5 as candidate validation matrix; preserve old core on migration.

## Existing distribution Nginx compatibility

Migration keeps an installed Nginx >=1.22 when no preserved backend requires
HTTP/2 upstream proxying. `state.nginx.version` records the detected executable
version; `state.nginx.legacy_http2_directive` selects `listen ... ssl http2` on
versions before 1.25.1. The same syntax adjustment applies to preserved WS and
HTTPUpgrade frontends. A preserved `proxy_http_version 2` backend still requires
Nginx >=1.29.4; the migration never upgrades that existing web server implicitly.
New installations continue to use the pinned official signed 1.30.5 package.

Distribution builds with a dynamic stream module are load-tested against the
actual Nginx executable. If the module is missing, only an exact package-version
match of `libnginx-mod-stream` is eligible; APT simulation must show no removal
or replacement of the installed Nginx packages. If the matching package is no
longer available, migration stops and requires explicit package maintenance.
An owned load directive is added only when the effective Nginx configuration
does not already load the module, and preparation rollback restores that file.

Each certificate's actual Certbot renewal webroot is retained under
`state.certificates.webroots`. Only `/var/lib/sb/acme` and the previous standalone
`/var/www/subscription-acme` are recognized. A 15-minute `sb-cert-sync.timer`
retries deployment of already-issued certificate changes after a deploy hook
collides with the manager lock; it does not request another certificate.

Unit tests cover version selection, migration syntax, exact module package
selection, and rejection of unintended Nginx upgrades. Syntax validation with
the cached Nginx 1.30.5 executable is not proof of execution on an old 1.22/1.24
binary; that distribution matrix remains a staging acceptance check.
The syntax boundaries follow the official [HTTP/2 module documentation](https://nginx.org/en/docs/http/ngx_http_v2_module.html)
and [HTTP proxy version documentation](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_http_version).
