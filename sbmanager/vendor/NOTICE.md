# Vendored rule snapshot runtime

`snapshot.py` and `dns.py` are copied from `Forlooong/clash-rules-mrs/runtime/`
(local reviewed source, 2026-10-14) under GPL-3.0, the same license as this
repository. Upstream: https://github.com/Forlooong/clash-rules-mrs

The manager imports schema validation, deterministic rule assembly and v2 DNS
assembly. It does
not invoke the vendored command-line entry point or its automatic activation.
`sbmanager.rules` provides transaction-only activation and preserves unrelated
client settings. Legacy v1 DNS is unchanged; balanced-v2 manages DNS only during
the final full-subscription compilation. Rule snapshots retain the four sources'
notices; v2's full source archives and per-rule audit live in a separate release
artifact referenced by the manifest. Individual licensing is recorded by the
rule build's notice.
