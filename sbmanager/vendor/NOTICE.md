# Vendored rule snapshot runtime

`snapshot.py` is copied from `Forlooong/clash-rules-mrs/runtime/snapshot.py`
(local reviewed source, 2026-10-13) under GPL-3.0, the same license as this
repository. Upstream: https://github.com/Forlooong/clash-rules-mrs

The manager imports schema validation and deterministic rule assembly. It does
not invoke the vendored command-line entry point or its automatic activation.
`sbmanager.rules` provides transaction-only activation and preserves the user's
client template instead of applying the vendor assembler's unrelated overrides.
Rule snapshots retain the four sources' notices and source archives; their
individual licensing is recorded in each build manifest.
