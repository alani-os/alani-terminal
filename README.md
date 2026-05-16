# alani-terminal

Interactive shell and CLI surface for inspection, service control, cognition experiments, and debugging.

| Field | Value |
|---|---|
| Status | Experimental Rust skeleton |
| Tier | MVK required |
| Owner | Terminal team |
| Aliases | None |
| Architectural dependencies | `alani-runtime`, `alani-lib`, `alani-protocol`, `alani-observability` |

## Quick Start

```bash
cargo fmt -- --check
cargo test --all-features
cargo test --no-default-features
cargo check --no-default-features
cargo clippy --all-features -- -D warnings
```

## Repository Layout

- `src/commands.rs` owns command descriptors, command context, request/result records, and fixed-capacity registration.
- `src/commands.rs` also provides built-in descriptor metadata for help, inspect, trace, service-control, cognition, debug, exit, and echo commands.
- `src/parser.rs` owns conservative command-line tokenization, parser policy, fixed-capacity script planning, and sensitive literal rejection.
- `src/session.rs` owns terminal session descriptors, principal metadata, lifecycle state, bounded history, unlock flow, and command context derivation.
- `src/format.rs` owns output format descriptors, diagnostic records, command result output, severity, style, and redaction-aware formatting.

## Feature Flags

- `std` is enabled by default for host-mode tests and the small CLI binary.
- `--no-default-features` builds the library as `no_std`.

## Security And Observability Notes

Security-sensitive command and session operations fail closed. Service-control, debug, cognition, authority, policy, persistent-state, and release-evidence changes must be represented as audit-required command descriptors or session events. Public APIs carry `TraceContext`, `DataClass`, and `RedactionState` so terminal frontends can propagate observability metadata without depending on sibling private modules.

## Troubleshooting

- `reserved_bits` means a caller supplied unknown rights, feature, or trace flag bits.
- `sensitive_input` means the parser saw a literal such as `token=` while sensitive literals were disabled by policy.
- `audit_required` means the command or session requires audit evidence but the caller lacks audit authority or an audit sink.

Keep public API changes synchronized with `alani-spec/docs/repositories/alani-terminal.md`, Doc 39, Doc 40, Doc 42, and Doc 43.
