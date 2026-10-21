<p align="center">
  <a href="https://zentinelproxy.io">
    <picture>
      <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/zentinelproxy/design/main/marks/lockup/zentinel-lockup-dark.svg">
      <img alt="Zentinel" src="https://raw.githubusercontent.com/zentinelproxy/design/main/marks/lockup/zentinel-lockup-light.svg" height="52">
    </picture>
  </a>
</p>

<h3 align="center">Rate limit agent (deprecated)</h3>

<p align="center">Per-key request rate limiting on the request headers, as an external agent. Superseded by the rate limiting built into Zentinel.</p>

<p align="center">
  <a href="https://github.com/zentinelproxy/zentinel-agent-ratelimit/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/zentinelproxy/zentinel-agent-ratelimit/actions/workflows/ci.yml/badge.svg"></a>
  <img alt="License: Apache-2.0" src="https://img.shields.io/badge/license-Apache--2.0-9b4d8a?style=flat&labelColor=1f161e">
  <img alt="Rust: 1.94.1+" src="https://img.shields.io/badge/rust-1.94.1%2B-f68d31?style=flat&labelColor=1f161e&logo=rust&logoColor=white">
  <img alt="Agent protocol: v2" src="https://img.shields.io/badge/agent%20protocol-v2-f68d31?style=flat&labelColor=1f161e">
</p>

<p align="center">
  <a href="https://registry.zentinelproxy.io/ratelimit/">Registry</a> &middot;
  <a href="https://docs.zentinelproxy.io">Docs</a> &middot;
  <a href="https://github.com/zentinelproxy">All repositories</a>
</p>

> [!WARNING]
> **Deprecated.** This agent is deprecated since Zentinel 26.01 and is kept
> only for existing deployments. Use the built-in `rate-limit` filter instead:
> it runs in the proxy (no socket hop), applies `burst`, supports `delay` and
> `log-only` actions, and can share buckets across instances through Redis or
> memcached. Reference: [Filters: Rate limiting](https://docs.zentinelproxy.io/configuration/filters/#rate-limiting).

## Migrating to the built-in filter

```kdl
filters {
    filter "api-limit" {
        type "rate-limit"
        max-rps 100
        burst 200
        key "client-ip"
        on-limit "reject"
    }
}

routes {
    route "api" {
        matches {
            path-prefix "/api/"
        }
        upstream "backend"
        filters "api-limit"
    }
}
```

| This agent | Built-in `rate-limit` filter |
|---|---|
| `requests-per-second` | `max-rps` |
| `burst` (parsed, not applied) | `burst` |
| `key: client_ip` | `key "client-ip"` |
| `key: path` | `key "path"` |
| `key: global` | `key "route"` |
| `key: !header X-API-Key` | `key "header:X-API-Key"` |
| `status-code`, `message` | `status-code`, `message` |
| `dry-run` | `on-limit "log-only"` |
| rule `conditions` | one filter per route |

Remove the `agents` block entry and the agent filter once the built-in filter is in place.

## What it does (legacy)

The agent receives `request_headers`, picks the first rule whose conditions
all match (or the default rule), derives a key from the request and checks a
per-key limiter. Over the limit, it blocks with the rule's status (429 by
default) and `X-RateLimit-Limit`, `X-RateLimit-Remaining: 0`,
`X-RateLimit-Reset` and `Retry-After: 1`. Allowed requests are forwarded with
`X-RateLimit-Rule` and `X-RateLimit-Key` added to the upstream request.
Limiters are kept in memory per agent process; idle ones are dropped after
five minutes.

Known limits: `burst` is read but not applied (the bucket size equals
`requests-per-second`), and a limiter is keyed by the key value alone, so two
rules that produce the same key share the limiter created first.

## Install

```bash
zentinel bundle install ratelimit
```

Or from the repository (the crate is not on crates.io):

```bash
cargo install --git https://github.com/zentinelproxy/zentinel-agent-ratelimit
```

Release binaries (`zentinel-ratelimit-agent-<version>-<platform>.tar.gz`) for
`linux-x86_64`, `linux-aarch64` and `darwin-aarch64` are on the
[releases page](https://github.com/zentinelproxy/zentinel-agent-ratelimit/releases).

## Configuration

```bash
zentinel-ratelimit-agent --socket /var/run/zentinel/ratelimit.sock --config ratelimit.yaml
```

```kdl
agents {
    agent "ratelimit" type="rate_limit" {
        unix-socket "/var/run/zentinel/ratelimit.sock"
        events "request_headers"
        timeout-ms 50
    }
}

filters {
    filter "ratelimit" {
        type "agent"
        agent "ratelimit"
        failure-mode "open"
    }
}
```

Attach it to a route with `filters "ratelimit"`.

| Option | Default | Meaning |
|---|---|---|
| `--socket`, `-s` / `RATELIMIT_AGENT_SOCKET` | `/tmp/ratelimit-agent.sock` | Unix socket to listen on |
| `--grpc-address` / `RATELIMIT_AGENT_GRPC_ADDRESS` | none | Listen on gRPC (e.g. `0.0.0.0:50051`) instead of the socket |
| `--config`, `-c` / `RATELIMIT_AGENT_CONFIG` | none | YAML rules file; without it, one client-IP rule from the flags below |
| `--default-rps` / `RATELIMIT_AGENT_DEFAULT_RPS` | `100` | Requests per second of the default rule (no `--config`) |
| `--default-burst` / `RATELIMIT_AGENT_DEFAULT_BURST` | `200` | Burst of the default rule (not applied, see above) |
| `--dry-run` / `RATELIMIT_AGENT_DRY_RUN` | `false` | Log instead of blocking (no `--config`; with a file, use its `dry-run`) |
| `--cleanup-interval` / `RATELIMIT_AGENT_CLEANUP_INTERVAL` | `60` | Seconds between sweeps of idle limiters |
| `--log-level`, `-l` / `RATELIMIT_AGENT_LOG_LEVEL` | `info` | Log level (`RUST_LOG` takes precedence) |

Rules file (keys are kebab-case; keys and conditions are YAML tags):

```yaml
default:
  name: default
  key: client_ip            # client_ip, path, method, global, !header <name>, !composite [...]
  requests-per-second: 100
  burst: 200

rules:
  - name: uploads
    key: client_ip
    requests-per-second: 10
    burst: 10
    conditions:             # all must match: !path_prefix, !path, !method [..], !header {name, value}
      - !path_prefix /api/v1/upload
  - name: per-api-key
    key: !header X-API-Key
    requests-per-second: 50
    burst: 50
    status-code: 429
    message: Too many requests

dry-run: false
```

The proxy does not forward an agent block's `config { }` to the agent, so
configure it with the flags and file above.

## Development

```bash
cargo test
cargo clippy --all-targets -- -D warnings
```

## Related

- [Built-in rate limiting](https://docs.zentinelproxy.io/configuration/filters/#rate-limiting)
- [Registry page](https://registry.zentinelproxy.io/ratelimit/)
- [Agent protocol v2](https://docs.zentinelproxy.io/agents/v2/)
- [Zentinel](https://github.com/zentinelproxy/zentinel)

## License

Apache-2.0, see [`LICENSE`](LICENSE).

---

<p align="center">
  <sub>Part of <a href="https://zentinelproxy.io">Zentinel</a>, the security-first reverse proxy. The shisa guards the gate.</sub>
</p>
