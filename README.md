# cpa-plugin-opencode-session-mapper

CLIProxyAPI request interceptor plugin: forwards client conversation session
ids to OpenCode Zen as `x-opencode-session`, and since v0.4.0 completes the
free-tier client fingerprint upstream expects:
`x-opencode-client: cli`, `x-opencode-project: global`, a per-request
`x-opencode-request`, and the `x-opencode-session-id` session mirror.

Since 09/06 OpenCode Zen free tier rejects requests that do not look like the
official CLI with `403 FreeTierError`: custom headers (`x-opencode-client`
must be `cli`, not a proxy label), a real CLI-minted session
(`x-opencode-session`/`x-opencode-session-id`), and a request id shaped
`msg_` + 12 hex + 14 base62 that varies per request. Fabricated session ids
are rejected outright — sessions must be minted by running the real CLI once
and captured from its wire request (rotate/mint fresh ones regularly; a 403
means a stale session, while a 429 is pure per-IP rate limiting).

Exact wire snapshot captured 2026-10-19 from CLI 1.19.0
(`ai-sdk/provider-utils/4.0.23`, `bun/1.3.14`) — pin the matching
`User-Agent` per credential in `config.yaml` (see Install).

OpenCode Zen uses `x-opencode-session` (one stable ID per conversation) for
sticky routing and prompt-cache affinity. Since 09/06, requests missing this
header may error. But requests that pass through CLIProxyAPI lose the header:
executors rebuild outbound headers from scratch and only forward a small
whitelist (`Version` / `Session_id` / `User-Agent` on the codex path, nothing
extra on the openai-compat path).

This plugin restores the session signal and the fingerprint in two stages:

1. **Plugin** (`request.intercept_before` + `request.intercept_after`):
   reads the downstream client's own stable session headers and injects them
   as `X-Opencode-Session` into the execution headers, plus the
   `X-Opencode-Session-Id` mirror, a per-request `X-Opencode-Request`
   (`msg_` + 12 hex + 14 base62, derived from the host request id so both
   interceptor passes agree — generated fresh when the host provides none),
   `X-Opencode-Client: cli`, and `X-Opencode-Project: global`.
2. **Config** (`headers:` with `$` references on each zen credential):
   resolves the injected values onto the actual upstream wire request via
   `X-Opencode-Session: $X-Opencode-Session` and friends.

Session source priority (the first present, valid source wins):

| Header | Client |
|---|---|
| `Session-Id` / `Session_id` | codex CLI |
| `Thread-Id` / `Thread_id` | codex CLI thread (= conversation) |
| `X-Claude-Code-Session-Id` | claude code |
| `X-DeepSeek-Harness-Session-Id` | dsh / deepseek-harness (native provider) |
| `X-Session-Affinity` | dsh pi-ai (anthropic-messages / openai-completions) |
| `X-Session-Id` | generic / opencode-ish clients |
| `X-Client-Request-Id` | last resort (dsh pi-ai openai-responses) |

Rules:

- A client-sent `x-opencode-session` (real opencode CLI) is authoritative and
  never overridden.
- Client-supplied `x-opencode-session-id` / `x-opencode-request` /
  `x-opencode-project` / `x-opencode-client` values pass through unchanged
  (with the bare `X-Opencode-Session` re-injected only when the client didn't
  send it); official CLI values are substituted for anything missing.
- A client-supplied header always outranks the metadata fallback below; a
  request that identifies itself is never overridden.
- No header at all → the **metadata fallback** below, then no-op.
- Session identifiers are trimmed, limited to 1024 bytes, and rejected if
  they contain Unicode control characters. Conflicting repeated or
  case-variant values fail closed instead of depending on Go map iteration
  order. A present but invalid higher-priority source also blocks lower
  sources and the metadata fallback rather than allowing header poisoning.
  The same fail-closed treatment applies to the fingerprint headers above.
- Serialized native interceptor envelopes larger than 64 MiB (fixed,
  non-configurable cap) are rejected before any pointer dereference, before
  any allocation, and before the C `size_t` -> `C.int` conversion feeding
  `C.GoBytes`; the exported ABI boundary also contains panics and returns a
  structured failure envelope. The plugin decodes only a narrow projection
  (`RequestID`/`Headers`/`Metadata`) and does not base64-decode or retain
  `Body`, which the host base64-encodes into the envelope at roughly 4/3 of
  the raw body size — so
  legitimate requests carrying multi-megabyte bodies are accepted and still
  map normally.

### Metadata fallback

Some clients send no session header at all. DeepSeek Harness is the motivating
case: its pi-ai transport gates session headers behind `sendSessionAffinityHeaders`,
which the dsh adapter marks `withhold` — so nothing reaches the wire and there is
nothing to map.

For those requests the plugin reads `Metadata.canonical_session_id` from the
interceptor payload, which the host computes from the source protocol and the
client's own session id (`claude:<uuid>`, `codex:<id>`, …). It is populated only
on the **after-auth** pass, which is why it is a fallback rather than a source.

`derived_session_id` and `lcp_affinity_session_id` are deliberately **not** used:
the former is absent from this payload on v7.2.157, and core documents the latter
as unusable for provider conversation identity.

**Known limitation.** `canonical_session_id` is stateless: two independent
conversations whose content is byte-identical (same opening message, same tools)
hash to the same value, so they share one upstream session. This affects
prompt-cache affinity only, never correctness. Distinguishing such conversations
requires the client to send a real session id.

Verified live against zen:

- `muse-free` (codex `/v1/responses`, client `Session-Id`) and `mimo-free`
  (openai-compat `/v1/chat/completions`, client `X-DeepSeek-Harness-Session-Id`)
  arrive upstream carrying the mapped `X-Opencode-Session`.
- `deepseek-flash` with **no** session header at all (dsh 0.1.5,
  `/v1/chat/completions`) now returns 200 instead of upstream
  `MissingSessionID` 400; the derived id stays stable as a conversation grows
  turn by turn and differs between conversations.

v0.4.0 fingerprint values (`cli` / `global` / `msg_…` request ids) follow the
2026-10-19 CLI 1.19.0 wire snapshot from the free-tier analysis notes; live
zen re-verification of that fingerprint is pending, and the snapshot may rot
as the CLI updates — re-capture the wire request when upstream changes its
client and `403` starts reappearing.

## Capability

- `request_interceptor` — runs before and after credential selection.

## Install

Add the store source and enable the plugin in `config.yaml`:

```yaml
plugins:
  enabled: true
  store-sources:
    - https://raw.githubusercontent.com/Lynn-Becky/cpa-plugin-opencode/main/registry.json
  configs:
    opencode-session-mapper:
      enabled: true
      priority: 1
```

Then add `$` forwarding headers to every zen credential so the injected
values reach the wire, and pin the captured CLI `User-Agent` fingerprint. On
each `codex-api-key` entry whose `base-url` contains `opencode.ai`, and on
the `openai-compatibility` provider pointing at `https://opencode.ai/zen/v1`:

```yaml
headers:
  X-Opencode-Session: $X-Opencode-Session
  X-Opencode-Session-Id: $X-Opencode-Session-Id
  X-Opencode-Request: $X-Opencode-Request
  X-Opencode-Client: $X-Opencode-Client
  X-Opencode-Project: $X-Opencode-Project
  User-Agent: opencode/1.19.0 ai-sdk/provider-utils/4.0.23 runtime/bun/1.3.14
```

`$Name` copies the value from the (plugin-augmented) execution headers; when
absent the header is omitted. When a new CLI pins its fingerprint (a fresh
wire snapshot), update both the `User-Agent` here and any captured values.

Sessions must be real CLI-minted exchange ids (`ses_...` captured from the
official CLI's actual requests); fabricated ids fail with 403 regardless of
the rest of the fingerprint. Restart CLIProxyAPI (plugins load at startup):

```bash
docker restart cli-proxy-api
```

Verify:

```bash
docker logs cli-proxy-api | grep opencode-session-mapper
```

## Build

The CLIProxyAPI runtime image is Debian-based (glibc). Building with the
alpine Go image produces a musl-linked `.so` that fails to `dlopen` at runtime
(`libc.musl-x86_64.so.1: cannot open shared object file`). The build script
pins the Go patch release and container image digest, uses module read-only
mode, runs the full verification suite, embeds VCS provenance, and injects the
requested registration version. Its default output is repository-local
`dist/local/linux_amd64/`, never a live plugin mount.

Use it from a clean Git checkout:

```bash
./build.sh
# Override only when an explicit staging directory is desired:
PLUGIN_OUT_DIR=/tmp/opencode-session-mapper-build ./build.sh
# Release automation may also inject another prerelease/test identity:
PLUGIN_VERSION=0.4.0-dev PLUGIN_OUT_DIR=/tmp/opencode-session-mapper-build ./build.sh
```

## Test

```bash
test -z "$(gofmt -l ./*.go ./.github/scripts/*.go)"
go mod verify
go vet ./...
go vet ./.github/scripts
go test ./...
go test ./.github/scripts
go test -race ./...
```

## Release

Tags matching `v*` trigger the GitHub Actions release workflow. It builds on
native runners for Linux amd64/arm64, macOS amd64/arm64, and Windows amd64,
then publishes immutable `<id>_<version>_<goos>_<goarch>.zip` archives plus
`checksums.txt`. Every archive contains exactly one root library named
`opencode-session-mapper.so`, `.dylib`, or `.dll`.

`v0.3.1` supersedes `v0.3.0`: the v0.3.0 behavior was correct, but its release
binary still registered the stale source default `0.1.0`. The corrected
release uses a linker-injected version and verifies registration before
packaging. Published tags and assets are never replaced.

`v0.3.2` supersedes `v0.3.1`: raises the fixed envelope gate from 8 MiB to
64 MiB so legitimate Host-shaped payloads carrying multi-megabyte
(base64-encoded) bodies are accepted into normal header/metadata mapping;
mapping behavior is otherwise unchanged. Published tags and assets are never
replaced.

`v0.4.0` completes the free-tier client fingerprint per the 2026-10-19 wire
snapshot: default `X-Opencode-Client` is now `cli` (was `cliproxy`),
`X-Opencode-Project: global` is injected, `X-Opencode-Request` carries a
per-request `msg_` + 12 hex + 14 base62 id derived from the host request id
(random when the host supplies none), and `X-Opencode-Session-Id` mirrors the
mapped session. Client-supplied values for these headers pass through
unchanged; conflicting case-variant pairs fail closed. Credential configs
must add the new `$` forwarding headers and pin `User-Agent`. Published tags
and assets are never replaced.

## License

MIT
