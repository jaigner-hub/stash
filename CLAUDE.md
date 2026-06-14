# CLAUDE.md

Orientation for working in this repo. Keep it current when the shape of the
project changes.

## What this is

`stash` is a lightweight, **single-binary, highly-available secrets manager** —
HA secret storage that's easy to stand up: no external DB, no Redis, no
Kubernetes. One Go binary, state replicated with **embedded Raft** (`hashicorp/raft`
over a bbolt log). It's a **hobby project, not production-ready**; it's the
build-your-own alternative to keygrip's ADR-0018 (self-hosted Infisical). For the
keygrip dev pair, SOPS stays authoritative until stash is battle-tested.

The README is the user-facing tour (architecture diagrams, API table, quickstart).
This file is the contributor's map.

## Build / test / run

```sh
make build      # -> ./stash (version stamped from `git describe` via -ldflags)
make release    # CGO_ENABLED=0 static linux/amd64 binary for deploying to the cluster
make test       # go test ./...
make vet        # go vet ./...
make fmt        # gofmt -w .
make run-demo   # build + run a throwaway single-node cluster (Ctrl-C to stop)
```

- **Always run `make test` and `make vet` before committing.** The suite is fast
  except `internal/cluster` (real Raft, ~10–12s).
- **`make release` (static, `CGO_ENABLED=0`) is mandatory for deploys** — a plain
  `make build` is glibc-dynamic and won't run on the NixOS witness node.
- Standard library + four deps only: `hashicorp/raft`, `hashicorp/raft-boltdb/v2`,
  `go.etcd.io/bbolt`, `golang.org/x/crypto`. **Don't add dependencies casually** —
  the embedded web console (`internal/ui`) is deliberately dependency-free vanilla
  JS/HTML served via `go:embed`. Keep it that way.

## Architecture

Request path: **reads are served locally** (a follower may be slightly stale);
**writes are accepted only on the leader**, and a follower transparently
reverse-proxies a write to the current leader (marked with the `X-Stash-Forwarded`
header so the leader doesn't double-audit it).

Envelope encryption, **performed once on the leader** so every replica holds
byte-identical ciphertext:

```
unseal key (KEK)  → unwraps →  data key (DEK)  → encrypts →  secret values
(memory/tmpfs only)            (random, replicated wrapped)   (XChaCha20-Poly1305, AAD="secret:<path>")
```

HA uses an odd voter count: a 2-keyed-node pair gets a third vote from a
**witness** started with no `-unseal-key` — it's **sealed**, replicates ciphertext,
and can never read plaintext (and yields leadership if it ever wins an election).

The Raft **FSM is the source of truth for derived state** — version sequence
numbers, pruning, etc. are computed inside `internal/cluster/fsm.go` so every
replica derives an identical history. Don't compute replicated state outside the FSM.

### Package map

| Package | Responsibility |
|---|---|
| `internal/crypto`  | AEAD seal/open + key generation (XChaCha20-Poly1305) |
| `internal/store`   | bbolt-backed encrypted KV; KEK→DEK envelope; versions (`MaxVersions`=10); snapshot export/import |
| `internal/cluster` | Raft FSM + node lifecycle (bootstrap, join, leader-forwarding, sealed witness), `ClusterStatus` |
| `internal/server`  | HTTP/JSON API; auth (bearer tokens + path-prefix ACLs); writes forwarded to leader |
| `internal/audit`   | per-node, append-only, **hash-chained** audit log in its own `audit.db` |
| `internal/pki`     | stash-as-CA: issues node leaf certs for inter-node mTLS (CA travels in the join token) |
| `internal/agent`   | `stash agent`: render secrets to a file (template or `-auto`) with a last-good cache |
| `internal/ui`      | embedded web console (dependency-free), served at `/` |
| `cmd/stash`        | CLI dispatch: `init`, `server`, `join`, `token`, `agent`, `version` |

## Conventions

- **TLS/mTLS is on by default**; pass `-no-tls` for local dev. The API is HTTPS +
  bearer token; inter-node Raft + write-forwarding use mutual TLS under stash's own CA.
- **Open mode**: when no identities exist yet, the API is unauthenticated (logs a
  warning) so an upgrade can't lock you out. Creating the first identity flips on
  enforcement. `/v1/health` (and `/metrics`) are always open.
- **Tests**: standard `go test`, table-driven where it helps. The HTTP layer tests
  against an in-memory `fakeBackend` (`internal/server/server_test.go`) — no real
  network/Raft. Add a fake method when you extend the `Backend` interface.
- **Node restart is stateless to operate**: `stash server -data DIR -unseal-key key`
  recovers identity/addresses from `cluster.json`; no re-join.
- Default ports: API `:8200`, Raft `:8300`.

## Gotchas

- **Killing demo processes**: use `pkill -x stash` (exact match). `pkill -f "stash
  server"` self-matches the shell command and kills your own session.
- **`init && server &`** makes `$!` the subshell PID, not stash's — use `pgrep -x stash`.
- The join token **bundles the unseal key by default** (one value to move) — treat
  it as sensitive as the master key. Use `--no-key` for witnesses.

## Deployment

Single static binary per node. The live cluster is three nodes on the keygrip
tailnet: two keyed nodes (`vent.dog`, `vent.dog2` — Ubuntu, systemd
`stash.service`, binary at `/usr/local/bin/stash`) and a sealed witness
(`monitor` — homelab NixOS, `stash-witness.service`, binary at `/opt/stash/stash`,
managed from `~/Projects/nixos-config`). The two keyed boxes also run
`stash-agent.service`, deployed by the keygrip Ansible roles (`stash`, `stash_agent`)
and monitored by the observability stack (blackbox `/v1/health` probe + alerts).
Rolling upgrades are order-independent (backward-compatible API, no on-disk format
change). Build with `make release`, then push the binary and restart per node.
