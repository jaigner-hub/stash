# stash

A lightweight, single-binary, highly-available secrets manager. The goal: HA
secret storage that is genuinely *easy* to stand up — no external database, no
Redis, no Kubernetes. One Go binary that does it all, replicating state with
embedded Raft.

> **Status: milestone 2 — HA via embedded Raft.** This is a hobby project and is
> **not production-ready**. Do not trust it with real secrets yet. (For the
> keygrip dev pair, SOPS stays authoritative until this is battle-tested.)

## Why

The self-hosted options are bulky (Infisical drags in Node + Postgres + Redis)
or operationally heavy (Vault/OpenBao's unseal story fights reboot self-heal).
On a small, capacity-constrained box pair you want something that:

- is **one static binary** with an embedded store (no DB to run/back up);
- is **HA** via embedded Raft, so losing a node doesn't lose the service;
- **auto-unseals** from a tiny bootstrap key on tmpfs, preserving 3am
  reboot-self-heal (no human, no external call);
- gives you **audit + revoke + versioning** — the things plain SOPS lacks
  (on the roadmap).

## Architecture

### Envelope encryption

```
unseal key (KEK)  ── lives only in memory / on tmpfs, never in the DB or log
      │  unwraps
      ▼
data key (DEK)    ── random, generated at bootstrap, replicated wrapped(KEK)
      │  encrypts
      ▼
secret values     ── XChaCha20-Poly1305, AAD = "secret:<path>" (binds value→path)
```

Encryption happens **once, on the leader**; the resulting ciphertext is what
gets replicated, so every replica holds byte-identical state. The Raft log and
snapshots only ever contain ciphertext plus the *wrapped* DEK.

### HA + the witness

```
   ┌──────────┐   raft   ┌──────────┐
   │  node 1  │◀────────▶│  node 2  │   both unsealed (KEK on tmpfs) → serve reads/writes
   │  voter   │          │  voter   │
   └────┬─────┘          └─────┬────┘
        └────────┬─────────────┘
            ┌────▼─────┐
            │ witness  │  voter for quorum; started WITHOUT a key →
            │ (sealed) │  replicates ciphertext, cannot read a secret
            └──────────┘
```

Raft needs an odd voter count; a 2-box pair gets a third vote from a **witness**
started with no `-unseal-key`. It participates in consensus and stores ciphertext
but is cryptographically unable to read plaintext.

Writes are accepted only on the leader — a follower transparently reverse-proxies
write requests to the current leader. Reads are served locally (a follower may be
slightly stale).

### Packages

| Package | Responsibility |
|---|---|
| `internal/crypto`  | AEAD seal/open + key generation (XChaCha20-Poly1305) |
| `internal/store`   | bbolt-backed encrypted KV; KEK→DEK envelope; raw ops + snapshot export/import |
| `internal/cluster` | Raft FSM + node lifecycle (bootstrap, join, leader-forwarding, witness) |
| `internal/server`  | HTTP/JSON API; forwards writes to the leader |
| `cmd/stash`        | CLI: `init`, `server` |

## Quickstart

### Single node

```sh
make build
./stash init -unseal-key-out ./unseal-key            # generate the cluster key
./stash server -data ./data -unseal-key ./unseal-key -bootstrap

curl -s -X PUT localhost:8200/v1/secret/kg/web/SECRET_KEY -d '{"value":"s3cr3t"}'
curl -s localhost:8200/v1/secret/kg/web/SECRET_KEY    # {"value":"s3cr3t"}
curl -s localhost:8200/v1/health                      # {"is_leader":true,"sealed":false,...}
```

### Three-node HA cluster

```sh
./stash init -unseal-key-out key     # one key, shared by all real (non-witness) nodes

# node 1 — bootstrap
./stash server -data /data -unseal-key key -node-id n1 \
    -listen 0.0.0.0:8200 -raft-addr 10.0.0.1:8300 \
    -advertise-http http://10.0.0.1:8200 -bootstrap

# node 2 — join
./stash server -data /data -unseal-key key -node-id n2 \
    -listen 0.0.0.0:8200 -raft-addr 10.0.0.2:8300 \
    -advertise-http http://10.0.0.2:8200 -join http://10.0.0.1:8200

# witness — join WITHOUT a key (sealed quorum voter)
./stash server -data /data -node-id w \
    -raft-addr 10.0.0.3:8300 -advertise-http http://10.0.0.3:8200 \
    -listen 0.0.0.0:8200 -join http://10.0.0.1:8200
```

In production the unseal key is the only thing you keep in SOPS, decrypted to
tmpfs at deploy and passed via `-unseal-key`. That's the entire residual SOPS
surface.

## API

| Method | Path | Body | Result |
|---|---|---|---|
| `GET`    | `/v1/health`         | — | `{"status","sealed","is_leader"}` |
| `GET`    | `/v1/secrets`        | — | `{"keys":[...]}` |
| `GET`    | `/v1/secret/<path>`  | — | `{"value":"..."}` |
| `PUT`    | `/v1/secret/<path>`  | `{"value":"..."}` | `204` (forwarded to leader) |
| `DELETE` | `/v1/secret/<path>`  | — | `204` (forwarded to leader) |
| `POST`   | `/v1/cluster/join`   | `{"node_id","raft_addr","http_addr"}` | `200` |

`<path>` may contain slashes (`kg/web/SECRET_KEY`).

## Roadmap

- [x] **M1 — single encrypted node**: bbolt + envelope encryption + auto-unseal, HTTP API.
- [x] **M2 — HA**: embedded `hashicorp/raft` (voters + sealed witness), leader-forwarding, join/bootstrap.
- [ ] **M3 — identity & access**: machine-identity tokens (hashed at rest) + path-prefix ACLs.
- [ ] **M4 — audit**: hash-chained append-only audit log (reads + writes), ship to Loki.
- [ ] **M5 — versioning**: keep last N versions per path; list/diff.
- [ ] **M6 — agent**: `stash agent` renders secrets → tmpfs with last-good cache (reboot-during-outage self-heal).
- [ ] **M7 — UI**: small embedded web UI (the real DX win).

## Security notes (read before trusting it)

- Crypto uses only Go stdlib + `x/crypto` AEAD primitives — nothing hand-rolled.
- The unseal key is never persisted by the daemon and never enters the Raft log.
- Transport between nodes (Raft + the HTTP API) is currently **unencrypted** —
  run it over a private network / tailnet. mTLS is future work.
- This has **not** been audited. Treat M1–M5 as a learning build.
```
