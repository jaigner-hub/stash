# stash

A lightweight, single-binary secrets manager. The goal: HA secret storage that
is genuinely *easy* to stand up — no external database, no Redis, no key
ceremony, no Kubernetes. One Go binary that does it all.

> **Status: milestone 1 — single encrypted node.** This is a hobby project and
> is **not production-ready**. Do not trust it with real secrets yet. (For the
> keygrip dev pair, SOPS stays authoritative until this is battle-tested.)

## Why

The self-hosted options are bulky (Infisical drags in Node + Postgres + Redis)
or operationally heavy (Vault/OpenBao's unseal story fights reboot self-heal).
On a small, capacity-constrained box pair you want something that:

- is **one static binary** with an embedded store (no DB to run/back up);
- is **HA** via embedded Raft, so losing a node doesn't lose the service;
- **auto-unseals** from a tiny bootstrap key on tmpfs, preserving 3am
  reboot-self-heal (no human, no external call);
- gives you **audit + revoke + versioning** — the things plain SOPS lacks.

## Architecture (envelope encryption)

```
unseal key (KEK)  ── lives only in memory / on tmpfs, never in the DB
      │  unwraps
      ▼
data key (DEK)    ── random, generated at init, stored wrapped(KEK) in the DB
      │  encrypts
      ▼
secret values     ── XChaCha20-Poly1305, AAD = "secret:<path>" (binds value→path)
```

Because the on-disk database only ever holds *ciphertext* plus the *wrapped*
DEK, a node that never receives the KEK can hold the data without being able to
read it — which is exactly what the future quorum **witness** node will be.

### Packages

| Package | Responsibility |
|---|---|
| `internal/crypto` | AEAD seal/open + key generation (XChaCha20-Poly1305) |
| `internal/store`  | bbolt-backed encrypted KV; KEK→DEK envelope; init/unseal |
| `internal/server` | HTTP/JSON data-plane API |
| `cmd/stash`       | CLI: `init`, `server` |

## Quickstart

```sh
make build

# 1. Initialize a store. Prints (or writes) the unseal key — guard it.
./stash init -data ./data -unseal-key-out ./unseal-key

# 2. Run the node (auto-unseals from the key file).
./stash server -data ./data -unseal-key ./unseal-key -listen 127.0.0.1:8200

# 3. Use it (in another shell).
curl -s -X PUT localhost:8200/v1/secret/kg/web/SECRET_KEY \
  -d '{"value":"s3cr3t"}'
curl -s localhost:8200/v1/secret/kg/web/SECRET_KEY      # {"value":"s3cr3t"}
curl -s localhost:8200/v1/secrets                       # {"keys":["kg/web/SECRET_KEY"]}
curl -s -X DELETE localhost:8200/v1/secret/kg/web/SECRET_KEY
curl -s localhost:8200/v1/health                        # {"sealed":false,"status":"ok"}
```

In production the unseal key is the only thing you keep in SOPS, decrypted to
tmpfs at deploy and passed via `-unseal-key`. That's the entire residual SOPS
surface.

## API

| Method | Path | Body | Result |
|---|---|---|---|
| `GET`    | `/v1/health`         | — | `{"status","sealed"}` |
| `GET`    | `/v1/secrets`        | — | `{"keys":[...]}` |
| `GET`    | `/v1/secret/<path>`  | — | `{"value":"..."}` |
| `PUT`    | `/v1/secret/<path>`  | `{"value":"..."}` | `204` |
| `DELETE` | `/v1/secret/<path>`  | — | `204` |

`<path>` may contain slashes (`kg/web/SECRET_KEY`).

## Roadmap

- [x] **M1 — single encrypted node**: bbolt + envelope encryption + auto-unseal, HTTP API.
- [ ] **M2 — HA**: embedded `hashicorp/raft` (3 voters: 2 boxes + witness), leader-forwarding.
- [ ] **M3 — identity & access**: machine-identity tokens (hashed at rest) + path-prefix ACLs.
- [ ] **M4 — audit**: hash-chained append-only audit log (reads + writes), ship to Loki.
- [ ] **M5 — versioning**: keep last N versions per path; list/diff.
- [ ] **M6 — agent**: `stash agent` renders secrets → tmpfs with last-good cache (reboot-during-outage self-heal).
- [ ] **M7 — UI**: small embedded web UI (the real DX win).

## Security notes (read before trusting it)

- Crypto uses only Go stdlib + `x/crypto` AEAD primitives — nothing hand-rolled.
- The unseal key is never persisted by the daemon; `stash init` is the only time
  it exists outside your control.
- This has **not** been audited. Treat M1–M5 as a learning build.
