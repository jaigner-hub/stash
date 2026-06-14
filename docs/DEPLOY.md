# Deploying / upgrading the cluster

How to ship a new `stash` build to the running 3-node cluster. This is the
build-your-own ADR-0018 path that backs keygrip's secrets; the cluster is
**heterogeneous** (two Ansible/systemd boxes + one NixOS witness), so the binary
and restart mechanics differ per node.

## Topology

| Node        | Host / tailnet IP      | Role                              | Managed by                         | Binary path           | Unit                 |
| ----------- | ---------------------- | --------------------------------- | ---------------------------------- | --------------------- | -------------------- |
| `vent.dog`  | `100.106.141.112`      | keyed node (can serve reads/writes) | `~/Projects/keygrip` Ansible (`dev`) | `/usr/local/bin/stash` | `stash.service`      |
| `vent.dog2` | `100.110.200.36`       | keyed node (HA pair)              | `~/Projects/keygrip` Ansible (`dev`) | `/usr/local/bin/stash` | `stash.service`      |
| `monitor`   | `100.109.229.12`       | **witness** — sealed, vote-only, never reads | `~/Projects/nixos-config` (`machines/monitor/stash-witness.nix`) | `/opt/stash/stash`    | `stash-witness.service` |

- API listens on `:8200` (HTTPS/mTLS), Raft on `:8300`. Both bind the **tailnet
  IP**, not loopback.
- The `monitor` witness joined once with `--no-key` and holds no unseal key: it
  replicates ciphertext, can't read a secret, and hands back leadership if it
  ever wins an election. The conditional-GET change does not affect it (it never
  serves secrets), but upgrade it anyway for binary parity.
- `vent.dog` and `vent.dog2` also run `stash-agent.service`, which renders
  `kg/web/*` into `/run/keygrip/web.env` every 30s (the role lives in keygrip at
  `roles/stash_agent`).

> Heads-up: nothing in Ansible currently *pushes the server binary* — the
> `stash_agent` role assumes `/usr/local/bin/stash` and a running `stash.service`
> are already present. Until that gap is filled, the server binary is shipped by
> hand (below).

## Build

Build **one static binary** and use it on all three nodes. The default
`make build` links against glibc (cgo) and will **not** run on NixOS `monitor`;
`CGO_ENABLED=0` produces a portable static ELF that runs everywhere.

```sh
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o stash ./cmd/stash
file stash          # ... statically linked ...
sha256sum stash     # record this — it's how you verify each node post-rollout
go test ./...       # green before you ship
```

All three nodes are `linux/amd64`. If `monitor`'s arch ever differs, rebuild with
the matching `GOARCH` for that node.

There is no `stash version` command, so **sha256 is the source of truth** for
"did the new binary land": compare `sha256sum` on each node to the artifact you
built.

## Rollout

Order does not matter and there is no flag day:

- The server change is **backward compatible** — clients that don't send
  `If-None-Match` still get `200`s.
- There is **no Raft/FSM or on-disk format change** (the new `CurrentVersion` is
  a read-only version-key scan), so mixed-version nodes replicate fine.
- A restart recovers identity, addresses, and TLS material from
  `cluster.json` / `/var/lib/stash` — **no re-join**.

Go one node at a time, confirming the cluster is healthy between each.

### vent.dog and vent.dog2 (Ansible / systemd)

```sh
# from ~/Projects/stash, with the static ./stash built above
for h in 100.106.141.112 100.110.200.36; do
  scp stash jeff@$h:/tmp/stash.new
  ssh jeff@$h '
    sudo install -m 0755 /tmp/stash.new /usr/local/bin/stash &&
    sudo systemctl restart stash.service &&
    sleep 2 && sudo systemctl restart stash-agent.service &&
    sha256sum /usr/local/bin/stash'
done
```

Do them **one at a time**, not in a tight loop, if you want to watch quorum —
restart `vent.dog`, confirm health, then `vent.dog2`. Check the exact server
flags with `systemctl cat stash` if you need them; a plain restart is enough.

### monitor (NixOS witness)

The Nix module just runs a binary placed out-of-band at `/opt/stash/stash`, so a
**`nixos-rebuild` is not required** unless you changed `stash-witness.nix`. Swap
the binary and restart the unit:

```sh
scp stash root@100.109.229.12:/tmp/stash.new   # or your nix admin user
ssh root@100.109.229.12 '
  install -m 0755 /tmp/stash.new /opt/stash/stash &&
  systemctl restart stash-witness.service &&
  sha256sum /opt/stash/stash'
```

(If you'd rather pin it declaratively, package via `buildGoModule` in
`nixos-config` and `nixos-rebuild switch` — that's the proper follow-up noted in
the module.)

## Verify

1. **Binary landed** — `sha256sum` on each node matches the artifact.
2. **Conditional GET is live** (keyed nodes only — the witness is sealed):

   ```sh
   # from a tailnet box with the CA + a read token
   curl -sk https://100.106.141.112:8200/v1/secret/kg/web/<some-key> \
     -H "Authorization: Bearer $TOK" -D - -o /dev/null | grep -i etag
   # -> ETag: "v<n>"   (header present == new build serving)
   ```

3. **Flood is gone** — after the agents have polled a couple of cycles, the audit
   log should stop growing by N entries every 30s. Re-fetching an unchanged
   secret with `If-None-Match: "v<n>"` should return `304` and add no audit row.

## Rollback

Keep the previous binary around (`/usr/local/bin/stash.prev`, `/opt/stash/stash.prev`).
Rollback is the same swap in reverse + restart — no data migration, since nothing
on disk changed.
