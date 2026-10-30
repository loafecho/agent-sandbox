# agent-sandbox

Least-privilege sandboxes for running AI agents, and a switchboard that sits between those agents and
the infrastructure they are allowed to touch.

Each agent runs in an [OpenShell](https://github.com/NVIDIA/OpenShell) microVM box with its own kernel, a
read-only system, no network rules by default, and no credential values inside it. Anything an agent may
reach is a named rule kept in this repo; anything it may change on real infrastructure goes through the
switchboard, where the risky actions wait for a human to approve them.

I built this for my own home lab, where coding and home-automation agents run unattended. The goal was
simple to state: an agent should be able to do useful work, and a prompt injection or a bad plan should
still not be able to reach a credential, a private host, or a destructive action without a person saying yes.

## What is in the repo

| Path | What it is |
|---|---|
| `switchboard/` | Rust MCP tool server. Every box reaches it through its own OpenShell provider. Tools come in three tiers: **read** (runs, logged), **approve** (a request posted to Discord and, optionally, a passkey page; runs only after the one approver says yes), **forward** (passed to an agent's own upstream MCP gateway behind the same token and backend checks). |
| `switchboard/tools.yaml` | The single source of truth: every tool, its tier, its argument patterns, and which agents may call it. `gen.py` writes the switchboard's runtime config, each box's OpenShell provider profile, and `TOOLS.md` from it. |
| `boxes/coder/` | A long-lived interactive coding box: image, file and network policy, named doors, provider list, and the scripts that build, create, prove and drift-check it. |
| `boxes/homebot/` | A per-task job box for a Home Assistant agent: one fresh microVM per request, deleted afterwards, whose only tool is Home Assistant's MCP endpoint. Triggered by an SSH forced-command key that can do nothing else. |
| `gateways/interactive/` | Installs the OpenShell gateway for the interactive box (its own system user, port and config). |
| `gateways/jobs/` | A second gateway for job boxes under a different user, plus an nftables egress wall keyed by user id so the two kinds of box cannot reach each other's doors. |
| `bin/drift-check.sh` | One read-only check that the live boxes, providers and switchboard match this repo. |
| `tests/` | pytest tests for the Python helpers and the generator. |

## How it works

```
 agent in a box ──(placeholder token)──▶ OpenShell gateway ──(real token, matching rule only)──▶ switchboard
                                                                                                    │
                       read tier: run and log ◀─────────────────────────────────────────────────────┤
                       approve tier: post request → approver's ✅ or passkey → run once ◀─────────────┤
                       forward tier: agent's own MCP gateway ◀───────────────────────────────────────┘
```

**Boxes.** OpenShell boots each box as a microVM from a rootfs tar built here. The policy file fixes the
filesystem (system paths read-only) and lists the network doors. A door names one host, one port and one
program inside the box (for example `git-remote-http` may POST `git-receive-pack` to one repository and
nothing else). New doors are proposed as pending rules and opened by the operator by name; the box never
approves its own.

**Credentials.** Tokens are OpenShell *providers*. The box only ever holds a placeholder; the gateway swaps
in the real value on requests that match the provider's profile. Values travel from the secrets manager to
the gateway over SSH stdin and are never printed, logged or written to this repo; the repo holds secret
*names* only.

**Switchboard guards.** Every call passes a fixed ladder in `switchboard/src/guards.rs`: allowed source
address, bearer token (sha256, constant-time compare), tool allow-list per agent, argument patterns, per-agent
rate limit, and for approve-tier calls the approver check, a guest allowlist, claim-once, and the WebAuthn
checks (user verification, rpId, origin, single-use challenge bound to the request and its arguments, signature
counter, ES256 signature). `prove-red.sh` disables each guard in turn in a scratch copy and requires the test
suite to fail, so no guard is decorative. The audit log is append-only and hash-chained
(`switchboard audit-verify` walks it).

**Approvals.** An approve-tier call returns a request id at once and runs nothing. The request is posted to a
Discord channel; only the configured approver's ✅ or ❌ counts (the bot's own reactions and everyone else's
are ignored). With the web page enabled, the approver can also decide on a passkey page that only their
phone's address can reach. Whichever decision lands first wins; the write runs once. Requests expire after
30 minutes, and a restart expires anything pending.

**Drift.** `boxes/coder/bin/drift-check.sh` compares the live box with the repo (rules, providers, profiles,
secret names, pending rules). Job boxes are created per run, so `bin/drift-check.sh` compares the files the
jobs gateway boots them from by sha256. The switchboard check compares its live binary and config with the repo.

## Running it

The tests and linters run anywhere:

```
cd switchboard
cargo test                      # 72 unit tests: guards, approvals, passkey page, forwarding, config checks
bash prove-red.sh               # each guard disabled in turn must make the suite fail
python3 staging/e2e.py          # staging build with fake Discord/ntfy/backends: 12 end-to-end checks
python3 staging/loris.py        # slow-body regression: valid calls still answer with 16 stalled sockets open
python3 gen.py --check          # generated files match tools.yaml
cd ..
python3 -m pytest               # Python helpers and the generator
```

`e2e.py` needs the `cryptography` package (it signs as a software passkey) and `gen.py` needs PyYAML.

Running the boxes needs a Linux host with KVM and OpenShell 0.1.1, plus the hosts the examples name
(a Proxmox hypervisor, Prometheus, Home Assistant, a secrets manager). Every host-touching script is a dry
run unless given `--yes-write`, and reads its targets from environment variables (`AGENT_HOST`,
`AGENT_HOST_KEY`, `PVE_HOST`, the `SB_*` values in `switchboard/deploy/install.sh`). Rough order:

1. `boxes/coder/bin/install-gateway.sh` (B1), then `build-image.sh` and `create-box.sh` (B2).
2. `boxes/coder/bin/prove-gateway.sh` and `prove-box.sh` to check isolation before trusting the box.
3. `switchboard/deploy/install.sh` on a dedicated VM; `switchboard/bin/install-door.sh coder` gives the box its door.
4. `gateways/jobs/jobs-gateway-setup.sh` and `install-jobs-wall.sh` for job boxes such as `boxes/homebot/`.

## CI

`.github/workflows/ci.yml` runs on every push: `cargo fmt --check`, `cargo build`, `cargo test`, the
guard mutation proof, the staging end-to-end and slow-body tests, `gen.py --check`, pytest, ruff,
shellcheck on every shell script, yamllint on the policies and profiles, `nft -c` on both firewall
rulesets, and the placeholder scan over the repo.

## Limits

- The OpenShell side (boxes, gateways, doors, drift checks) needs real hosts. CI checks those scripts with
  shellcheck and their Python helpers with unit tests, but does not boot a box.
- Addresses, host names, guest ids and Discord ids in this repo are documentation examples
  (`172.16.0.0/12`, `198.51.100.0/24`, `*.tailnet.example`), not a working network.
- `boxes/coder/openshell/policy.yaml` is a representative set of doors, not a capture of a live box.
- The forward tier has no upstream gateway configured in `tools.yaml`; it is exercised by the unit tests only.
- The WebAuthn code is a narrow hand-written implementation: ES256 only, attestation `none`, one approver.
- Jellyfin has no read-only API key, so the switchboard's Jellyfin key is admin-level. Read tools use a
  GET-only client type and the one write sits behind approval, but the key itself is broader than the tools.
- Built and run for a single-operator home lab. It has not been reviewed for multi-tenant use.

## License

MIT. See `LICENSE`.
