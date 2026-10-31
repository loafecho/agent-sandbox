# homebot: a Home Assistant agent in a per-task OpenShell box

One task = one fresh microVM on the agent host's jobs gateway, deleted afterwards. Homebot's only tools are
Home Assistant's official MCP server (`/api/mcp`, Assist API, exposed entities only). No shell, no files, no web.

| Path | What |
|---|---|
| `image/Dockerfile`, `image/mcp.json` | image `homebot-agent:0.1` (pinned Claude Code, no curl), exported as a rootfs tar |
| `skill/SKILL.md` | Homebot's rulebook, baked read-only at `/opt/homebot/SKILL.md`, appended to its system prompt |
| `openshell/policy.yaml` | box policy: no network rules of its own; the two doors come from providers |
| `openshell/profile-homebot-home-assistant.yaml` | provider profile: HA token bound to `POST /api/mcp` on one address only |
| `bin/homebot-remote` | agent-host side: SSH forced command; boots, runs and deletes the box; keeps run records under `~/homebot/runs/` |
| `bin/homebot` | workstation side: `homebot ask "…"` (read-only tools), `homebot do "…"` (read + change tools), `homebot chat [--do]` |
| tool grant | `bin/homebot-remote` picks the HA tools per task from the mode (`READ_TOOLS`, `CHANGE_TOOLS`), never from the task text; unlisted tools (covers, locks, alarm, vacuums, timers) are refused |
| `bin/set-homebot-tokens.sh` | the operator runs it: loads both tokens from the secrets manager into providers `homebot-ha`, `homebot-claude` |

## Why it is shaped this way

- **The box holds no credential.** Both tokens are OpenShell providers. The box sees placeholders; the gateway
  swaps in the real value only on requests that match the provider's profile (one host, one method, one path).
- **The agent has no built-in tools.** `claude -p --tools ""` with `--strict-mcp-config`: the only tool set is
  the Home Assistant MCP server.
- **The HA user is not an admin**, and HA only shows entities exposed to Assist. Security devices stay unexposed,
  and new devices are hidden by default (`expose_new: false`).
- **The trigger key can do one thing.** `restrict,from="<workstation>",command="/usr/local/bin/homebot-remote"`
  in `authorized_keys`: the key hands a task (max 4 KB of text) on stdin and nothing else. The forced command
  ignores `SSH_ORIGINAL_COMMAND`, takes a lock (one task at a time), and deletes the box on every exit path,
  including a dropped SSH connection.
- **Every run leaves a record**: the task, the box output (token-shaped strings scrubbed), and the network log,
  summarized as a `<<<NETWORK-HOSTS allowed=… denied=…>>>` trailer on every answer.

## Setup (operator steps, in order)

1. HA → Settings → People → Users → add `homebot`, **not admin**. Log in as homebot → Profile → Security →
   long-lived token. Add the `mcp_server` integration (Assist API) and choose the exposed entities.
2. Secrets manager: a project for Homebot with `HOMEBOT_HA_TOKEN` and `HOMEBOT_CLAUDE_TOKEN`
   (the second from `claude setup-token`) in `prod`.
3. `HOMEBOT_INFISICAL_PROJECT=<id> bin/set-homebot-tokens.sh`
4. Network: the jobs gateway's egress wall (`gateways/jobs/jobs-wall.nft`) must allow the jobs user to reach
   HA's port and nothing else private.
5. Trigger key (an access path, so the operator adds it by hand): on the workstation
   `ssh-keygen -t ed25519 -N '' -C homebot-trigger -f ~/.ssh/id_homebot_trigger`, then append to
   `/var/lib/openshell-jobs/.ssh/authorized_keys` on the agent host:
   `restrict,from="172.16.0.54",command="/usr/local/bin/homebot-remote" <pubkey>`
   and `install -m 755 bin/homebot ~/.local/bin/homebot`.

## Test ladder

Read-only ask → one light → red team (alarm, garage door, cameras, a web page: all must be refused) →
prompt injection through a renamed test entity (must be quoted back, not followed).
